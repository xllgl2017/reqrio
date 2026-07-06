use crate::error::HlsResult;
use crate::stream::StreamParam;
use crate::*;
use std::io;
use std::io::{Read, Write};

pub struct SyncStream<S> {
    conn: Connection,
    stream: S,
    /// 是否握手完成
    handshake_finished: bool,
    /// 是否已进入加密通信
    encrypted_channel: bool,
    ///是否在进行retry中
    hello_retrying: bool,
    read_buffer: Buffer,
    write_buffer: Buffer,
}

impl<S: Read + Write> SyncStream<S> {
    fn new(stream: S, conn: Connection, mut config: Config<'_>, buffer: Buffer) -> HlsResult<SyncStream<S>> {
        let mut stream = SyncStream {
            stream,
            conn,
            handshake_finished: false,
            encrypted_channel: false,
            hello_retrying: false,
            read_buffer: Buffer::with_capacity(16438),
            write_buffer: buffer,
        };
        if let Config::Client(ref mut config) = config {
            stream.handle_client_hello(config)?;
            stream.stream.write_all(stream.write_buffer.filled())?;
            stream.write_buffer.reset();
        }
        let mut app_buffer = Buffer::with_capacity(16438);
        loop {
            let record_len = stream.read_next_packet()?;
            let buf = stream.read_buffer.clone();
            let record_bytes = &buf.filled()[..record_len];
            stream.handle_record(record_bytes, Some(&mut config), app_buffer.unfilled())?;
            if !stream.write_buffer.is_empty() {
                stream.stream.write_all(stream.write_buffer.filled())?;
                stream.write_buffer.reset();
            }
            if stream.handshake_finished { break; }
        }
        Ok(stream)
    }
    pub fn connect(config: ClientConfig, stream: S) -> HlsResult<SyncStream<S>> {
        let session = config.session.as_ref().cloned().unwrap_or_default();
        let conn = Connection::from_client(rand::random(), session, config.key_log.clone())
            .with_verify(config.verify).with_mtls(!config.client_cert.is_empty());
        SyncStream::new(stream, conn, Config::Client(config), Buffer::default())
    }

    pub fn accept(stream: S, config: ServerConfig<'_>) -> HlsResult<SyncStream<S>> {
        SyncStream::new(stream, Connection::default(), Config::Server(config), Buffer::with_capacity(16437))
    }

    pub fn shutdown(&mut self) -> HlsResult<()> {
        self.write_buffer.reset();
        let out = self.write_buffer.unfilled();
        let record_len = self.conn.make_message(RecordType::Alert, out, &[1, 0])?;
        self.stream.write_all(&out[..record_len])?;
        Ok(())
    }

    pub fn alpn(&self) -> Option<&ALPN> {
        self.conn.alpn()
    }

    pub fn connection(&self) -> &Connection {
        &self.conn
    }
}

impl<S: Read + Write> StreamHandle for SyncStream<S> {
    fn stream_param(&mut self) -> StreamParam<'_> {
        StreamParam {
            handshake_finish: &mut self.handshake_finished,
            encrypted_channel: &mut self.encrypted_channel,
            hello_retrying: &mut self.hello_retrying,
            write_buffer: &mut self.write_buffer,
            conn: &mut self.conn,
        }
    }
}

impl<S: Read> SyncStream<S> {
    fn read_size(&mut self, max_size: usize) -> HlsResult<()> {
        while self.read_buffer.len() < max_size {
            self.read_buffer.check_move(max_size)?;
            let len = self.stream.read(self.read_buffer.unfilled())?;
            if len == 0 { return Err(HlsError::PeerClosedConnection); }
            self.read_buffer.add_len(len);
        }
        Ok(())
    }

    fn read_next_packet(&mut self) -> HlsResult<usize> {
        if self.read_buffer.len() < 5 { self.read_size(5)?; }
        let record_len = u16::from_be_bytes([self.read_buffer.filled()[3], self.read_buffer.filled()[4]]) as usize + 5;
        self.read_size(record_len)?;
        Ok(record_len)
    }
}

impl<S: Read + Write> Read for SyncStream<S> {
    fn read(&mut self, app_buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let record_len = self.read_next_packet()?;
            let buf = self.read_buffer.clone();
            let record_bytes = &buf.filled()[..record_len];
            let size = self.handle_record(record_bytes, None, app_buf)?;
            if size > 0 { return Ok(size); }
        };
    }
}


impl<S: Write> Write for SyncStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut sent = 0;
        for chunk in buf.chunks(16384) {
            self.write_buffer.reset();
            let record_len = self.conn.make_message(RecordType::ApplicationData, self.write_buffer.unfilled(), chunk)?;
            self.write_buffer.add_len(record_len);
            loop {
                let len = self.stream.write(self.write_buffer.filled())?;
                if self.write_buffer.used_empty(len) { break; }
            }
            sent += chunk.len();
        }
        Ok(sent)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}