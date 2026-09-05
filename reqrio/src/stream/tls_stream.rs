use crate::error::HlsResult;
#[cfg(feature = "aync")]
use crate::Timeout;
use super::connect::{ConnState, TlsConnecting};
use reqtls::*;
#[cfg(feature = "aync")]
use std::cmp::min;
use std::io::{Read, Write};
use std::mem;
#[cfg(feature = "aync")]
use std::pin::Pin;
#[cfg(feature = "aync")]
use std::task::{Context, Poll};
#[cfg(feature = "aync")]
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::stream::read::RecordReading;
use crate::stream::write::BufWriting;

pub struct TlsStream<S> {
    pub(super) conn: Connection,
    stream: S,
    encrypted_channel: bool,
    pub(super) handshake_finished: bool,
    hello_retrying: bool,
    pub(super) read_buffer: Writer,
    pub(super) write_buffer: Writer,
    #[cfg(feature = "aync")]
    shutdown_wrote: bool,
    #[cfg(feature = "aync")]
    write_offset: usize,
    #[cfg(feature = "aync")]
    pub(super) timeout: Timeout,
}

impl<S> TlsStream<S> {
    pub(crate) fn new(conn: Connection, stream: S) -> TlsStream<S> {
        TlsStream {
            conn,
            stream,
            encrypted_channel: false,
            handshake_finished: false,
            hello_retrying: false,
            read_buffer: Writer::with_capacity(16469),
            write_buffer: Writer::with_capacity(16469),
            #[cfg(feature = "aync")]
            shutdown_wrote: false,
            #[cfg(feature = "aync")]
            write_offset: 0,
            #[cfg(feature = "aync")]
            timeout: Timeout::longer(),
        }
    }

    pub fn connect(mut config: ClientConfig<'_>, stream: S) -> TlsConnecting<'_, S> {
        let session = config.session.as_ref().cloned().unwrap_or_default();
        let conn = Connection::new_client(session, mem::take(&mut config.key_log), false)
            .with_verify(config.verify).with_mtls(!config.client_cert.is_empty());
        TlsConnecting {
            sent_client_hello: false,
            state: ConnState::Connecting(Box::new(TlsStream::new(conn, stream))),
            config: Config::Client(config),
            app_buf: Writer::with_capacity(16384),
        }
    }

    pub fn accept(stream: S, config: ServerConfig<'_>) -> TlsConnecting<'_, S> {
        TlsConnecting {
            sent_client_hello: true,
            state: ConnState::Connecting(Box::new(TlsStream::new(Connection::default().with_verify(config.verify), stream))),
            config: Config::Server(config),
            app_buf: Writer::with_capacity(16384),
        }
    }

    pub(super) fn write_buffer(&mut self) -> BufWriting<'_, S> {
        #[cfg(feature = "aync")]
        self.timeout.reset_write();
        BufWriting {
            stream: &mut self.stream,
            buf: &mut self.write_buffer,
            #[cfg(feature = "aync")]
            timeout: &mut self.timeout,
        }
    }

    pub(super) fn read_next_record(&mut self) -> RecordReading<'_, S> {
        #[cfg(feature = "aync")]
        self.timeout.reset_read();
        RecordReading {
            stream: &mut self.stream,
            buf: &mut self.read_buffer,
            #[cfg(feature = "aync")]
            timeout: &mut self.timeout,
        }
    }

    pub fn alpn(&self) -> Option<&ALPN> { self.conn.alpn() }

    pub fn connection(&self) -> &Connection { &self.conn }

    #[cfg(feature = "aync")]
    pub fn set_timeout(&mut self, mut timeout: Timeout) {
        timeout.reset_read();
        timeout.reset_write();
        timeout.reset_connect();
        self.timeout = timeout;
    }
}

impl<S: Write> TlsStream<S> {
    pub fn shutdown(&mut self) -> HlsResult<()> {
        self.write_buffer.reset();
        let out = self.write_buffer.unfilled();
        let record_len = self.conn.make_message(RecordType::Alert, out, &[1, 0])?;
        self.write_buffer.add_len(record_len);
        self.write_buffer().wait()
    }
}

impl<S: Read> Read for TlsStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let record_len = self.read_next_record().wait()?;
            let size = self.handle_record(record_len, None, buf)?;
            self.read_buffer.used_empty(record_len);
            if size > 0 { return Ok(size); }
        }
    }
}
#[cfg(feature = "aync")]
impl<S: AsyncRead + Unpin> AsyncRead for TlsStream<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        if self.shutdown_wrote { return Poll::Ready(Ok(())); }
        let stream = self.get_mut();
        loop {
            let mut record = stream.read_next_record();
            let record_len = match Pin::new(&mut record).poll(cx)? {
                Poll::Ready(len) => len,
                Poll::Pending => return Poll::Pending,
            };
            let len = stream.handle_record(record_len, None, buf.initialized_mut()).unwrap();
            stream.read_buffer.used_empty(record_len);
            if len == 0 { continue; }
            buf.set_filled(len);
            return Poll::Ready(Ok(()));
        }
    }
}

impl<S: Write> Write for TlsStream<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        for chunk in buf.chunks(16384) {
            self.write_buffer.reset();
            let record_len = self.conn.make_message(RecordType::ApplicationData, self.write_buffer.unfilled(), chunk)?;
            self.write_buffer.add_len(record_len);
            self.write_buffer().wait()?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}
#[cfg(feature = "aync")]
impl<S: AsyncWrite + Unpin> AsyncWrite for TlsStream<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let stream = self.get_mut();
        loop {
            if stream.write_offset == buf.len() && stream.write_buffer.is_empty() { break; }
            if stream.write_buffer.is_empty() {
                let chunk_size = min(16384, buf.len());
                let chunk = &buf[stream.write_offset..stream.write_offset + chunk_size];
                let record_len = stream.conn.make_message(RecordType::ApplicationData, stream.write_buffer.unfilled(), chunk)?;
                stream.write_buffer.add_len(record_len);
                stream.write_offset += chunk_size;
            }
            let mut writer = stream.write_buffer();
            if Pin::new(&mut writer).poll(cx)?.is_pending() { return Poll::Pending; }
        }
        assert_eq!(stream.write_offset, buf.len());
        stream.write_offset = 0;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let stream = self.get_mut();
        if stream.write_buffer.is_empty() {
            let len = stream.conn.make_message(RecordType::Alert, stream.write_buffer.unfilled(), &Alert::close_notify().to_bytes())?;
            stream.write_buffer.add_len(len);
        }
        match stream.shutdown_wrote {
            true => Pin::new(&mut stream.stream).poll_shutdown(cx),
            false => {
                let mut writer = stream.write_buffer();
                match Pin::new(&mut writer).poll(cx)? {
                    Poll::Ready(_) => {
                        stream.shutdown_wrote = true;
                        Pin::new(&mut stream.stream).poll_shutdown(cx)
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }
}

impl<S> StreamHandle for TlsStream<S> {
    fn stream_param(&mut self) -> (&Writer, StreamParam<'_>) {
        (&self.read_buffer, StreamParam {
            handshake_finish: &mut self.handshake_finished,
            encrypted_channel: &mut self.encrypted_channel,
            hello_retrying: &mut self.hello_retrying,
            write_buffer: &mut self.write_buffer,
            conn: &mut self.conn,
        })
    }
}