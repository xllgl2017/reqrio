use crate::error::HlsResult;
use crate::stream::config::Config;
use crate::stream::TlsStreamHandle;
use crate::*;
use std::io;
use std::io::{Read, Write};

pub struct SyncStream<S> {
    conn: Connection,
    stream: S,
    handshake_finished: bool,
    read_buffer: Buffer,
    write_buffer: Buffer,
}

impl<S: Read + Write> SyncStream<S> {
    fn new(stream: S, conn: Connection, mut config: Config<'_>, buffer: Buffer) -> HlsResult<SyncStream<S>> {
        let mut stream = SyncStream {
            stream,
            conn,
            handshake_finished: false,
            read_buffer: Buffer::default(),
            write_buffer: buffer,
        };
        if let Config::Client(config) = &mut config {
            stream.handle_client_hello(config)?;
            stream.stream.write_all(stream.write_buffer.filled())?;
            stream.write_buffer.reset();
        }
        loop {
            let record_len = stream.read_next_packet()?;
            let len = stream.read_buffer.len();
            let hello_done = stream.handle_message(Some(&mut config))?;
            stream.read_buffer.move_to(record_len..len, 0);
            if hello_done { break; }
        }
        Ok(stream)
    }
    pub fn connect(config: ClientConfig, stream: S) -> HlsResult<SyncStream<S>> {
        // let mut write_buffer = Buffer::with_capacity(0xFFFF);
        // let conn = Self::handle_client_hello(&mut config, &mut write_buffer)?;
        // stream.write_all(write_buffer.filled())?;
        // write_buffer.reset();
        SyncStream::new(stream, Connection::default().with_verify(config.verify), Config::Client(config), Buffer::default())
    }

    pub fn accept(stream: S, config: ServerConfig<'_>) -> HlsResult<SyncStream<S>> {
        SyncStream::new(stream, Connection::default(), Config::Server(config), Buffer::default())
    }

    fn handle_message(&mut self, mut config: Option<&mut Config>) -> HlsResult<bool> {
        let record = RecordLayer::from_bytes(self.read_buffer.filled_mut(), self.handshake_finished, Some(self.conn.cipher_suite()))?;
        match record.context_type {
            RecordType::CipherSpec => self.handshake_finished = true,
            RecordType::Alert => {
                let record_len = record.len as usize + 5;
                return Err(self.handle_by_alert(self.handshake_finished, record_len)?.into());
            }
            RecordType::HandShake => {
                for message in record.messages {
                    match message {
                        Message::ServerHello(v) => self.conn.set_by_server_hello(&v)?,
                        Message::Certificate(v) => {
                            let param = config.as_mut().ok_or("conn param can't be null")?;
                            let config = param.client_mut().ok_or("missing config")?;
                            self.conn.set_by_certificate(v, config.ca_certs, config.sni)?;
                        }
                        Message::ServerKeyExchange(v) => self.conn.set_by_server_exchange_key(v)?,
                        Message::ServerHelloDone(_) => {
                            self.handle_by_server_hello_done(config.as_mut().ok_or("conn param can't be null")?)?;
                            self.stream.write_all(self.write_buffer.filled())?;
                            self.write_buffer.reset();
                            return Ok(true);
                        }
                        Message::ClientHello(v) => {
                            let config = config.as_mut().ok_or("config can't be null")?;
                            let random = rand::random::<[u8; 32]>();
                            let server = config.server_mut().ok_or("missing config")?;
                            let mut record = self.conn.gen_server_hello(v, server.server_cert, server.cert_key, &random)?;
                            let session_id = rand::random::<[u8; 32]>();
                            record.messages[0].server_mut().ok_or(HlsError::NullPointer)?.set_session_id(&session_id);

                            record.write_to(&mut self.write_buffer, 1)?;
                            self.conn.update_session(&self.write_buffer.filled()[5..])?;
                            self.stream.write_all(self.write_buffer.filled())?;
                            self.write_buffer.reset();
                            break;
                        }
                        Message::ClientKeyExchange(v) => {
                            self.conn.set_by_client_exchange_key(v);
                            self.conn.make_cipher(true)?;
                        }
                        Message::Payload(_) => {
                            let record_len = record.len as usize + 5;
                            let mut out = vec![0; record_len];
                            let len = self.conn.read_message(&self.read_buffer[..record_len], &mut out)?;
                            self.conn.verify_finish(&out[..len], false)?;

                            let mut ticket = SessionTicket::default();
                            let tbs = rand::random::<[u8; 276]>();
                            ticket.tls_ticket_mut().set_value(&tbs);
                            self.write_buffer.write_slice(&[22, 3, 3])?;
                            self.write_buffer.write_u16(ticket.len() as u16)?;
                            ticket.write_to(&mut self.write_buffer)?;
                            self.conn.update_session(&self.write_buffer.filled()[5..])?;
                            self.write_buffer.write_slice(&[20, 3, 3, 0, 1, 1])?;
                            let record_len = self.conn.make_finish_message(self.write_buffer.unfilled_mut(), true)?;
                            self.write_buffer.add_len(record_len);
                            self.stream.write_all(self.write_buffer.filled())?;
                            self.write_buffer.reset();
                            return Ok(true);
                        }
                        Message::CertificateRequest(v) => {
                            let config = config.as_mut().ok_or("config can't be null")?;
                            let config = config.client_mut().ok_or("missing config")?;
                            self.conn.set_by_cert_req(v, config.client_cert.first_mut())?;
                        }
                        _ => {}
                    }
                }
            }
            RecordType::ApplicationData => {}
        }

        Ok(false)
    }

    pub fn shutdown(&mut self) -> HlsResult<()> {
        self.write_buffer.reset();
        let record_len = self.conn.make_message(RecordType::Alert, &mut self.write_buffer[..], &[1, 0])?;
        self.stream.write_all(&self.write_buffer[..record_len])?;
        Ok(())
    }

    pub fn alpn(&self) -> Option<&str> {
        Some(self.conn.alpn()?.value())
    }
}

impl<S: Read + Write> TlsStreamHandle for SyncStream<S> {
    fn conn_wbuf(&mut self) -> (&mut Connection, &mut Buffer) {
        (&mut self.conn, &mut self.write_buffer)
    }

    fn conn_rbuf(&mut self) -> (&mut Connection, &mut Buffer) {
        (&mut self.conn, &mut self.read_buffer)
    }
}

impl<S: Read> SyncStream<S> {
    fn read_size(&mut self, size: usize) -> HlsResult<()> {
        let start = self.read_buffer.len();
        while self.read_buffer.len() - start < size {
            self.read_buffer.sync_read(&mut self.stream)?;
        }
        Ok(())
    }

    fn check_and_read(&mut self) -> HlsResult<usize> {
        if self.read_buffer.len() < 5 { return Err("tls head len < 5".into()); }
        let len = u16::from_be_bytes([self.read_buffer[3], self.read_buffer[4]]) as usize;
        if self.read_buffer.len() >= len + 5 {
            Ok(len + 5)
        } else {
            self.read_size(len + 5 - self.read_buffer.len())?;
            Ok(len + 5)
        }
    }

    fn read_zero(&mut self) -> HlsResult<usize> {
        self.read_buffer.sync_read(&mut self.stream)?;
        self.check_and_read()
    }

    fn read_next_packet(&mut self) -> HlsResult<usize> {
        let record_len = if self.read_buffer.len() >= 5 {
            self.check_and_read()?
        } else {
            self.read_zero()?
        };
        if !self.handshake_finished { self.conn.update_session(&self.read_buffer.filled()[5..record_len])?; }
        Ok(record_len)
    }
}

impl<S: Read + Write> Read for SyncStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let record_len = self.read_next_packet()?;
            match RecordType::from_byte(self.read_buffer[0]).ok_or(io::Error::other("Unknown record type"))? {
                RecordType::CipherSpec | RecordType::HandShake => {
                    if self.handshake_finished {
                        self.conn.read_message(&self.read_buffer[..record_len], buf)?;
                    } else { let _ = self.handle_message(None)?; }
                    self.read_buffer.move_to(record_len..self.read_buffer.len(), 0);
                    continue;
                }
                RecordType::Alert => return Err(self.handle_by_alert(self.handshake_finished, record_len)?.into()),
                RecordType::ApplicationData => {
                    let len = self.conn.read_message(&self.read_buffer[..record_len], buf)?;
                    self.read_buffer.move_to(record_len..self.read_buffer.len(), 0);
                    return Ok(len);
                }
            }
        };
    }
}


impl<S: Write> Write for SyncStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut sent = 0;
        for chunk in buf.chunks(16384) {
            self.write_buffer.reset();
            loop {
                let record_len = self.conn.make_message(RecordType::ApplicationData, &mut self.write_buffer[..], chunk)?;
                self.write_buffer.set_len(record_len);
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