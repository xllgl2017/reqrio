use crate::stream::config::{ClientConfig, Config, ServerConfig};
use crate::stream::TlsStreamHandle;
use crate::*;
use std::io::Error;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::{io, mem};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};


enum Handshake<S> {
    Handshaking(Box<TlsStream<S>>),
    Finished,
}


pub struct Connecting<'a, S> {
    handshake: Handshake<S>,
    config: Config<'a>,
    sent_client_hello: bool,
}

impl<'a, S: AsyncRead + AsyncWrite + Unpin> Connecting<'a, S> {
    fn handle_message(tls_stream: &mut TlsStream<S>, config: &mut Config<'_>, cx: &mut Context<'_>) -> Poll<HlsResult<bool>> {
        let record = RecordLayer::from_bytes(tls_stream.read_buffer.filled_mut(), tls_stream.handshake_finished, Some(tls_stream.conn.cipher_suite()))?;
        match record.context_type {
            RecordType::CipherSpec => tls_stream.handshake_finished = true,
            RecordType::Alert => {
                let record_len = record.len as usize + 5;
                return Poll::Ready(Err(tls_stream.handle_by_alert(tls_stream.handshake_finished, record_len)?.into()));
            }
            RecordType::HandShake => {
                for message in record.messages {
                    match message {
                        Message::ServerHello(v) => tls_stream.conn.set_by_server_hello(&v)?,
                        Message::Certificate(v) => {
                            let config = config.client_mut().ok_or("missing config")?;
                            tls_stream.conn.set_by_certificate(v, config.ca_certs, config.sni)?;
                        }
                        Message::ServerKeyExchange(v) => tls_stream.conn.set_by_server_exchange_key(v)?,
                        Message::ServerHelloDone(_) => {
                            if tls_stream.write_buffer.is_empty() {
                                tls_stream.handle_by_server_hello_done(config)?;
                            }
                            return match tls_stream.write_buffer(cx)? {
                                Poll::Ready(_) => Poll::Ready(Ok(true)),
                                Poll::Pending => Poll::Pending,
                            };
                        }
                        Message::ClientHello(v) => {
                            if tls_stream.write_buffer.is_empty() {
                                let random = rand::random::<[u8; 32]>();
                                let server = config.server_mut().ok_or("missing config")?;
                                let mut record = tls_stream.conn.gen_server_hello(v, server.server_cert, server.cert_key, &random)?;
                                let session_id = rand::random::<[u8; 32]>();
                                record.messages[0].server_mut().ok_or(HlsError::NullPointer)?.set_session_id(&session_id);

                                record.write_to(&mut tls_stream.write_buffer, 1)?;
                                tls_stream.conn.update_session(&tls_stream.write_buffer.filled()[5..])?;
                            }
                            if tls_stream.client_hello.is_empty() {
                                let len = record.len as usize + 5;
                                tls_stream.client_hello.extend_from_slice(tls_stream.read_buffer[..len].as_ref());
                            }
                            match tls_stream.write_buffer(cx)? {
                                Poll::Ready(_) => break,
                                Poll::Pending => return Poll::Pending,
                            }
                        }
                        Message::ClientKeyExchange(v) => {
                            tls_stream.conn.set_by_client_exchange_key(v);
                            tls_stream.conn.make_cipher(true)?;
                        }
                        Message::Payload(_) => {
                            if tls_stream.write_buffer.is_empty() {
                                let record_len = record.len as usize + 5;
                                let mut out = vec![0; record_len];
                                let len = tls_stream.conn.read_message(&tls_stream.read_buffer[..record_len], &mut out)?;
                                tls_stream.conn.verify_finish(&out[..len], false)?;

                                let mut ticket = SessionTicket::default();
                                let tbs = rand::random::<[u8; 276]>();
                                ticket.tls_ticket_mut().set_value(&tbs);
                                tls_stream.write_buffer.write_slice(&[22, 3, 3])?;
                                tls_stream.write_buffer.write_u16(ticket.len() as u16)?;
                                ticket.write_to(&mut tls_stream.write_buffer)?;
                                tls_stream.conn.update_session(&tls_stream.write_buffer.filled()[5..])?;
                                tls_stream.write_buffer.write_slice(&[20, 3, 3, 0, 1, 1])?;
                                let record_len = tls_stream.conn.make_finish_message(tls_stream.write_buffer.unfilled_mut(), true)?;
                                tls_stream.write_buffer.add_len(record_len);
                            }
                            return match tls_stream.write_buffer(cx)? {
                                Poll::Ready(_) => Poll::Ready(Ok(true)),
                                Poll::Pending => Poll::Pending,
                            };
                        }
                        Message::CertificateRequest(v) => {
                            let config = config.client_mut().ok_or("missing config")?;
                            tls_stream.conn.set_by_cert_req(v, config.client_cert.first_mut())?;
                        }
                        _ => {}
                    }
                }
            }
            RecordType::ApplicationData => {}
        }
        Poll::Ready(Ok(false))
    }
}


impl<'a, S: AsyncRead + AsyncWrite + Unpin> Future for Connecting<'a, S> {
    type Output = HlsResult<TlsStream<S>>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let connector = self.get_mut();
        let stream = match connector.handshake {
            Handshake::Handshaking(ref mut stream) => stream,
            Handshake::Finished => return Poll::Ready(Err(RlsError::HandShake(HandShakeError::PollWhileFinish).into())),
        };
        if !connector.sent_client_hello {
            if stream.write_buffer.is_empty() {
                stream.handle_client_hello(connector.config.client_mut().ok_or("missing config")?)?;
            }
            match stream.write_buffer(cx)? {
                Poll::Ready(_) => connector.sent_client_hello = true,
                Poll::Pending => return Poll::Pending,
            }
        }
        let stream = loop {
            let record_len = match stream.read_next_record(cx)? {
                Poll::Ready(len) => len,
                Poll::Pending => return Poll::Pending,
            };
            if stream.read_buffer.filled()[0] == 22 {
                stream.conn.update_session(&stream.read_buffer.filled()[5..record_len])?;
            }
            let hello_done = match Connecting::handle_message(stream, &mut connector.config, cx)? {
                Poll::Ready(status) => status,
                Poll::Pending => {
                    println!("handshake pending");
                    return Poll::Pending;
                }
            };
            stream.read_buffer.used_empty(record_len);
            if hello_done { break mem::replace(&mut connector.handshake, Handshake::Finished); }
        };
        match stream {
            Handshake::Handshaking(mut stream) => {
                stream.read_buffer.move_to(stream.read_buffer.offset(), 0);
                stream.write_buffer.reset();
                Poll::Ready(Ok(*stream))
            }
            Handshake::Finished => Poll::Ready(Err(RlsError::HandShake(HandShakeError::PollWhileFinish).into())),
        }
    }
}

pub struct TlsStream<S> {
    conn: Connection,
    stream: S,
    handshake_finished: bool,
    read_buffer: Buffer,
    write_buffer: Buffer,
    shutdown_wrote: bool,
    wrote_len: usize,
    pending: Vec<usize>,
    client_hello: Vec<u8>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> TlsStream<S> {
    fn _connect(stream: S, conn: Connection, config: Config<'_>, buffer: Buffer) -> Connecting<'_, S> {
        let stream = TlsStream {
            stream,
            conn,
            handshake_finished: false,
            read_buffer: Buffer::default(),
            write_buffer: buffer,
            shutdown_wrote: false,
            wrote_len: 0,
            pending: vec![],
            client_hello: vec![],
        };
        Connecting {
            handshake: Handshake::Handshaking(Box::new(stream)),
            config,
            sent_client_hello: false,
        }
    }
    #[inline]
    pub fn connect(stream: S, config: ClientConfig<'_>) -> Connecting<'_, S> {
        Connecting {
            handshake: Handshake::Handshaking(Box::new(TlsStream {
                stream,
                conn: Connection::default().with_verify(config.verify),
                handshake_finished: false,
                read_buffer: Buffer::default(),
                write_buffer: Buffer::default(),
                shutdown_wrote: false,
                wrote_len: 0,
                pending: vec![],
                client_hello: vec![],
            })),
            sent_client_hello: false,
            config: Config::Client(config),
        }
    }

    #[inline]
    pub fn accept(stream: S, config: ServerConfig<'_>) -> Connecting<'_, S> {
        TlsStream::_connect(stream, Connection::default(), Config::Server(config), Buffer::default())
    }

    pub fn alpn(&self) -> Option<&ALPN> {
        self.conn.alpn()
    }

    pub fn client_hello(&self) -> &[u8] { &self.client_hello }
}

impl<S> TlsStreamHandle for TlsStream<S> {
    #[inline]
    fn conn_wbuf(&mut self) -> (&mut Connection, &mut Buffer) {
        (&mut self.conn, &mut self.write_buffer)
    }

    #[inline]
    fn conn_rbuf(&mut self) -> (&mut Connection, &mut Buffer) {
        (&mut self.conn, &mut self.read_buffer)
    }
}

impl<S> TlsStream<S> {
    fn read_message(&mut self, buf: &mut ReadBuf<'_>, record_len: usize) -> io::Result<usize> {
        let record = RecordLayer::from_bytes(self.read_buffer.filled_mut(), self.handshake_finished, None)?;
        match record.context_type {
            RecordType::CipherSpec => {
                self.handshake_finished = true;
                self.read_buffer.move_to(record_len..self.read_buffer.len(), 0);
            }
            RecordType::Alert => return Err(self.handle_by_alert(self.handshake_finished, record_len)?.into()),
            RecordType::HandShake => {
                if self.handshake_finished {
                    let len = self.conn.read_message(&self.read_buffer[..record_len], buf.initialized_mut())?;
                    self.conn.verify_finish(&buf.initialized()[..len], true)?;
                } else {
                    self.conn.update_session(&self.read_buffer[5..record_len])?;
                }
                self.read_buffer.move_to(record_len..self.read_buffer.len(), 0);
            }
            RecordType::ApplicationData => {
                let len = self.conn.read_message(&self.read_buffer[..record_len], buf.initialized_mut())?;
                buf.set_filled(len);
                self.read_buffer.move_to(record_len..self.read_buffer.len(), 0);
                return Ok(len);
            }
        }
        Ok(0)
    }
}

impl<S: AsyncRead + Unpin> TlsStream<S> {
    fn read_next_record(&mut self, cx: &mut Context<'_>) -> Poll<HlsResult<usize>> {
        if self.read_buffer.len() < 5 {
            loop {
                let stream = Pin::new(&mut self.stream);
                let mut buf = ReadBuf::new(self.read_buffer.unfilled_mut());
                match stream.poll_read(cx, &mut buf)? {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(_) => {
                        let len = buf.filled().len();
                        self.read_buffer.add_len(len);
                        if self.read_buffer.len() > 5 { break; }
                    }
                }
            }
        }
        let filled = self.read_buffer.filled();
        let record_len = u16::from_be_bytes([filled[3], filled[4]]) as usize + 5;
        while self.read_buffer.len() < record_len {
            let stream = Pin::new(&mut self.stream);
            let mut buf = ReadBuf::new(self.read_buffer.unfilled_mut());
            match stream.poll_read(cx, &mut buf)? {
                Poll::Ready(_) => {
                    let len = buf.filled().len();
                    self.read_buffer.add_len(len);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(record_len))
    }
}

impl<S: AsyncWrite + Unpin> TlsStream<S> {
    #[inline]
    fn write_buffer(&mut self, cx: &mut Context<'_>) -> Poll<HlsResult<()>> {
        loop {
            let stream = Pin::new(&mut self.stream);
            match stream.poll_write(cx, self.write_buffer.filled())? {
                Poll::Ready(wrote) => if self.write_buffer.used_empty(wrote) { break },
                Poll::Pending => return Poll::Pending,
            }
        }
        self.write_buffer.reset();
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for TlsStream<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if self.shutdown_wrote { return Poll::Ready(Ok(())); }
        let stream = self.get_mut();
        loop {
            let record_len = match stream.read_next_record(cx)? {
                Poll::Ready(len) => len,
                Poll::Pending => return Poll::Pending,
            };
            match stream.read_message(buf, record_len) {
                Ok(len) => if len > 0 { return Poll::Ready(Ok(())); } else { continue; }
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TlsStream<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, Error>> {
        let stream = self.get_mut();
        let chucks = buf.chunks(16384).collect::<Vec<_>>();
        if stream.pending.is_empty() {
            stream.wrote_len = 0;
            stream.pending = (0..chucks.len()).collect();
        }
        loop {
            if stream.pending.is_empty() { break; }
            if stream.write_buffer.is_empty() {
                let record_len = stream.conn.make_message(RecordType::ApplicationData, &mut stream.write_buffer[..], chucks[stream.pending[0]])?;
                stream.write_buffer.set_len(record_len);
                stream.wrote_len += chucks[stream.pending[0]].len();
            }
            match stream.write_buffer(cx)? {
                Poll::Ready(_) => stream.pending.remove(0),
                Poll::Pending => return Poll::Pending,
            };
        }
        assert_eq!(stream.wrote_len, buf.len());
        Poll::Ready(Ok(stream.wrote_len))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let stream = self.get_mut();
        if stream.write_buffer.is_empty() {
            let len = stream.conn.make_message(RecordType::Alert, &mut stream.write_buffer[..], &Alert::close_notify().to_bytes())?;
            stream.write_buffer.set_len(len);
        }
        match stream.shutdown_wrote {
            true => Pin::new(&mut stream.stream).poll_shutdown(cx),
            false => match stream.write_buffer(cx)? {
                Poll::Ready(_) => {
                    stream.shutdown_wrote = true;
                    Pin::new(&mut stream.stream).poll_shutdown(cx)
                }
                Poll::Pending => Poll::Pending,
            }
        }
    }
}
