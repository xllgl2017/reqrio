use std::mem;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use reqtls::{rand, HandShakeError, Message, RecordLayer, RecordType, RlsError, SessionTicket, WriteExt};
use crate::error::HlsResult;
use crate::HlsError;
use crate::stream::config::Config;
use crate::stream::TlsStreamHandle;
use super::TlsStream;

pub(super) enum Handshake<S> {
    Handshaking(Box<TlsStream<S>>),
    Finished,
}


pub struct Connecting<'a, S> {
    pub(super) handshake: Handshake<S>,
    pub(super) config: Config<'a>,
    pub(super) sent_client_hello: bool,
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