use crate::error::{HlsError, HlsResult};
use crate::stream::ConnParam;
use crate::{Buffer, ALPN};
use reqtls::*;
use std::io::Error;
use std::ops::Range;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};


pub struct TlsConnector<'a> {
    sni: &'a str,
    fingerprint: &'a mut Fingerprint,
    alpn: &'a ALPN,
}

impl<'a> TlsConnector<'a> {
    pub async fn connect<S: AsyncRead + AsyncWrite + Unpin>(self, stream: S) -> HlsResult<TlsStream<S>> {
        TlsStream::connect(self, stream).await
    }
}

impl<'a> From<(&'a str, &'a mut Fingerprint, &'a ALPN)> for TlsConnector<'a> {
    fn from((sni, fingerprint, alpn): (&'a str, &'a mut Fingerprint, &'a ALPN)) -> Self {
        TlsConnector {
            sni,
            fingerprint,
            alpn,
        }
    }
}

impl<'a> From<ConnParam<'a>> for TlsConnector<'a> {
    fn from(value: ConnParam<'a>) -> Self {
        TlsConnector {
            sni: value.url.addr().host(),
            fingerprint: value.fingerprint,
            alpn: value.alpn,
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
    write_range: Range<usize>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> TlsStream<S> {
    pub async fn connect(mut connector: TlsConnector<'_>, mut stream: S) -> HlsResult<TlsStream<S>> {
        let client_random = rand::random::<[u8; 32]>();
        let mut conn = Connection::new(client_random.to_vec());
        let mut record = RecordLayer::from_bytes(connector.fingerprint.client_hello_mut(), false)?;
        let message = record.messages.get_mut(0).ok_or(RlsError::ClientHelloNone)?;
        message.client_mut().ok_or(HlsError::NonePointer)?.set_random(client_random.clone());
        message.client_mut().ok_or(HlsError::NonePointer)?.set_server_name(connector.sni);
        message.client_mut().ok_or(HlsError::NonePointer)?.set_session_id(rand::random());
        match connector.alpn {
            ALPN::Http20 => message.client_mut().ok_or(HlsError::NonePointer)?.add_h2_alpn(),
            _ => message.client_mut().ok_or(HlsError::NonePointer)?.remove_h2_alpn()
        }
        message.client_mut().ok_or(HlsError::NonePointer)?.remove_tls13();
        let bs = record.handshake_bytes();
        conn.update_session(&bs[5..])?;
        stream.write(&bs).await?;
        stream.flush().await?;
        let mut stream = TlsStream {
            stream,
            conn,
            handshake_finished: false,
            read_buffer: Buffer::with_capacity(16413),
            write_buffer: Buffer::with_capacity(16413),
            shutdown_wrote: false,
            wrote_len: 0,
            write_range: 0..0,
        };
        while !stream.handshake_finished {
            stream.read_packet().await?;
            stream.handle_message(&mut connector).await?;
        }

        stream.read_packet().await?;
        let mut record = RecordLayer::from_bytes(stream.read_buffer.filled_mut(), stream.handshake_finished)?;
        stream.conn.read_message(&mut record)?;
        stream.read_buffer.reset();
        stream.write_buffer.reset();
        Ok(stream)
    }

    pub async fn read_packet(&mut self) -> HlsResult<()> {
        self.read_buffer.reset();
        self.read_buffer.async_read_limit(&mut self.stream, 5).await?;
        if self.read_buffer.len() < 5 { return Err(HlsError::InvalidHeadSize)?; }
        let payload_len = u16::from_be_bytes([self.read_buffer[3], self.read_buffer[4]]) as usize;
        while self.read_buffer.len() - 5 < payload_len {
            self.read_buffer.async_read_limit(&mut self.stream, payload_len + 5 - self.read_buffer.len()).await?;
        }
        if !self.handshake_finished { self.conn.update_session(&self.read_buffer.filled()[5..])?; }
        Ok(())
    }

    async fn handle_message(&mut self, connector: &mut TlsConnector<'_>) -> HlsResult<()> {
        let record = RecordLayer::from_bytes(self.read_buffer.filled_mut(), self.handshake_finished)?;
        match record.context_type {
            RecordType::CipherSpec => self.handshake_finished = true,
            RecordType::Alert => {}
            RecordType::HandShake => {
                for message in record.messages {
                    match message {
                        Message::ServerHello(v) => {
                            println!("{:#?}-{}", v.cipher_suite, connector.sni);
                            self.conn.set_by_server_hello(v)?;
                        }
                        Message::ServerKeyExchange(v) => {
                            // println!("{:#?}", v);
                            self.conn.set_by_exchange_key(v.hellman_param().pub_key().clone(), v.hellman_param().named_curve().clone())
                        }
                        Message::ServerHelloDone(_) => {
                            let keypair = PriKey::new(self.conn.named_curve())?;
                            let client_pub_key = keypair.pub_key();
                            let mut record = RecordLayer::from_bytes(connector.fingerprint.client_key_exchange_mut(), false)?;
                            let client_key_exchange = record.messages.get_mut(0).ok_or(HlsError::NonePointer)?;
                            client_key_exchange.client_key_exchange_mut().unwrap().set_pub_key(client_pub_key);
                            let bs = record.handshake_bytes();
                            self.conn.update_session(&bs[5..])?;
                            self.stream.write_all(&bs).await?;

                            self.stream.write_all(&connector.fingerprint.change_cipher_spec()).await?;
                            let share_secret = keypair.diffie_hellman(self.conn.server_pub_key().as_ref())?;
                            let handshake_hash = self.conn.session_hash()?;
                            self.conn.make_cipher(&share_secret, handshake_hash.clone())?;

                            let record_len = self.conn.make_finish_message(&handshake_hash, &mut self.write_buffer[..])?;

                            // let aead = self.conn.aead().ok_or(RlsError::AeadNone)?;
                            self.stream.write_all(&self.write_buffer[..record_len]).await?;
                            break;
                        }
                        _ => {}
                    }
                }
            }
            RecordType::ApplicationData => {}
        }
        Ok(())
    }

    pub fn alpn(&self) -> Option<&str> {
        Some(self.conn.alpn()?.value())
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for TlsStream<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let stream = self.get_mut();
        loop {
            let read_len = match stream.read_buffer.len() {
                0 => {
                    stream.read_buffer.reset();
                    5
                }
                _ => {
                    let pd_len = u16::from_be_bytes([stream.read_buffer[3], stream.read_buffer[4]]) as usize;
                    if pd_len+5<stream.read_buffer.len() {
                        println!("reas {} {} {:?}", pd_len, stream.read_buffer.len(), &stream.read_buffer[..5]);
                    }
                    pd_len + 5 - stream.read_buffer.len()
                }
            };
            if read_len == 0 { break; }
            let mut rd = ReadBuf::new(&mut stream.read_buffer.unfilled_mut()[..read_len]);
            match Pin::new(&mut stream.stream).poll_read(cx, &mut rd) {
                Poll::Ready(Ok(_)) => {
                    let fill_len = rd.filled().len();
                    if fill_len == 0 { return Poll::Ready(Ok(())); }
                    stream.read_buffer.set_len(stream.read_buffer.len() + fill_len);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
        }
        let len = u16::from_be_bytes([stream.read_buffer[3], stream.read_buffer[4]]) as usize;
        if stream.read_buffer.len() < len + 5 { return Poll::Ready(Ok(())); }
        let mut record = RecordLayer::from_bytes(stream.read_buffer.filled_mut(), stream.handshake_finished)?;
        let rt = record.context_type.as_u8();
        let len = stream.conn.read_message(&mut record)?;
        let aead = stream.conn.aead().ok_or(RlsError::AeadNone)?;
        if rt == 0x15 && &stream.read_buffer[aead.payload_start()..aead.payload_start() + len] == &[1, 0] {
            return Poll::Ready(Err(HlsError::PeerClosedConnection.into()));
        }
        buf.put_slice(&stream.read_buffer.filled()[aead.payload_start()..aead.payload_start() + len]);
        stream.read_buffer.reset();
        Poll::Ready(Ok(()))
    }
}


impl<S: AsyncWrite + Unpin> AsyncWrite for TlsStream<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, Error>> {
        let stream = self.get_mut();
        let chucks = buf.chunks(16384).collect::<Vec<_>>();
        if stream.write_range.start == stream.write_range.end {
            stream.write_range = 0..chucks.len();
            stream.wrote_len = 0;
        }

        for i in stream.write_range.start..stream.write_range.end {
            let aead = stream.conn.aead().ok_or(RlsError::AeadNone)?;
            let record_len = aead.encrypted_payload_len(chucks[i].len()) + 5;
            // println!("{} {} {}", stream.wrote_len, i, stream.wrote_len % 16384);
            if stream.wrote_len / 16384 == i {
                stream.write_buffer.reset();
                let push_len = stream.write_buffer.push_slice_in(aead.payload_start(), chucks[i]);
                // stream.write_buffer.set_len(aead.payload_start() + push_len);
                stream.conn.make_message(RecordType::ApplicationData, &mut stream.write_buffer[..], push_len)?;
                stream.wrote_len += chucks[i].len();
            }
            match Pin::new(&mut stream.stream).poll_write(cx, &stream.write_buffer[..record_len]) {
                Poll::Ready(Ok(_)) => {
                    stream.write_range.start = i + 1
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        stream.write_buffer.reset();
        if stream.wrote_len>buf.len() {
            println!("write {} {}", stream.wrote_len, buf.len());
        }
        Poll::Ready(Ok(stream.wrote_len))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let stream = self.get_mut();

        if stream.write_buffer.len() == 0 {
            stream.write_buffer.reset();
            let aead = stream.conn.aead().ok_or(RlsError::AeadNone)?;
            // stream.write_buffer.set_len(31);
            stream.write_buffer[aead.payload_start()..aead.payload_start() + 2].copy_from_slice(&[1, 0]);
            stream.conn.make_message(RecordType::Alert, &mut stream.write_buffer[..], 2)?;
        }
        if stream.shutdown_wrote {
            Pin::new(&mut stream.stream).poll_shutdown(cx)
        } else {
            match Pin::new(&mut stream.stream).poll_write(cx, &stream.write_buffer[..31]) {
                Poll::Ready(Ok(_)) => Pin::new(&mut stream.stream).poll_shutdown(cx),
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Pending,
            }
        }
    }
}