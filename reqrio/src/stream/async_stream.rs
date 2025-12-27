use std::io::Error;
use std::ops::Range;
use std::pin::Pin;
use std::task::{Context, Poll};
use crate::error::{HlsError, HlsResult};
use crate::stream::ConnParam;
use crate::{Buffer, ALPN};
use reqtls::*;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

pub struct AsyncStream<S> {
    conn: Connection,
    stream: S,
    handshake_finished: bool,
    buffer: Buffer,
    shutdown_wrote: bool,
    wrote_len: usize,
    write_range: Range<usize>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncStream<S> {
    pub async fn connect(mut param: ConnParam<'_>, mut stream: S) -> HlsResult<AsyncStream<S>> {
        let client_random = rand::random::<[u8; 32]>();
        let mut conn = Connection::new(client_random.to_vec());
        let mut client_hello = RecordLayer::from_bytes(param.fingerprint.client_hello_mut(), false)?;
        client_hello.message.client_mut().ok_or(HlsError::NonePointer)?.set_random(client_random.clone());
        client_hello.message.client_mut().ok_or(HlsError::NonePointer)?.set_server_name(param.url.addr().host());
        client_hello.message.client_mut().ok_or(HlsError::NonePointer)?.set_session_id(rand::random());
        match param.alpn {
            ALPN::Http20 => client_hello.message.client_mut().ok_or(HlsError::NonePointer)?.add_h2_alpn(),
            _ => client_hello.message.client_mut().ok_or(HlsError::NonePointer)?.remove_h2_alpn()
        }
        client_hello.message.client_mut().ok_or(HlsError::NonePointer)?.remove_tls13();
        let bs = client_hello.handshake_bytes();
        conn.update_session(&bs[5..])?;
        stream.write(&bs).await?;
        stream.flush().await?;
        let mut stream = AsyncStream {
            stream,
            conn,
            handshake_finished: false,
            buffer: Buffer::with_capacity(16413),
            shutdown_wrote: false,
            wrote_len: 0,
            write_range: 0..0,
        };
        while !stream.handshake_finished {
            stream.read_packet().await?;
            stream.handle_message(&mut param).await?;
        }

        stream.read_packet().await?;
        let mut record = RecordLayer::from_bytes(stream.buffer.filled_mut(), stream.handshake_finished)?;
        stream.conn.read_message(&mut record)?;
        Ok(stream)
    }

    pub async fn read_packet(&mut self) -> HlsResult<()> {
        self.buffer.reset();
        self.buffer.async_read_limit(&mut self.stream, 5).await?;
        if self.buffer.len() < 5 { return Err(HlsError::InvalidHeadSize)?; }
        let payload_len = u16::from_be_bytes([self.buffer[3], self.buffer[4]]) as usize;
        while self.buffer.len() - 5 < payload_len {
            self.buffer.async_read_limit(&mut self.stream, payload_len + 5 - self.buffer.len()).await?;
        }
        if !self.handshake_finished { self.conn.update_session(&self.buffer.filled()[5..])?; }
        let record_type = RecordType::from_byte(self.buffer[0]).ok_or("LayerType Unknown")?;
        if let RecordType::CipherSpec = record_type {
            self.handshake_finished = true;
        }
        Ok(())
    }

    async fn handle_message(&mut self, param: &mut ConnParam<'_>) -> HlsResult<()> {
        let record = RecordLayer::from_bytes(self.buffer.filled_mut(), self.handshake_finished)?;
        match record.context_type {
            RecordType::CipherSpec => self.handshake_finished = true,
            RecordType::Alert => {}
            RecordType::HandShake => {
                match record.message {
                    Message::ServerHello(v) => self.conn.set_by_server_hello(v),
                    Message::ServerKeyExchange(v) => {
                        // println!("{:#?}", v);
                        self.conn.set_by_exchange_key(v.hellman_param().pub_key().clone(), v.hellman_param().named_curve().clone())
                    }
                    Message::ServerHelloDone(_) => {
                        let keypair = PriKey::new(self.conn.named_curve())?;
                        let client_pub_key = keypair.pub_key();
                        let mut client_key_exchange = RecordLayer::from_bytes(param.fingerprint.client_key_exchange_mut(), false)?;
                        client_key_exchange.message.client_key_exchange_mut().unwrap().set_pub_key(client_pub_key);
                        let bs = client_key_exchange.handshake_bytes();
                        self.conn.update_session(&bs[5..])?;
                        self.stream.write(&bs).await?;
                        self.stream.flush().await?;

                        self.stream.write(&param.fingerprint.change_cipher_spec()).await?;
                        self.stream.flush().await?;
                        let share_secret = keypair.diffie_hellman(self.conn.server_pub_key().as_ref())?;
                        let handshake_hash = self.conn.session_hash()?;
                        self.conn.make_cipher(&share_secret, handshake_hash.clone())?;

                        self.buffer.reset();
                        self.conn.make_finish_message(&handshake_hash, &mut self.buffer[..45])?;
                        self.stream.write(&self.buffer[..45]).await?;
                        self.stream.flush().await?;
                    }
                    _ => {}
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

impl<S: AsyncRead + Unpin> AsyncRead for AsyncStream<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let stream = self.get_mut();
        loop {
            let read_len = match stream.buffer.len() {
                0 => 5,
                _ => {
                    let pd_len = u16::from_be_bytes([stream.buffer[3], stream.buffer[4]]) as usize;
                    pd_len + 5 - stream.buffer.len()
                }
            };
            if read_len == 0 { break; }
            let mut rd = ReadBuf::new(&mut stream.buffer.unfilled_mut()[..read_len]);
            match Pin::new(&mut stream.stream).poll_read(cx, &mut rd) {
                Poll::Ready(Ok(_)) => {
                    let fill_len = rd.filled().len();
                    if fill_len == 0 { return Poll::Ready(Ok(())); }
                    stream.buffer.set_len(stream.buffer.len() + fill_len);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
        }
        let len = u16::from_be_bytes([stream.buffer[3], stream.buffer[4]]) as usize;
        if stream.buffer.len() < len + 5 { return Poll::Ready(Ok(())); }
        let mut record = RecordLayer::from_bytes(stream.buffer.filled_mut(), stream.handshake_finished)?;
        let rt = record.context_type.as_u8();
        let len = stream.conn.read_message(&mut record)?;
        if rt == 0x15 && &stream.buffer[13..13 + len] == &[1, 0] {
            return Poll::Ready(Err(HlsError::PeerClosedConnection.into()));
        }
        buf.put_slice(&stream.buffer.filled()[13..13 + len]);
        stream.buffer.reset();
        Poll::Ready(Ok(()))
    }
}


impl<S: AsyncWrite + Unpin> AsyncWrite for AsyncStream<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, Error>> {
        let stream = self.get_mut();
        let chucks = buf.chunks(16384).collect::<Vec<_>>();
        if stream.write_range.start == stream.write_range.end {
            stream.write_range = 0..chucks.len();
            stream.wrote_len = 0;
        }
        loop {
            if stream.write_range.start == stream.write_range.end { break; }
            for i in stream.write_range.start..stream.write_range.end {
                let len = 13 + chucks[i].len() + 16;
                if stream.wrote_len % 16413 == i {
                    stream.buffer.reset();
                    stream.buffer.push_slice_in(13, chucks[i]);
                    stream.conn.make_message(RecordType::ApplicationData, &mut stream.buffer[..len])?;
                    stream.wrote_len += len;
                }
                match Pin::new(&mut stream.stream).poll_write(cx, &stream.buffer[..len]) {
                    Poll::Ready(Ok(_)) => {
                        stream.write_range.start = i + 1
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
        }
        stream.buffer.reset();
        Poll::Ready(Ok(stream.wrote_len))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let stream = self.get_mut();

        if stream.buffer.len() == 0 {
            stream.buffer.reset();
            stream.buffer.set_len(31);
            stream.buffer[13..15].copy_from_slice(&[1, 0]);
            stream.conn.make_message(RecordType::Alert, &mut stream.buffer[..31])?;
        }
        if stream.shutdown_wrote {
            Pin::new(&mut stream.stream).poll_shutdown(cx)
        } else {
            match Pin::new(&mut stream.stream).poll_write(cx, &stream.buffer[..31]) {
                Poll::Ready(Ok(_)) => Pin::new(&mut stream.stream).poll_shutdown(cx),
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Pending,
            }
        }
    }
}