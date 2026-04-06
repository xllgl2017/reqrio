mod connect;

use super::ext::TimeoutRW;
use crate::error::HlsResult;
use crate::stream::config::Config;
use crate::stream::{ConnParam, TlsStreamHandle};
use crate::{Buffer, ClientConfig, ProxyStream, ServerConfig};
use reqtls::{Alert, Connection, RecordLayer, RecordType, WriteExt, ALPN};
use std::io;
use std::io::Error;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use connect::{Connecting, Handshake};


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

pub struct TlsStreamA {
    stream: TlsStream<ProxyStream<TcpStream>>,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
}

impl TlsStreamA {
    pub async fn connect_timeout(param: ConnParam<'_>, tcp: ProxyStream<TcpStream>) -> HlsResult<TlsStreamA> {
        let connect_timeout = param.timeout.connect();
        let read_timeout = param.timeout.read();
        let write_timeout = param.timeout.write();
        let config = ClientConfig {
            sni: param.addr.host(),
            alpn: param.alpn,
            fingerprint: param.fingerprint,
            client_cert: param.cert,
            cert_key: param.key,
            verify: param.verify,
            ca_certs: param.ca_cert,
        };
        Ok(TlsStreamA {
            stream: tokio::time::timeout(connect_timeout, TlsStream::connect(tcp, config)).await??,
            read_timeout: Some(read_timeout),
            write_timeout: Some(write_timeout),
        })
    }

    pub fn alpn(&self) -> Option<&ALPN> {
        self.stream.alpn()
    }
}

impl TimeoutRW<TlsStream<ProxyStream<TcpStream>>> for TlsStreamA {
    fn stream(&mut self) -> &mut TlsStream<ProxyStream<TcpStream>> {
        &mut self.stream
    }

    fn read_timeout(&self) -> Option<Duration> {
        self.read_timeout
    }

    fn write_timeout(&self) -> Option<Duration> {
        self.write_timeout
    }
}
