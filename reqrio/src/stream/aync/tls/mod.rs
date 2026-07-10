mod connect;

use super::ext::TimeoutRW;
use crate::error::HlsResult;
use crate::stream::{ConnParam, StreamParam};
use crate::*;
use connect::{Connecting, Handshake};
use reqtls::{rand, Alert, Config, Connection, RecordType, StreamHandle, WriteExt, ALPN};
use std::io::Error;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use std::{io, mem};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc::Receiver;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

pub struct TlsStream<S> {
    conn: Connection,
    writer: WriteHalf<S>,
    reader: Receiver<io::Result<ReadOffset>>,
    encrypted_channel: bool,
    handshake_finished: bool,
    hello_retrying: bool,
    read_buffer: Buffer,
    write_buffer: Buffer,
    shutdown_wrote: bool,
    wrote_len: usize,
    pending: Vec<usize>,
    client_hello: Vec<u8>,
    closed: oneshot::Sender<()>,
    read_work: JoinHandle<()>,
}


impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> TlsStream<S> {
    fn _connect(stream: S, conn: Connection, config: Config<'_>, buffer: Buffer) -> Connecting<'_, S> {
        let (reader, writer) = tokio::io::split(stream);
        let (sender, receiver) = tokio::sync::mpsc::channel(100);
        let read_buffer = Buffer::with_capacity(2 * 16438);
        let (closed_sender, closed_receive) = oneshot::channel();
        let mut reader = StreamRead {
            reader,
            buffer: RecordBuffer::new(read_buffer.clone()),
            sender,
            closed: closed_receive,
            notify: Arc::new(Default::default()),
        };
        let stream = TlsStream {
            reader: receiver,
            writer,
            conn,
            encrypted_channel: false,
            handshake_finished: false,
            hello_retrying: false,
            read_buffer,
            write_buffer: buffer,
            shutdown_wrote: false,
            wrote_len: 0,
            pending: vec![],
            client_hello: vec![],
            closed: closed_sender,
            read_work: tokio::spawn(async move { reader.run().await }),
        };
        Connecting {
            handshake: Handshake::Handshaking(Box::new(stream)),
            sent_client_hello: matches!(config, Config::Server(_)),
            config,
        }
    }
    #[inline]
    pub fn connect(stream: S, mut config: ClientConfig<'_>) -> Connecting<'_, S> {
        let (reader, writer) = tokio::io::split(stream);
        let (sender, receiver) = tokio::sync::mpsc::channel(100);
        let (closed_sender, closed_receive) = oneshot::channel();
        let read_buffer = Buffer::with_capacity(2 * 16438);
        let mut reader = StreamRead {
            reader,
            buffer: RecordBuffer::new(read_buffer.clone()),
            sender,
            closed: closed_receive,
            notify: Arc::new(Default::default()),
        };
        let session = config.session.as_ref().cloned().unwrap_or_else(Default::default);
        Connecting {
            handshake: Handshake::Handshaking(Box::new(TlsStream {
                reader: receiver,
                writer,
                conn: Connection::from_client(rand::random(), session, mem::take(&mut config.key_log))
                    .with_verify(config.verify).with_mtls(!config.client_cert.is_empty()),
                handshake_finished: false,
                hello_retrying: false,
                read_buffer,
                write_buffer: Buffer::default(),
                shutdown_wrote: false,
                wrote_len: 0,
                pending: vec![],
                client_hello: vec![],
                encrypted_channel: false,
                closed: closed_sender,
                read_work: tokio::spawn(async move { reader.run().await }),
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

impl<S> StreamHandle for TlsStream<S> {
    #[inline]
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

impl<S> TlsStream<S> {
    pub fn connection(&self) -> &Connection {
        &self.conn
    }
}

impl<S: AsyncRead + Unpin> TlsStream<S> {
    fn read_next_record(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<ReadOffset>> {
        match self.reader.poll_recv(cx) {
            Poll::Ready(Some(res)) => {
                // println!("recv: {:?}", res);
                Poll::Ready(res)
            }
            Poll::Ready(None) => Poll::Ready(Err(Error::other("read none"))),
            Poll::Pending => Poll::Pending
        }
    }
}

impl<S: AsyncWrite + Unpin> TlsStream<S> {
    #[inline]
    fn write_buffer(&mut self, cx: &mut Context<'_>) -> Poll<HlsResult<()>> {
        loop {
            let stream = Pin::new(&mut self.writer);
            match stream.poll_write(cx, self.write_buffer.filled())? {
                Poll::Ready(wrote) => {
                    if wrote == 0 { return Poll::Ready(Err(HlsError::PeerClosedConnection)); }
                    if self.write_buffer.used_empty(wrote) { break; }
                }
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
            let Poll::Ready(mut record) = stream.read_next_record(cx)?else {
                if buf.filled().is_empty() { return Poll::Pending; }
                return Poll::Ready(Ok(()));
            };
            let len = stream.handle_record(record.record(&stream.read_buffer), None, buf.initialize_unfilled())?;
            record.release();
            buf.set_filled(buf.filled().len() + len);
            if len == 0 || buf.remaining() > 16384 { continue; }
            return Poll::Ready(Ok(()));
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
                let record_len = stream.conn.make_message(RecordType::ApplicationData, stream.write_buffer.unfilled(), chucks[stream.pending[0]])?;
                stream.write_buffer.add_len(record_len);
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
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let stream = self.get_mut();
        if stream.write_buffer.is_empty() {
            if stream.closed.poll_closed(cx).is_pending() { return Poll::Pending; }
            let len = stream.conn.make_message(RecordType::Alert, stream.write_buffer.unfilled(), &Alert::close_notify().to_bytes())?;
            stream.write_buffer.add_len(len);
        }
        match stream.shutdown_wrote {
            true => Pin::new(&mut stream.writer).poll_shutdown(cx),
            false => match stream.write_buffer(cx)? {
                Poll::Ready(_) => {
                    stream.shutdown_wrote = true;
                    Pin::new(&mut stream.writer).poll_shutdown(cx)
                }
                Poll::Pending => Poll::Pending,
            }
        }
    }
}

impl<S> Drop for TlsStream<S> {
    fn drop(&mut self) {
        println!("wait read thread finish");
        self.read_work.abort();
        println!("closed read thread");
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
        let config = ClientConfig::from(param);
        Ok(TlsStreamA {
            stream: tokio::time::timeout(connect_timeout, TlsStream::connect(tcp, config)).await??,
            read_timeout: Some(read_timeout),
            write_timeout: Some(write_timeout),
        })
    }

    pub fn alpn(&self) -> Option<&ALPN> {
        self.stream.alpn()
    }

    pub fn get_ref(&self) -> &TlsStream<ProxyStream<TcpStream>> { &self.stream }
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