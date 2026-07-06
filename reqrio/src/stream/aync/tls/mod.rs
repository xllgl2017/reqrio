mod connect;

use super::ext::TimeoutRW;
use crate::error::HlsResult;
use crate::stream::{ConnParam, StreamParam};
use crate::{Buffer, ClientConfig, HlsError, ProxyStream, ServerConfig};
use connect::{Connecting, Handshake};
use reqtls::{rand, Alert, BufferError, Config, Connection, RecordType, StreamHandle, WriteExt, ALPN};
use std::io::Error;
use std::ops::Range;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use std::{io, mem};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::Notify;

pub struct ReadOffset {
    using_blocks: Arc<AtomicUsize>,
    offset: Range<usize>,
    notify: Arc<Notify>,
    buffer: Buffer,
}

impl ReadOffset {
    fn record(&self) -> &[u8] {
        let end = self.offset.end - self.offset.start;
        &self.buffer.slice_at(self.offset.start)[..end]
    }

    fn release(&mut self) {
        let current = self.using_blocks.fetch_sub(1, Ordering::SeqCst);
        if current == 1 {
            self.notify.notify_waiters();
        }
    }
}

pub struct StreamRead<S: Send> {
    buffer: Buffer,
    reader: ReadHalf<S>,
    using_blocks: Arc<AtomicUsize>,
    sender: Sender<io::Result<ReadOffset>>,
    notify: Arc<Notify>,
    next_record_pos: usize,
}

impl<S: AsyncRead + Unpin + Send> StreamRead<S> {
    async fn check_move(&mut self, max_size: usize) -> HlsResult<()> {
        if self.buffer.unfilled_len() < max_size {
            let notified = self.notify.notified();
            let using_blocks = self.using_blocks.load(Ordering::SeqCst);
            if using_blocks != 0 {
                notified.await;
            }
            let offset = self.next_record_pos..self.buffer.end();
            self.next_record_pos = 0;
            self.buffer.move_to(offset, 0)?;
        }
        if self.buffer.unfilled().is_empty() {
            return Err(BufferError::CapacityTooSmall {
                needed: max_size + self.buffer.capacity(),
                current: self.buffer.capacity(),
            }.into());
        }
        Ok(())
    }


    async fn read_size(&mut self, max_size: usize) -> HlsResult<()> {
        while self.buffer.offset().end - self.next_record_pos < max_size {
            self.check_move(max_size).await?;
            let len = self.reader.read(self.buffer.unfilled()).await?;
            if len == 0 { return Err(HlsError::PeerClosedConnection); }
            self.buffer.add_len(len);
        }
        Ok(())
    }

    async fn read_record(&mut self) -> io::Result<Range<usize>> {
        let had_buf = self.buffer.end() - self.next_record_pos > 5;
        if !had_buf { self.read_size(5).await?; }
        let filled = self.buffer.slice_at(self.next_record_pos);
        let record_len = u16::from_be_bytes([filled[3], filled[4]]) as usize + 5;
        self.read_size(record_len).await?;
        let res = self.next_record_pos..self.next_record_pos + record_len;
        self.next_record_pos += record_len;
        Ok(res)
    }
}


pub struct TlsStream<S> {
    conn: Connection,
    writer: WriteHalf<S>,
    reader: Receiver<io::Result<ReadOffset>>,
    encrypted_channel: bool,
    handshake_finished: bool,
    hello_retrying: bool,
    write_buffer: Buffer,
    shutdown_wrote: bool,
    wrote_len: usize,
    pending: Vec<usize>,
    client_hello: Vec<u8>,
}


impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> TlsStream<S> {
    fn _connect(stream: S, conn: Connection, config: Config<'_>, buffer: Buffer) -> Connecting<'_, S> {
        let (reader, writer) = tokio::io::split(stream);
        let (sender, receiver) = tokio::sync::mpsc::channel(30);
        TlsStream::<S>::read_work(reader, sender);
        let stream = TlsStream {
            reader: receiver,
            writer,
            conn,
            encrypted_channel: false,
            handshake_finished: false,
            hello_retrying: false,
            write_buffer: buffer,
            shutdown_wrote: false,
            wrote_len: 0,
            pending: vec![],
            client_hello: vec![],
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
        let (sender, receiver) = tokio::sync::mpsc::channel(30);
        TlsStream::<S>::read_work(reader, sender);
        let session = config.session.as_ref().cloned().unwrap_or_else(Default::default);
        Connecting {
            handshake: Handshake::Handshaking(Box::new(TlsStream {
                reader: receiver,
                writer,
                conn: Connection::from_client(rand::random(), session, mem::take(&mut config.key_log))
                    .with_verify(config.verify).with_mtls(!config.client_cert.is_empty()),
                handshake_finished: false,
                hello_retrying: false,
                write_buffer: Buffer::default(),
                shutdown_wrote: false,
                wrote_len: 0,
                pending: vec![],
                client_hello: vec![],
                encrypted_channel: false,
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

impl<S: AsyncRead + Unpin + Send + 'static> TlsStream<S> {
    fn read_work(reader: ReadHalf<S>, sender: Sender<io::Result<ReadOffset>>) {
        tokio::spawn(async move {
            let mut stream = StreamRead {
                reader,
                using_blocks: Default::default(),
                buffer: Buffer::with_capacity(16438 * 2),
                sender,
                notify: Arc::new(Notify::new()),
                next_record_pos: 0,
            };
            loop {
                match stream.read_record().await {
                    Ok(record_offset) => {
                        stream.using_blocks.fetch_add(1, Ordering::SeqCst);
                        stream.sender.send(Ok(ReadOffset {
                            using_blocks: stream.using_blocks.clone(),
                            offset: record_offset,
                            notify: stream.notify.clone(),
                            buffer: stream.buffer.clone(),
                        })).await.unwrap();
                    }
                    Err(e) => {
                        stream.sender.send(Err(e)).await.unwrap();
                        break;
                    }
                }
            }
        });
    }
}

impl<S: AsyncRead + Unpin> TlsStream<S> {
    fn read_next_record(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<ReadOffset>> {
        match self.reader.poll_recv(cx) {
            Poll::Ready(Some(res)) => Poll::Ready(res),
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
            let Poll::Ready(mut record) = stream.read_next_record(cx)?else { return Poll::Pending; };
            let len = stream.handle_record(record.record(), None, buf.initialized_mut())?;
            record.release();
            if len == 0 { continue; }
            buf.set_filled(len);
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