mod proxy;
mod ws;
#[cfg(feature = "quic")]
mod quic;
#[cfg(feature = "quic")]
mod http3;
mod http2;
mod http1;
mod tls_stream;
mod read;
mod write;
mod connect;
mod message;

use crate::stream::connect::{ConnState, HTTPStreamConnect, TlsConnecting};
use crate::stream::read::StreamRead;
use crate::stream::write::{StreamShutdown, StreamWrite};
use crate::*;
use http1::HTTP1Stream;
use http2::HTTP2Stream;
#[cfg(feature = "quic")]
use stream::connect::QUICStreamConnect;
pub use proxy::Proxy;
pub use proxy::ProxyStream;
#[cfg(feature = "quic")]
pub use quic::QUICStream;
use std::collections::HashMap;
use std::io;
pub use tls_stream::*;
pub use ws::*;
pub use message::{StreamMessage, SendParam};
#[cfg(feature = "quic")]
use crate::fingerprint::H3Finger;
#[cfg(feature = "quic")]
use crate::stream::http3::HTTP3Stream;
#[cfg(feature = "quic")]
use crate::stream::quic::QUICConnect;

pub struct ConnParam<'a> {
    pub url: &'a Url,
    pub proxy: &'a Proxy,
    pub timeout: &'a Timeout,
    pub ech: bool,
}

pub enum HTTPStream {
    NonConnection,
    SyncH1(HTTP1Stream),
    SyncH2(HTTP2Stream),
    #[cfg(feature = "quic")]
    SyncH3(HTTP3Stream<std::net::UdpSocket>),
    #[cfg(feature = "aync")]
    AsyncH1(HTTP1Stream),
    #[cfg(feature = "aync")]
    AsyncH2(HTTP2Stream),
    #[cfg(all(feature = "aync", feature = "quic"))]
    AsyncH3(HTTP3Stream<tokio::net::UdpSocket>),
}

impl HTTPStream {
    pub(crate) fn scheme(&self) -> Option<Scheme> {
        match self {
            HTTPStream::NonConnection => None,
            HTTPStream::SyncH1(h1) => h1.stream().scheme(),
            HTTPStream::SyncH2(h2) => h2.stream().scheme(),
            #[cfg(feature = "quic")]
            HTTPStream::SyncH3(_) => Some(Scheme::Https),
            #[cfg(feature = "aync")]
            HTTPStream::AsyncH1(h1) => h1.stream().scheme(),
            #[cfg(feature = "aync")]
            HTTPStream::AsyncH2(h2) => h2.stream().scheme(),
            #[cfg(all(feature = "aync", feature = "quic"))]
            HTTPStream::AsyncH3(_) => Some(Scheme::Https),
        }
    }

    pub fn into_stream(self) -> HlsResult<Stream> {
        match self {
            HTTPStream::NonConnection => Err("connect first".into()),
            HTTPStream::SyncH1(h1) => Ok(h1.into_stream()),
            HTTPStream::SyncH2(h2) => Ok(h2.into_stream()),
            #[cfg(feature = "quic")]
            HTTPStream::SyncH3(_) => Err("use `QUICStreamS`".into()),
            #[cfg(feature = "aync")]
            HTTPStream::AsyncH1(h1) => Ok(h1.into_stream()),
            #[cfg(feature = "aync")]
            HTTPStream::AsyncH2(h2) => Ok(h2.into_stream()),
            #[cfg(all(feature = "aync", feature = "quic"))]
            HTTPStream::AsyncH3(_) => Err("use `HTTPStreamA`".into()),
        }
    }

    pub fn stream_mut(&mut self) -> io::Result<&mut Stream> {
        match self {
            HTTPStream::NonConnection => Err(io::ErrorKind::NotConnected.into()),
            HTTPStream::SyncH1(h1) => Ok(h1.stream_mut()),
            HTTPStream::SyncH2(h2) => Ok(h2.stream_mut()),
            #[cfg(feature = "quic")]
            HTTPStream::SyncH3(_) => Err(io::Error::other("use `QUICStreamS`")),
            #[cfg(feature = "aync")]
            HTTPStream::AsyncH1(h1) => Ok(h1.stream_mut()),
            #[cfg(feature = "aync")]
            HTTPStream::AsyncH2(h2) => Ok(h2.stream_mut()),
            #[cfg(all(feature = "aync", feature = "quic"))]
            HTTPStream::AsyncH3(_) => Err(io::Error::other("use `HTTPStreamA`")),
        }
    }

    pub fn tls_session(&self) -> Option<&TlsSession> {
        match self {
            HTTPStream::NonConnection => None,
            HTTPStream::SyncH1(h1) => h1.stream().tls_session(),
            HTTPStream::SyncH2(h2) => h2.stream().tls_session(),
            #[cfg(feature = "quic")]
            HTTPStream::SyncH3(_) => None,
            #[cfg(feature = "aync")]
            HTTPStream::AsyncH1(h1) => h1.stream().tls_session(),
            #[cfg(feature = "aync")]
            HTTPStream::AsyncH2(h2) => h2.stream().tls_session(),
            #[cfg(all(feature = "aync", feature = "quic"))]
            HTTPStream::AsyncH3(_) => None,
        }
    }
}


impl HTTPStream {
    pub(crate) fn send_sync(&mut self, param: SendParam) -> HlsResult<u64> {
        match self {
            HTTPStream::NonConnection => Err("need connected before send".into()),
            HTTPStream::SyncH1(h1) => Ok(h1.send_sync(param)?),
            HTTPStream::SyncH2(h2) => h2.send_sync(param),
            #[cfg(feature = "quic")]
            HTTPStream::SyncH3(h3) => h3.send(param),
            #[cfg(feature = "aync")]
            _ => Err("invalid sync stream".into()),
        }
    }

    pub(crate) fn recv_sync(&mut self, responses: &mut HashMap<u64, StreamMessage>) -> HlsResult<Vec<u64>> {
        match self {
            HTTPStream::NonConnection => Err("need connected before recv".into()),
            HTTPStream::SyncH1(h1) => h1.recv_sync(responses),
            HTTPStream::SyncH2(h2) => h2.recv_sync(responses),
            #[cfg(feature = "quic")]
            HTTPStream::SyncH3(h3) => h3.recv(responses),
            #[cfg(feature = "aync")]
            _ => Err("invalid sync stream".into()),
        }
    }

    pub(crate) fn conn_sync(&mut self, config: ClientConfig, param: ConnParam, finger: &Fingerprint) -> HlsResult<ALPN> {
        match config.alpn {
            #[cfg(feature = "quic")]
            h3 if h3 == ALPN::HTTP30 => {
                let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
                let addr = param.url.addr().socket_addr(false)?;
                let stream = QUICStream::connect(socket, addr, config, param.timeout.clone());
                *self = Stream::connect_quic(finger.h3(), stream).wait()?;
                Ok(ALPN::HTTP30)
            }
            _ => {
                let _ = self.stream_mut().and_then(|stream| stream.shutdown().wait());
                let addr = param.proxy.socket_addr(param.url.addr(), false)?;
                let stream = std::net::TcpStream::connect_timeout(&addr, param.timeout.connect())?;
                stream.set_read_timeout(Some(param.timeout.read()))?;
                stream.set_write_timeout(Some(param.timeout.write()))?;
                let (alpn, stream) = Stream::connect(config, param, finger, stream).wait()?;
                *self = stream;
                Ok(alpn)
            }
        }
    }
}

#[cfg(feature = "aync")]
impl HTTPStream {
    pub(crate) async fn send_async(&mut self, param: SendParam<'_>) -> HlsResult<u64> {
        match self {
            HTTPStream::NonConnection => Err("need connected before send".into()),
            HTTPStream::AsyncH1(h1) => Ok(h1.send_async(param).await?),
            HTTPStream::AsyncH2(h2) => h2.send_async(param).await,
            #[cfg(feature = "quic")]
            HTTPStream::AsyncH3(h3) => h3.send(param).await,
            _ => Err("invalid async stream".into()),
        }
    }

    pub(crate) async fn recv_async(&mut self, responses: &mut HashMap<u64, StreamMessage>) -> HlsResult<Vec<u64>> {
        match self {
            HTTPStream::NonConnection => Err("need connected before send".into()),
            HTTPStream::AsyncH1(h1) => h1.recv_async(responses).await,
            HTTPStream::AsyncH2(h2) => h2.recv_async(responses).await,
            #[cfg(feature = "quic")]
            HTTPStream::AsyncH3(h3) => h3.recv(responses).await,
            _ => Err("invalid async stream".into()),
        }
    }

    pub(crate) async fn conn_async(&mut self, config: ClientConfig<'_>, param: ConnParam<'_>, finger: &Fingerprint) -> HlsResult<ALPN> {
        match config.alpn {
            #[cfg(feature = "quic")]
            h3 if h3 == ALPN::HTTP30 => {
                let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
                let addr = param.url.addr().socket_addr(false)?;
                let stream = QUICStream::connect(socket, addr, config, param.timeout.clone());
                *self = Stream::connect_quic(finger.h3(), stream).await?;
                Ok(ALPN::HTTP30)
            }
            _ => {
                if let Ok(stream) = self.stream_mut() { let _ = stream.shutdown().await; }
                let addr = param.proxy.socket_addr(param.url.addr(), false)?;
                let connect = tokio::net::TcpStream::connect(addr);
                let stream = tokio::time::timeout(param.timeout.connect(), connect).await
                    .or(Err(TimeError::ConnectTimeout))??;
                let (alpn, stream) = Stream::connect(config, param, finger, stream).await?;
                *self = stream;
                Ok(alpn)
            }
        }
    }
}


pub enum Stream {
    NonConnection,
    // Synchronous
    SyncHttp(ProxyStream<std::net::TcpStream>),
    SyncHttps(TlsStream<ProxyStream<std::net::TcpStream>>),
    // Asynchronous
    #[cfg(feature = "aync")]
    AsyncHttp(ProxyStream<tokio::net::TcpStream>),
    #[cfg(feature = "aync")]
    AsyncHttps(TlsStream<ProxyStream<tokio::net::TcpStream>>),
}

impl Stream {
    pub fn scheme(&self) -> Option<Scheme> {
        match self {
            Stream::NonConnection => None,
            Stream::SyncHttp(_) => Some(Scheme::Http),
            Stream::SyncHttps(_) => Some(Scheme::Https),
            #[cfg(feature = "aync")]
            Stream::AsyncHttp(_) => Some(Scheme::Http),
            #[cfg(feature = "aync")]
            Stream::AsyncHttps(_) => Some(Scheme::Https),
        }
    }

    pub fn tls_session(&self) -> Option<&TlsSession> {
        match self {
            Stream::SyncHttps(s) => Some(s.connection().session()),
            #[cfg(feature = "aync")]
            Stream::AsyncHttps(s) => Some(s.connection().session()),
            _ => None
        }
    }

    #[cfg(feature = "aync")]
    pub fn timeout(&self) -> &Timeout {
        match self {
            Stream::NonConnection => unreachable!(),
            Stream::SyncHttp(stream) => &stream.timeout,
            Stream::SyncHttps(stream) => &stream.timeout,
            Stream::AsyncHttp(stream) => &stream.timeout,
            Stream::AsyncHttps(stream) => &stream.timeout,
        }
    }

    pub fn read<'a>(&'a mut self, buffer: &'a mut Writer) -> StreamRead<'a> {
        StreamRead {
            stream: self,
            buf: buffer,
        }
    }

    pub fn write<'a>(&'a mut self, buf: &'a mut Writer) -> StreamWrite<'a> {
        StreamWrite {
            stream: self,
            buf,
        }
    }

    pub fn shutdown(&mut self) -> StreamShutdown<'_> {
        StreamShutdown {
            stream: self
        }
    }

    pub fn connect<'a, S>(config: ClientConfig<'a>, param: ConnParam<'a>, finger: &'a Fingerprint, stream: S) -> HTTPStreamConnect<'a, S> {
        HTTPStreamConnect {
            proxy_connecting: ProxyStream::connect(stream, param.url.addr(), param.proxy, param.timeout.clone()),
            param,
            fingerprint: finger,
            tls_connecting: TlsConnecting {
                sent_client_hello: false,
                sent_server_hello: false,
                config: Config::Client(config),
                state: ConnState::Connected,
                app_buf: Writer::with_capacity(32876),
                #[cfg(feature = "aync")]
                timeout_reset: false,
            },
            #[cfg(feature = "aync")]
            proxy_connected: false,
            #[cfg(feature = "aync")]
            stream: Stream::NonConnection,
            #[cfg(feature = "aync")]
            tls_connected: false,
        }
    }

    #[cfg(feature = "quic")]
    pub fn connect_quic<'a, S>(h3_finger: &'a H3Finger, stream: QUICConnect<'a, S>) -> QUICStreamConnect<'a, S> {
        QUICStreamConnect {
            h3_finger,
            conn: Some(stream),
            #[cfg(feature = "aync")]
            stream: None,
            #[cfg(feature = "aync")]
            buffer: None,
            #[cfg(feature = "aync")]
            offset: 0,
            #[cfg(feature = "aync")]
            connected: false,
        }
    }
}

impl io::Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let stream: &mut dyn io::Read = match self {
            Stream::NonConnection => return Err(io::Error::from(io::ErrorKind::NotConnected)),
            Stream::SyncHttp(stream) => stream,
            Stream::SyncHttps(stream) => stream,
            #[cfg(feature = "aync")]
            _ => unreachable!(),
        };
        stream.read(buf)
    }
}

#[cfg(feature = "aync")]
impl tokio::io::AsyncRead for Stream {
    fn poll_read(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<io::Result<()>> {
        let stream: &mut (dyn tokio::io::AsyncRead + Unpin) = match self.get_mut() {
            Stream::NonConnection => return std::task::Poll::Ready(Err(io::Error::from(io::ErrorKind::NotConnected))),
            Stream::AsyncHttp(stream) => stream,
            Stream::AsyncHttps(stream) => stream,
            #[cfg(feature = "aync")]
            _ => unreachable!(),
        };
        tokio::io::AsyncRead::poll_read(std::pin::Pin::new(stream), cx, buf)
    }
}
