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

use crate::packet::HeaderParam;
use crate::stream::connect::{ConnState, StreamConnect, TlsConnecting};
#[cfg(all(feature = "quic", feature = "aync"))]
use crate::stream::http3::HTTP3StreamA;
use crate::stream::read::StreamRead;
use crate::stream::write::{StreamShutdown, StreamWrite};
use crate::*;
use http1::HTTP1Stream;
use http2::HTTP2Stream;
#[cfg(feature = "quic")]
pub use http3::HTTP3StreamS;
pub use proxy::Proxy;
pub use proxy::ProxyStream;
#[cfg(feature = "quic")]
pub use quic::QUICStream;
use std::collections::HashMap;
use std::sync::Arc;
pub use tls_stream::*;
pub use ws::*;
pub use message::{StreamMessage, SendParam};

pub struct ConnParam<'a> {
    pub url: &'a Url,
    pub proxy: &'a Proxy,
    pub timeout: &'a Timeout,
    pub fingerprint: &'a mut Fingerprint,
    pub alpn: &'a ALPN,
    pub verify: bool,
    pub cert: &'a mut Vec<Certificate>,
    pub key: &'a RsaKey,
    pub ca_cert: &'a Vec<Certificate>,
    pub key_log: Option<Arc<String>>,
    pub ech: bool,
    pub session: Option<TlsSession>,
    pub version: Version,
}

impl<'a, 'b: 'a> From<&'a mut ConnParam<'b>> for ClientConfig<'a> {
    fn from(param: &'a mut ConnParam<'b>) -> Self {
        ClientConfig {
            sni: param.url.sni(),
            alpn: param.alpn,
            fingerprint: param.fingerprint.tls_mut(),
            client_cert: param.cert,
            cert_key: param.key,
            verify: param.verify,
            ca_certs: param.ca_cert,
            key_log: param.key_log.take(),
            session: param.session.take(),
            version: param.version,
        }
    }
}


pub enum HTTPStream {
    NonConnection,
    SyncH1(HTTP1Stream),
    SyncH2(HTTP2Stream),
    #[cfg(feature = "quic")]
    SyncH3(HTTP3StreamS),
    #[cfg(feature = "aync")]
    AsyncH1(HTTP1Stream),
    #[cfg(feature = "aync")]
    AsyncH2(HTTP2Stream),
    #[cfg(all(feature = "aync", feature = "quic"))]
    AsyncH3(HTTP3StreamA),
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

    pub fn stream_mut(&mut self) -> HlsResult<&mut Stream> {
        match self {
            HTTPStream::NonConnection => Err("connect first".into()),
            HTTPStream::SyncH1(h1) => Ok(h1.stream_mut()),
            HTTPStream::SyncH2(h2) => Ok(h2.stream_mut()),
            #[cfg(feature = "quic")]
            HTTPStream::SyncH3(_) => Err("use `QUICStreamS`".into()),
            #[cfg(feature = "aync")]
            HTTPStream::AsyncH1(h1) => Ok(h1.stream_mut()),
            #[cfg(feature = "aync")]
            HTTPStream::AsyncH2(h2) => Ok(h2.stream_mut()),
            #[cfg(all(feature = "aync", feature = "quic"))]
            HTTPStream::AsyncH3(_) => Err("use `HTTPStreamA`".into()),
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
    pub(crate) fn send_sync(&mut self, header: &Header, body: &Body<'_>, param: HeaderParam) -> HlsResult<u64> {
        match self {
            HTTPStream::NonConnection => Err("need connected before send".into()),
            HTTPStream::SyncH1(h1) => Ok(h1.send_sync(SendParam {
                method: param.method,
                url: param.url,
                header,
                body,
                priority: param.priority,
                weight: param.weight,
            })?),
            HTTPStream::SyncH2(h2) => h2.send_sync(SendParam {
                method: param.method,
                url: param.url,
                header,
                body,
                priority: param.priority,
                weight: param.weight,
            }),
            #[cfg(feature = "quic")]
            HTTPStream::SyncH3(h3) => h3.send(header, body, param),
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

    pub(crate) fn conn_sync<'a, 'b: 'a>(&'a mut self, param: ConnParam<'b>) -> HlsResult<ALPN> {
        match param.alpn {
            #[cfg(feature = "quic")]
            h3 if h3 == ALPN::HTTP30 => {
                let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
                *self = HTTPStream::SyncH3(HTTP3StreamS::connect(socket, param)?);
                Ok(ALPN::HTTP30)
            }
            _ => {
                let _ = self.stream_mut().and_then(|stream| stream.shutdown().wait());
                let addr = param.proxy.socket_addr(param.url.addr(), false)?;
                let stream = std::net::TcpStream::connect_timeout(&addr, param.timeout.connect())?;
                stream.set_read_timeout(Some(param.timeout.read()))?;
                stream.set_write_timeout(Some(param.timeout.write()))?;
                let (alpn, stream) = Stream::connect(param, stream).wait()?;
                *self = stream;
                Ok(alpn)
            }
        }
    }
}

#[cfg(feature = "aync")]
impl HTTPStream {
    pub(crate) async fn send_async(&mut self, header: &Header, body: &Body<'_>, param: HeaderParam<'_>) -> HlsResult<u64> {
        match self {
            HTTPStream::NonConnection => Err("need connected before send".into()),
            HTTPStream::AsyncH1(h1) => Ok(h1.send_async(SendParam {
                method: param.method,
                url: param.url,
                header,
                body,
                priority: param.priority,
                weight: param.weight,
            }).await?),
            HTTPStream::AsyncH2(h2) => h2.send_async(SendParam {
                method: param.method,
                url: param.url,
                header,
                body,
                priority: param.priority,
                weight: param.weight,
            }).await,
            #[cfg(feature = "quic")]
            HTTPStream::AsyncH3(h3) => h3.send(header, body, param).await,
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

    pub(crate) async fn conn_async<'a, 'b: 'a>(&'a mut self, param: ConnParam<'b>) -> HlsResult<ALPN> {
        match param.alpn {
            #[cfg(feature = "quic")]
            h3 if h3 == ALPN::HTTP30 => {
                let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
                *self = HTTPStream::AsyncH3(HTTP3StreamA::connect(socket, param).await?);
                Ok(ALPN::HTTP30)
            }
            _ => {
                if let Ok(stream) = self.stream_mut() { let _ = stream.shutdown().await; }
                let addr = param.proxy.socket_addr(param.url.addr(), false)?;
                let connect = tokio::net::TcpStream::connect(addr);
                let stream = tokio::time::timeout(param.timeout.connect(), connect).await
                    .or(Err(TimeError::ConnectTimeout))??;
                let (alpn, stream) = Stream::connect(param, stream).await?;
                *self = stream;
                Ok(alpn)
            }
        }
    }
}


pub enum Stream {
    NonConnection,
    //同步
    SyncHttp(ProxyStream<std::net::TcpStream>),
    SyncHttps(TlsStream<ProxyStream<std::net::TcpStream>>),
    //异步
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

    pub fn connect<S>(param: ConnParam, stream: S) -> StreamConnect<S> {
        StreamConnect {
            url: param.url,
            fingerprint: param.fingerprint,
            proxy_connecting: ProxyStream::connect(stream, param.url.addr(), param.proxy, param.timeout.clone()),
            tls_connecting: TlsConnecting {
                sent_client_hello: false,
                sent_server_hello: false,
                config: Config::Client(ClientConfig {
                    sni: param.url.sni(),
                    alpn: param.alpn,
                    fingerprint: TlsFinger::DEFAULT,
                    client_cert: param.cert,
                    cert_key: param.key,
                    verify: param.verify,
                    ca_certs: param.ca_cert,
                    key_log: param.key_log.clone(),
                    session: param.session,
                    version: param.version,
                }),
                state: ConnState::Connected,
                app_buf: Writer::with_capacity(24657),
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
}

impl std::io::Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let stream: &mut dyn std::io::Read = match self {
            Stream::NonConnection => return Err(std::io::Error::from(std::io::ErrorKind::NotConnected)),
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
    fn poll_read(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<std::io::Result<()>> {
        let stream: &mut (dyn tokio::io::AsyncRead + Unpin) = match self.get_mut() {
            Stream::NonConnection => return std::task::Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::NotConnected))),
            Stream::AsyncHttp(stream) => stream,
            Stream::AsyncHttps(stream) => stream,
            #[cfg(feature = "aync")]
            _ => unreachable!(),
        };
        tokio::io::AsyncRead::poll_read(std::pin::Pin::new(stream), cx, buf)
    }
}