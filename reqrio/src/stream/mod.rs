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

use crate::packet::HeaderParam;
use crate::stream::connect::{ConnState, StreamConnect, TlsConnecting};
#[cfg(all(feature = "quic", feature = "aync"))]
use crate::stream::http3::HTTP3StreamA;
use crate::stream::read::StreamRead;
use crate::stream::write::{StreamShutdown, StreamWrite};
use crate::*;
#[cfg(feature = "aync")]
use http1::HTTP1StreamA;
use http1::HTTP1StreamS;
#[cfg(feature = "aync")]
use http2::HTTP2StreamA;
use http2::HTTP2StreamS;
#[cfg(feature = "quic")]
pub use http3::HTTP3StreamS;
pub use proxy::Proxy;
pub use proxy::ProxyStream;
#[cfg(feature = "quic")]
pub use quic::QUICStream;
use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};
pub use tls_stream::*;
pub use ws::*;

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
    pub key_log: &'a Option<PathBuf>,
    pub ech: bool,
    pub session: &'a Option<TlsSession>,
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
            key_log: param.key_log.clone().or_else(|| match env::var("SSLKEYLOGFILE") {
                Ok(key_log) => Some(Path::new(&key_log).to_path_buf()),
                Err(_) => None
            }),
            session: param.session,
        }
    }
}


pub enum HTTPStream {
    NonConnection,
    SyncH1(HTTP1StreamS),
    SyncH2(HTTP2StreamS),
    #[cfg(feature = "quic")]
    SyncH3(HTTP3StreamS),
    #[cfg(feature = "aync")]
    AsyncH1(HTTP1StreamA),
    #[cfg(feature = "aync")]
    AsyncH2(HTTP2StreamA),
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
}


impl HTTPStream {
    pub(crate) fn send_sync(&mut self, header: &Header, body: &Body<'_>, param: HeaderParam) -> HlsResult<u64> {
        match self {
            HTTPStream::NonConnection => Err("need connected before send".into()),
            HTTPStream::SyncH1(h1) => h1.send(header, body, param),
            HTTPStream::SyncH2(h2) => h2.send(header, body, param),
            #[cfg(feature = "quic")]
            HTTPStream::SyncH3(h3) => h3.send(header, body, param),
            #[cfg(feature = "aync")]
            _ => Err("invalid sync stream".into()),
        }
    }

    pub(crate) fn recv_sync(&mut self, responses: &mut HashMap<u64, Response>) -> HlsResult<Vec<u64>> {
        match self {
            HTTPStream::NonConnection => Err("need connected before recv".into()),
            HTTPStream::SyncH1(h1) => h1.recv(responses),
            HTTPStream::SyncH2(h2) => h2.recv(responses),
            #[cfg(feature = "quic")]
            HTTPStream::SyncH3(h3) => h3.recv(responses),
            #[cfg(feature = "aync")]
            _ => Err("invalid sync stream".into()),
        }
    }

    pub(crate) fn conn_sync<'a, 'b: 'a>(&'a mut self, param: ConnParam<'b>) -> HlsResult<ALPN> {
        match param.alpn {
            #[cfg(feature = "quic")]
            ALPN::Http30 => {
                let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
                *self = HTTPStream::SyncH3(HTTP3StreamS::connect(socket, param)?);
                Ok(ALPN::Http30)
            }
            _ => {
                let _ = self.stream_mut().and_then(|stream| stream.shutdown().wait());
                let addr = param.proxy.socket_addr(param.url.addr(), false)?;
                let stream = std::net::TcpStream::connect_timeout(&addr, param.timeout.connect())?;
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
            HTTPStream::AsyncH1(h1) => h1.send(header, body, param).await,
            HTTPStream::AsyncH2(h2) => h2.send(header, body, param).await,
            #[cfg(feature = "quic")]
            HTTPStream::AsyncH3(h3) => h3.send(header, body, param).await,
            _ => Err("invalid async stream".into()),
        }
    }

    pub(crate) async fn recv_async(&mut self, responses: &mut HashMap<u64, Response>) -> HlsResult<Vec<u64>> {
        match self {
            HTTPStream::NonConnection => Err("need connected before send".into()),
            HTTPStream::AsyncH1(h1) => h1.recv(responses).await,
            HTTPStream::AsyncH2(h2) => h2.recv(responses).await,
            #[cfg(feature = "quic")]
            HTTPStream::AsyncH3(h3) => h3.recv(responses).await,
            _ => Err("invalid async stream".into()),
        }
    }

    pub(crate) async fn conn_async<'a, 'b: 'a>(&'a mut self, param: ConnParam<'b>) -> HlsResult<ALPN> {
        match param.alpn {
            #[cfg(feature = "quic")]
            ALPN::Http30 => {
                let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
                *self = HTTPStream::AsyncH3(HTTP3StreamA::connect(socket, param).await?);
                Ok(ALPN::Http30)
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
                }),
                state: ConnState::Connected,
                app_buf: Writer::with_capacity(16384),
            },
            #[cfg(feature = "aync")]
            proxy_connected: false,
            #[cfg(feature = "aync")]
            stream: Stream::NonConnection,
            #[cfg(feature = "aync")]
            buffer: Writer::none(),
            #[cfg(feature = "aync")]
            tls_connected: false,
        }
    }
}

