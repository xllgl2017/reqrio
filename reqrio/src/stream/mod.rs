use crate::*;
#[cfg(feature = "aync")]
pub use aync::*;
pub use proxy::Proxy;
pub use proxy::ProxyStream;
use std::{env, io};
use std::io::Write;
use std::path::{Path, PathBuf};
pub use sync_stream::SyncStream;
pub use ws::{WebSocket, WebSocketBuilder};

mod sync_stream;

mod proxy;
mod ws;
#[cfg(feature = "aync")]
mod aync;

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

impl<'a> From<ConnParam<'a>> for ClientConfig<'a> {
    fn from(param: ConnParam<'a>) -> Self {
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

pub enum Stream {
    NonConnection,
    //同步
    SyncHttp(ProxyStream<std::net::TcpStream>),
    SyncHttps(SyncStream<ProxyStream<std::net::TcpStream>>),
    //异步
    #[cfg(feature = "aync")]
    AsyncHttp(TcpStreamA),
    #[cfg(feature = "aync")]
    AsyncHttps(TlsStreamA),
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
            Stream::AsyncHttps(s) => Some(s.get_ref().connection().session()),
            _ => None
        }
    }
}

#[cfg(feature = "aync")]
impl Stream {
    pub async fn async_conn(&mut self, param: ConnParam<'_>) -> HlsResult<ALPN> {
        let _ = self.async_shutdown().await;
        // let st = Time::now_mills();
        let connect = ProxyStream::async_connect(param.proxy, param.url.addr(), param.ech);
        let stream = tokio::time::timeout(param.timeout.connect(), connect).await??;
        // println!("TCP TIME: {}", Time::now_mills() - st);
        match param.url.scheme() {
            Scheme::Http | Scheme::Ws => {
                *self = Stream::AsyncHttp(TcpStreamA::from_proxy_stream(stream, param.timeout));
                Ok(ALPN::Http11)
            }
            Scheme::Https | Scheme::Wss => {
                // let st = Time::now_mills();
                let tls_stream = TlsStreamA::connect_timeout(param, stream).await?;
                // println!("TLS TIME: {}", Time::now_mills() - st);
                let alpn = tls_stream.alpn().cloned().unwrap_or(ALPN::Http11);
                *self = Stream::AsyncHttps(tls_stream);
                Ok(alpn)
            }
            _ => Err("stream not supported".into())
        }
    }


    pub async fn async_write(&mut self, buf: &[u8]) -> HlsResult<()> {
        match self {
            Stream::AsyncHttp(s) => s.write_all(buf).await,
            Stream::AsyncHttps(s) => s.write_all(buf).await,
            _ => Err("Unsupported async write".into()),
        }
    }

    pub async fn async_read(&mut self, buffer: &mut Buffer) -> HlsResult<()> {
        match self {
            Stream::AsyncHttp(s) => s.read(buffer).await,
            Stream::AsyncHttps(s) => Ok(s.read(buffer).await?),
            _ => Err("Unsupported async read".into()),
        }
    }

    pub async fn async_shutdown(&mut self) -> HlsResult<()> {
        match self {
            Stream::AsyncHttp(s) => Ok(s.shutdown().await?),
            Stream::AsyncHttps(s) => Ok(s.shutdown().await?),
            _ => Err("Unsupported async read".into()),
        }
    }
}

impl Stream {
    pub fn sync_conn(&mut self, param: ConnParam) -> HlsResult<ALPN> {
        let _ = self.sync_shutdown();
        let stream = ProxyStream::sync_connect(param.proxy, param.url.addr(), param.timeout, param.ech)?;
        match param.url.scheme() {
            Scheme::Http | Scheme::Ws => {
                *self = Stream::SyncHttp(stream);
                Ok(ALPN::Http11)
            }
            Scheme::Https | Scheme::Wss => {
                let tls_stream = SyncStream::connect(ClientConfig::from(param), stream)?;
                let alpn = tls_stream.alpn().cloned().unwrap_or(ALPN::Http11);
                *self = Stream::SyncHttps(tls_stream);
                Ok(alpn)
            }
            _ => Err("stream not supported".into())
        }
    }

    pub fn sync_write(&mut self, buf: &[u8]) -> HlsResult<()> {
        match self {
            Stream::SyncHttp(s) => {
                s.write_all(buf)?;
                Ok(())
            }
            Stream::SyncHttps(s) => {
                s.write_all(buf)?;
                Ok(())
            }
            _ => Err("Unsupported sync write".into()),
        }
    }

    pub fn sync_read(&mut self, buffer: &mut Buffer) -> HlsResult<()> {
        match self {
            Stream::SyncHttp(stream) => {
                let len = io::Read::read(stream, buffer.unfilled())?;
                if len == 0 { return Err(HlsError::PeerClosedConnection); }
                buffer.add_len(len);
                Ok(())
            }
            Stream::SyncHttps(stream) => {
                let len = io::Read::read(stream, buffer.unfilled())?;
                if len == 0 { return Err(HlsError::PeerClosedConnection); }
                buffer.add_len(len);
                Ok(())
            },
            _ => Err("Unsupported async read".into()),
        }
    }

    pub fn sync_shutdown(&mut self) -> HlsResult<()> {
        match self {
            Stream::SyncHttp(s) => Ok(s.shutdown()?),
            Stream::SyncHttps(s) => Ok(s.shutdown()?),
            _ => Err("Unsupported async read".into()),
        }
    }
}


