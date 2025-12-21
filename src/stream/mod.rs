pub use proxy::Proxy;
use super::url::{Protocol, Url};
use crate::error::HlsResult;
#[cfg(cls_async)]
use crate::stream::astream::AsyncTlsStream;
#[cfg(all(feature = "std_sync", not(feature = "cls")))]
use crate::stream::cstream::StdSyncTlsStream;
use crate::timeout::Timeout;
#[cfg(all(feature = "std_async", not(feature = "cls")))]
use astream::StdAsyncTlsStream;
#[cfg(aync)]
use astream::AsyncTcpStream;
#[cfg(sync)]
use std::io::{Read, Write};
#[cfg(sync)]
use std::net::Shutdown;
use crate::alpn::ALPN;
#[cfg(cls_sync)]
use crate::tls::SyncStream;
#[cfg(use_cls)]
use super::tls::Fingerprint;

#[cfg(aync)]
mod astream;
mod proxy;
#[cfg(feature = "std_sync")]
mod cstream;

pub struct ConnParam<'a> {
    pub url: &'a Url,
    pub proxy: &'a Proxy,
    pub timeout: &'a Timeout,
    #[cfg(any(feature = "cls_sync", feature = "cls_async"))]
    pub fingerprint: &'a mut Fingerprint,
    pub alpn: &'a ALPN,
}

pub enum Stream {
    NonConnection,
    //同步
    #[cfg(any(feature = "std_sync", feature = "cls_sync"))]
    SyncHttp(std::net::TcpStream),
    #[cfg(all(feature = "cls_sync", not(feature = "std_sync"), not(feature = "std_async")))]
    SyncHttps(SyncStream<std::net::TcpStream>),
    #[cfg(all(feature = "std_sync", not(feature = "cls")))]
    StdSyncHttps(StdSyncTlsStream),
    //异步

    #[cfg(any(feature = "std_async", feature = "cls_async"))]
    AsyncHttp(AsyncTcpStream),
    #[cfg(all(feature = "std_async", not(feature = "cls")))]
    StdAsyncHttps(StdAsyncTlsStream),
    #[cfg(cls_async)]
    AsyncHttps(AsyncTlsStream),
}

#[cfg(aync)]
impl Stream {
    pub async fn async_conn(&mut self, param: ConnParam<'_>) -> HlsResult<ALPN> {
        let _ = self.async_shutdown().await;
        let stream = param.proxy.create_async_stream(param.url.addr(), param.timeout).await?;
        match param.url.protocol() {
            Protocol::Http => {
                *self = Stream::AsyncHttp(stream);
                Ok(ALPN::Http11)
            }
            #[cfg(feature = "std_async")]
            Protocol::Https => {
                let tls_stream = StdAsyncTlsStream::connect_timeout(param, stream).await?;
                let alpn = tls_stream.alpn().unwrap_or(ALPN::Http11);
                *self = Stream::StdAsyncHttps(tls_stream);
                Ok(alpn)
            }
            #[cfg(feature = "cls_async")]
            Protocol::Https => {
                let tls_stream = AsyncTlsStream::connect_timeout(param, stream).await?;
                let alpn = tls_stream.alpn().map(|x| ALPN::from_slice(x.as_bytes())).unwrap_or(ALPN::Http11);
                *self = Stream::AsyncHttps(tls_stream);
                Ok(alpn)
            }
            _ => Err("stream not supported".into())
        }
    }


    pub async fn async_write(&mut self, buf: &[u8]) -> HlsResult<()> {
        match self {
            Stream::AsyncHttp(s) => {
                s.write(buf).await?;
                s.flush().await?;
                Ok(())
            }
           #[cfg(cls_async)]
            Stream::AsyncHttps(s) => {
                s.write(buf).await?;
                s.flush().await?;
                Ok(())
            }
            #[cfg(all(feature = "std_async", not(feature = "cls")))]
            Stream::StdAsyncHttps(s) => {
                s.write(buf).await?;
                s.flush().await?;
                Ok(())
            }
            _ => Err("Unsupported async write".into()),
        }
    }

    pub async fn async_read(&mut self) -> HlsResult<Vec<u8>> {
        match self {
            Stream::AsyncHttp(s) => {
                let mut buffer = [0; 16 * 1024];
                let len = s.read(&mut buffer).await?;
                if len == 0 { return Err("Connection Closed".into()); }
                Ok(buffer[..len].to_vec())
            }
            #[cfg(cls_async)]
            Stream::AsyncHttps(s) => Ok(s.read().await?),
            #[cfg(all(feature = "std_async", not(feature = "cls")))]
            Stream::StdAsyncHttps(s) => {
                let mut buffer = [0; 16 * 1024];
                let len = s.read(&mut buffer).await?;
                if len == 0 { return Err("Connection Closed".into()); }
                Ok(buffer[..len].to_vec())
            }
            _ => Err("Unsupported async read".into()),
        }
    }

    pub async fn async_shutdown(&mut self) -> HlsResult<()> {
        match self {
            Stream::AsyncHttp(s) => Ok(s.shutdown().await?),
            #[cfg(cls_async)]
            Stream::AsyncHttps(s) => Ok(s.shutdown().await?),
            #[cfg(all(feature = "std_async", not(feature = "cls")))]
            Stream::StdAsyncHttps(s) => Ok(s.shutdown().await?),
            _ => Err("Unsupported async read".into()),
        }
    }
}

#[cfg(any(feature = "std_sync", feature = "cls_sync"))]
impl Stream {
    pub fn sync_conn(&mut self, param: ConnParam) -> HlsResult<ALPN> {
        let _ = self.sync_shutdown();
        let stream = param.proxy.create_sync_stream(param.url.addr(), param.timeout)?;
        match param.url.protocol() {
            Protocol::Http => {
                *self = Stream::SyncHttp(stream);
                Ok(ALPN::Http11)
            }
            #[cfg(feature = "std_sync")]
            Protocol::Https => {
                let tls_stream = StdSyncTlsStream::connect(param, stream)?;
                let alpn = tls_stream.alpn().unwrap_or(ALPN::Http11);
                *self = Stream::StdSyncHttps(tls_stream);
                Ok(alpn)
            }
            #[cfg(feature = "cls_sync")]
            Protocol::Https => {
                let tls_stream = SyncStream::connect(param, stream)?;
                let alpn = tls_stream.alpn().map(|x| ALPN::from_slice(x.as_bytes())).unwrap_or(ALPN::Http11);
                *self = Stream::SyncHttps(tls_stream);
                Ok(alpn)
            }
            _ => Err("stream not supported".into())
        }
    }

    pub fn sync_write(&mut self, buf: &[u8]) -> HlsResult<()> {
        match self {
            Stream::SyncHttp(s) => {
                s.write(buf)?;
                s.flush()?;
                Ok(())
            }
            #[cfg(all(feature = "cls_sync", not(feature = "std")))]
            Stream::SyncHttps(s) => {
                s.write_tls(buf)?;
                s.flush()?;
                Ok(())
            }
            #[cfg(all(feature = "std_sync", not(feature = "cls")))]
            Stream::StdSyncHttps(s) => {
                s.write(buf)?;
                s.flush()?;
                Ok(())
            }
            _ => Err("Unsupported sync write".into()),
        }
    }

    pub fn sync_read(&mut self) -> HlsResult<Vec<u8>> {
        match self {
            Stream::SyncHttp(s) => {
                let mut buffer = [0; 4096];
                let len = s.read(&mut buffer)?;
                if len == 0 { return Err("Connection Closed".into()); }
                Ok(buffer[..len].to_vec())
            }
            #[cfg(all(feature = "cls_sync", not(feature = "std")))]
            Stream::SyncHttps(s) => Ok(s.read_tls()?),
            #[cfg(all(feature = "std_sync", not(feature = "cls")))]
            Stream::StdSyncHttps(s) => {
                let mut buffer = [0; 16 * 1024];
                let len = s.read(&mut buffer)?;
                if len == 0 { return Err("Connection Closed".into()); }
                Ok(buffer[..len].to_vec())
            }
            _ => Err("Unsupported async read".into()),
        }
    }

    pub fn sync_shutdown(&mut self) -> HlsResult<()> {
        match self {
            Stream::SyncHttp(s) => Ok(s.shutdown(Shutdown::Both)?),
            #[cfg(feature = "cls_sync")]
            Stream::SyncHttps(s) => Ok(s.shutdown()?),
            #[cfg(all(feature = "std_sync", not(feature = "cls")))]
            Stream::StdSyncHttps(s) => Ok(s.shutdown()?),
            _ => Err("Unsupported async read".into()),
        }
    }
}