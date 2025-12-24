#[cfg(sync)]
use std::io::{Read, Write};
#[cfg(sync)]
use std::net::Shutdown;
use crate::ALPN;
use crate::error::HlsResult;
#[cfg(feature = "cls_async")]
use crate::stream::astream::AsyncTlsStream;
#[cfg(aync)]
use crate::stream::astream::AsyncTcpStream;
use crate::stream::ConnParam;
#[cfg(feature = "cls_sync")]
use super::sync_stream::SyncStream;
use crate::url::Protocol;
#[cfg(std_async)]
use crate::stream::astream::StdAsyncTlsStream;
#[cfg(std_sync)]
use crate::stream::cstream::StdSyncTlsStream;

pub enum StreamKind {
    NonConnection,
    //同步
    #[cfg(any(feature = "std_sync", feature = "cls_sync"))]
    SyncHttp(std::net::TcpStream),
    #[cfg(all(feature = "cls_sync", not(feature = "std_sync"), not(feature = "std_async")))]
    SyncHttps(SyncStream<std::net::TcpStream>),
    #[cfg(std_sync)]
    StdSyncHttps(StdSyncTlsStream),
    //异步

    #[cfg(aync)]
    AsyncHttp(AsyncTcpStream),
    #[cfg(std_async)]
    StdAsyncHttps(StdAsyncTlsStream),
    #[cfg(cls_async)]
    AsyncHttps(AsyncTlsStream),
}

#[cfg(aync)]
impl StreamKind {
    pub async fn async_conn(&mut self, param: ConnParam<'_>) -> HlsResult<ALPN> {
        let _ = self.async_shutdown().await;
        let stream = param.proxy.create_async_stream(param.url.addr(), param.timeout).await?;
        match param.url.protocol() {
            Protocol::Http => {
                *self = StreamKind::AsyncHttp(stream);
                Ok(ALPN::Http11)
            }
            #[cfg(feature = "std_async")]
            Protocol::Https => {
                let tls_stream = StdAsyncTlsStream::connect_timeout(param, stream).await?;
                let alpn = tls_stream.alpn().unwrap_or(ALPN::Http11);
                *self = StreamKind::StdAsyncHttps(tls_stream);
                Ok(alpn)
            }
            #[cfg(cls_async)]
            Protocol::Https => {
                let tls_stream = AsyncTlsStream::connect_timeout(param, stream).await?;
                let alpn = tls_stream.alpn().map(|x| ALPN::from_slice(x.as_bytes())).unwrap_or(ALPN::Http11);
                *self = StreamKind::AsyncHttps(tls_stream);
                Ok(alpn)
            }
            _ => Err("stream not supported".into())
        }
    }


    pub async fn async_write(&mut self, buf: &[u8]) -> HlsResult<()> {
        match self {
            StreamKind::AsyncHttp(s) => {
                s.write(buf).await?;
                s.flush().await?;
                Ok(())
            }
            #[cfg(cls_async)]
            StreamKind::AsyncHttps(s) => {
                s.write(buf).await?;
                s.flush().await?;
                Ok(())
            }
            #[cfg(std_async)]
            StreamKind::StdAsyncHttps(s) => {
                s.write(buf).await?;
                s.flush().await?;
                Ok(())
            }
            _ => Err("Unsupported async write".into()),
        }
    }

    pub async fn async_read(&mut self) -> HlsResult<Vec<u8>> {
        match self {
            StreamKind::AsyncHttp(s) => {
                let mut buffer = [0; 16 * 1024];
                let len = s.read(&mut buffer).await?;
                if len == 0 { return Err("Connection Closed".into()); }
                Ok(buffer[..len].to_vec())
            }
            #[cfg(cls_async)]
            StreamKind::AsyncHttps(s) => Ok(s.read().await?),
            #[cfg(std_async)]
            StreamKind::StdAsyncHttps(s) => {
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
            StreamKind::AsyncHttp(s) => Ok(s.shutdown().await?),
            #[cfg(cls_async)]
            StreamKind::AsyncHttps(s) => Ok(s.shutdown().await?),
            #[cfg(std_sync)]
            StreamKind::StdAsyncHttps(s) => Ok(s.shutdown().await?),
            _ => Err("Unsupported async read".into()),
        }
    }
}

#[cfg(any(feature = "std_sync", feature = "cls_sync"))]
impl StreamKind {
    pub fn sync_conn(&mut self, param: ConnParam) -> HlsResult<ALPN> {
        let _ = self.sync_shutdown();
        let stream = param.proxy.create_sync_stream(param.url.addr(), param.timeout)?;
        match param.url.protocol() {
            Protocol::Http => {
                *self = StreamKind::SyncHttp(stream);
                Ok(ALPN::Http11)
            }
            #[cfg(std_sync)]
            Protocol::Https => {
                let tls_stream = crate::stream::cstream::StdSyncTlsStream::connect(param, stream)?;
                let alpn = tls_stream.alpn().unwrap_or(ALPN::Http11);
                *self = StreamKind::StdSyncHttps(tls_stream);
                Ok(alpn)
            }
            #[cfg(cls_sync)]
            Protocol::Https => {
                let tls_stream = SyncStream::connect(param, stream)?;
                let alpn = tls_stream.alpn().map(|x| ALPN::from_slice(x.as_bytes())).unwrap_or(ALPN::Http11);
                *self = StreamKind::SyncHttps(tls_stream);
                Ok(alpn)
            }
            _ => Err("stream not supported".into())
        }
    }

    pub fn sync_write(&mut self, buf: &[u8]) -> HlsResult<()> {
        match self {
            StreamKind::SyncHttp(s) => {
                s.write(buf)?;
                s.flush()?;
                Ok(())
            }
            #[cfg(cls_sync)]
            StreamKind::SyncHttps(s) => {
                s.write_tls(buf)?;
                s.flush()?;
                Ok(())
            }
            #[cfg(std_sync)]
            StreamKind::StdSyncHttps(s) => {
                s.write(buf)?;
                s.flush()?;
                Ok(())
            }
            _ => Err("Unsupported sync write".into()),
        }
    }

    pub fn sync_read(&mut self) -> HlsResult<Vec<u8>> {
        match self {
            StreamKind::SyncHttp(s) => {
                let mut buffer = [0; 4096];
                let len = s.read(&mut buffer)?;
                if len == 0 { return Err("Connection Closed".into()); }
                Ok(buffer[..len].to_vec())
            }
            #[cfg(cls_sync)]
            StreamKind::SyncHttps(s) => Ok(s.read_tls()?),
            #[cfg(std_sync)]
            StreamKind::StdSyncHttps(s) => {
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
            StreamKind::SyncHttp(s) => Ok(s.shutdown(Shutdown::Both)?),
            #[cfg(cls_sync)]
            StreamKind::SyncHttps(s) => Ok(s.shutdown()?),
            #[cfg(std_sync)]
            StreamKind::StdSyncHttps(s) => Ok(s.shutdown()?),
            _ => Err("Unsupported async read".into()),
        }
    }
}