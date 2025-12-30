#[cfg(use_cls)]
use reqtls::Fingerprint;
#[cfg(anys)]
use super::url::Url;
#[cfg(anys)]
use crate::alpn::ALPN;
#[cfg(anys)]
use crate::error::HlsResult;
#[cfg(anys)]
use crate::stream::kind::StreamKind;
#[cfg(anys)]
use crate::timeout::Timeout;

pub use proxy::Proxy;
#[cfg(anys)]
use crate::Buffer;
#[cfg(feature = "cls_async")]
pub use async_stream::{TlsStream, TlsConnector};

#[cfg(feature = "cls_async")]
mod async_stream;

#[cfg(cls_sync)]
mod sync_stream;

#[cfg(aync)]
mod astream;
mod proxy;
#[cfg(feature = "std_sync")]
mod cstream;
#[cfg(anys)]
mod kind;

#[cfg(anys)]
pub struct ConnParam<'a> {
    pub url: &'a Url,
    pub proxy: &'a Proxy,
    pub timeout: &'a Timeout,
    #[cfg(any(feature = "cls_sync", feature = "cls_async"))]
    pub fingerprint: &'a mut Fingerprint,
    pub alpn: &'a ALPN,
}

#[cfg(anys)]
pub struct Stream {
    alpn: ALPN,
    kind: StreamKind,
}

#[cfg(anys)]
impl Stream {
    pub fn unconnection() -> Self {
        Stream {
            alpn: ALPN::Unknown,
            kind: StreamKind::NonConnection,
        }
    }
    pub fn alpn(&self) -> &ALPN {
        &self.alpn
    }
}

#[cfg(aync)]
impl Stream {
    pub async fn async_connect(&mut self, param: ConnParam<'_>) -> HlsResult<()> {
        let alpn = self.kind.async_conn(param).await?;
        self.alpn = alpn;
        Ok(())
    }
    pub async fn async_read(&mut self, buffer: &mut Buffer) -> HlsResult<()> {
        self.kind.async_read(buffer).await
    }

    pub async fn async_write(&mut self, data: &[u8]) -> HlsResult<()> {
        self.kind.async_write(data).await
    }

    // pub async fn async_shutdown(&mut self) -> HlsResult<()> {
    //     self.kind.async_shutdown().await
    // }
}

#[cfg(sync)]
impl Stream {
    pub fn sync_connect(&mut self, param: ConnParam) -> HlsResult<()> {
        let alpn = self.kind.sync_conn(param)?;
        self.alpn = alpn;
        Ok(())
    }
    pub fn sync_read(&mut self, buffer: &mut Buffer) -> HlsResult<()> {
        self.kind.sync_read(buffer)
    }

    pub fn sync_write(&mut self, data: &[u8]) -> HlsResult<()> {
        self.kind.sync_write(data)
    }

    pub fn sync_shutdown(&mut self) -> HlsResult<()> {
        self.kind.sync_shutdown()
    }
}

