#[cfg(use_cls)]
use reqtls::Fingerprint;
use super::url::Url;
use crate::alpn::ALPN;
use crate::error::HlsResult;

use crate::stream::kind::StreamKind;
use crate::timeout::Timeout;

pub use proxy::Proxy;

#[cfg(feature = "cls_async")]
mod async_stream;

#[cfg(cls_sync)]
mod sync_stream;

#[cfg(aync)]
mod astream;
mod proxy;
#[cfg(feature = "std_sync")]
mod cstream;
mod kind;

pub struct ConnParam<'a> {
    pub url: &'a Url,
    pub proxy: &'a Proxy,
    pub timeout: &'a Timeout,
    #[cfg(any(feature = "cls_sync", feature = "cls_async"))]
    pub fingerprint: &'a mut Fingerprint,
    pub alpn: &'a ALPN,
}


pub struct Stream {
    alpn: ALPN,
    kind: StreamKind,
}

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
    pub async fn async_read(&mut self) -> HlsResult<Vec<u8>> {
        self.kind.async_read().await
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
    pub fn sync_read(&mut self) -> HlsResult<Vec<u8>> {
        self.kind.sync_read()
    }

    pub fn sync_write(&mut self, data: &[u8]) -> HlsResult<()> {
        self.kind.sync_write(data)
    }

    pub fn sync_shutdown(&mut self) -> HlsResult<()> {
        self.kind.sync_shutdown()
    }
}

