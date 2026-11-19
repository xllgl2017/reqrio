use super::QUICStream;
use crate::error::HlsResult;
use crate::*;
#[cfg(feature = "aync")]
use std::pin::Pin;
#[cfg(feature = "aync")]
use std::task::{Context, Poll};

pub struct QUICPacketWrite<'a, S> {
    pub(crate) buffer: Option<Buffer>,
    pub(crate) flag: QUICFlag,
    pub(crate) stream: &'a mut QUICStream<S>,
}

impl<'a> QUICPacketWrite<'a, std::net::UdpSocket> {
    pub fn wait(self) -> HlsResult<()> {
        if let Some(buffer) = self.buffer {
            self.stream.send(buffer, self.flag)?;
        }

        Ok(())
    }
}

#[cfg(feature = "aync")]
impl<'a> Future for QUICPacketWrite<'a, tokio::net::UdpSocket> {
    type Output = HlsResult<()>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let writing = self.get_mut();
        if let Some(buffer) = writing.buffer.take() {
            writing.stream.make_message(buffer, writing.flag)?;
        }
        if writing.stream.poll_send(cx).is_pending() { return Poll::Pending; }
        Poll::Ready(Ok(()))
    }
}
