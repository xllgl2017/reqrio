use std::collections::HashMap;
use std::net::SocketAddr;
use std::ops::Range;
#[cfg(feature = "aync")]
use std::pin::Pin;
#[cfg(feature = "aync")]
use std::task::{Context, Poll};
use reqtls::quic::{QUICConnection, QUICFrame};
use crate::error::HlsResult;
use crate::*;

#[must_use = "do nothing unless `.wait()/.await`"]
pub struct QUICPacketWrite<'a, S> {
    pub(crate) packet: QUICPacket<'a>,
    pub(crate) frames: Vec<QUICFrame<'a>>,
    pub(crate) uw_buffer: &'a mut Writer,
    pub(crate) conn: &'a mut QUICConnection,
    pub(crate) socket: &'a mut S,
    pub(crate) chunk_size: usize,
    pub(crate) seq: &'a mut u64,
    pub(crate) sent_num: &'a mut HashMap<u64, Range<usize>>,
    pub(crate) addr: &'a SocketAddr,
    #[cfg(feature = "aync")]
    pub(crate) timeout: &'a mut Timeout,

}

impl<'a> QUICPacketWrite<'a, std::net::UdpSocket> {
    pub fn wait(mut self) -> HlsResult<usize> {
        if self.frames.is_empty() { return Ok(0); }
        if self.uw_buffer.is_empty() { self.build_message()?; }
        while !self.uw_buffer.is_empty() {
            let len = self.socket.send_to(self.uw_buffer.filled(), *self.addr)?;
            self.uw_buffer.used_empty(len);
        }
        self.uw_buffer.reset();
        Ok(self.chunk_size)
    }
}

impl<'a, S> QUICPacketWrite<'a, S> {
    fn build_message(&mut self) -> Result<(), RlsError> {
        self.conn.build_message(&mut self.packet, &mut self.frames, self.uw_buffer)?;
        self.sent_num.insert(*self.seq, 0..0);
        *self.seq += 1;
        Ok(())
    }
}

#[cfg(feature = "aync")]
impl<'a> Future for QUICPacketWrite<'a, tokio::net::UdpSocket> {
    type Output = HlsResult<usize>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.frames.is_empty() { return Poll::Ready(Ok(0)); }
        let writer = self.get_mut();
        if writer.uw_buffer.is_empty() { writer.build_message()?; }
        while !writer.uw_buffer.is_empty() {
            match Pin::new(&mut writer.socket).poll_send_to(cx, writer.uw_buffer.filled(), *writer.addr)? {
                Poll::Ready(len) => {
                    writer.uw_buffer.used_empty(len);
                    writer.timeout.reset_write();
                }
                Poll::Pending => {
                    writer.timeout.write_timeout()?;
                    return Poll::Pending;
                }
            };
        }
        writer.uw_buffer.reset();
        Poll::Ready(Ok(writer.chunk_size))
    }
}