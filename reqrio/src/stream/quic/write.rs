use std::collections::HashMap;
use std::mem;
use std::net::SocketAddr;
use std::ops::Range;
#[cfg(feature = "aync")]
use std::pin::Pin;
#[cfg(feature = "aync")]
use std::task::{Context, Poll};
use reqtls::quic::{QUICConnection, QUICFrame};
use crate::error::HlsResult;
use crate::*;
use super::QUICStream;

#[must_use = "do nothing unless `.wait()/.await`"]
pub struct QUICPacketWrite<'a, S> {
    pub(crate) packet: QUICPacket<'a>,
    pub(crate) frames: Vec<QUICFrame<'a>>,
    pub(crate) uw_buffer: &'a mut Writer,
    pub(crate) conn: &'a mut QUICConnection,
    pub(crate) socket: &'a mut S,
    pub(crate) chunk_size: usize,
    pub(crate) sent_num: &'a mut HashMap<u64, Range<usize>>,
    pub(crate) addr: &'a SocketAddr,
    #[cfg(feature = "aync")]
    pub(crate) timeout: &'a mut Timeout,
    #[cfg(feature = "aync")]
    pub(crate) timeout_reset: bool,
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
        self.sent_num.insert(self.conn.seq(), 0..0);
        self.conn.set_seq(self.conn.seq() + 1);
        Ok(())
    }
}

#[cfg(feature = "aync")]
impl<'a> Future for QUICPacketWrite<'a, tokio::net::UdpSocket> {
    type Output = HlsResult<usize>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.frames.is_empty() { return Poll::Ready(Ok(0)); }
        let writer = self.get_mut();
        if !writer.timeout_reset {
            writer.timeout.reset_write();
            writer.timeout_reset = true;
        }
        if writer.uw_buffer.is_empty() { writer.build_message()?; }
        while !writer.uw_buffer.is_empty() {
            match Pin::new(&mut writer.socket).poll_send_to(cx, writer.uw_buffer.filled(), *writer.addr)? {
                Poll::Ready(len) => {
                    writer.uw_buffer.used_empty(len);
                    writer.timeout.reset_write();
                }
                Poll::Pending => {
                    writer.timeout.write_timeout(cx)?;
                    return Poll::Pending;
                }
            };
        }
        writer.uw_buffer.reset();
        Poll::Ready(Ok(writer.chunk_size))
    }
}


pub struct QUICPacketWrite2<'a, S> {
    pub(crate) buffer: Buffer,
    pub(crate) flag: QUICFlag,
    pub(crate) stream: &'a mut QUICStream<S>,
    pub(crate) bid: u64,
    #[cfg(feature = "aync")]
    pub(crate) encrypted: bool,
}

impl<'a> QUICPacketWrite2<'a, std::net::UdpSocket> {
    pub fn wait(mut self) -> HlsResult<()> {
        self.stream.conn.make_message2(&mut self.buffer, self.stream.dcid.as_slice(), self.flag)?;
        self.stream.send(&mut self.buffer)?;
        let mut buffer = mem::replace(&mut self.buffer, Buffer::none());
        buffer.reset();
        self.stream.idle_buffer.push((self.bid, buffer));
        Ok(())
    }
}

#[cfg(feature = "aync")]
impl<'a> Future for QUICPacketWrite2<'a, tokio::net::UdpSocket> {
    type Output = HlsResult<()>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let writing = self.get_mut();
        if !writing.encrypted {
            writing.stream.conn.make_message2(&mut writing.buffer, writing.stream.dcid.as_slice(), writing.flag)?;
            writing.encrypted = true;
        }
        while !writing.buffer.is_empty() {
            if writing.stream.poll_send(cx, &mut writing.buffer).is_pending() { return Poll::Pending; }
        }
        let mut buffer = mem::replace(&mut writing.buffer, Buffer::none());
        buffer.reset();
        writing.stream.idle_buffer.push((writing.bid, buffer));
        Poll::Ready(Ok(()))
    }
}
