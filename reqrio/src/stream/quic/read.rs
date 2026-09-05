use crate::*;
use std::ops::Range;
#[cfg(feature = "aync")]
use std::pin::Pin;
#[cfg(feature = "aync")]
use std::task::{Context, Poll};
#[cfg(feature = "aync")]
use tokio::io::ReadBuf;

#[must_use = "do nothing unless `.wait()/.await`"]
pub struct QUICPacketRead<'a, S> {
    pub(crate) socket: &'a mut S,
    pub(crate) packet_offsets: &'a mut Vec<(PacketType, Range<usize>)>,
    pub(crate) buffer: &'a mut Writer,
    pub(crate) current: PacketType,
    #[cfg(feature = "aync")]
    pub(crate) timeout: &'a mut Timeout,
}

impl<'a> QUICPacketRead<'a, std::net::UdpSocket> {
    pub fn wait(self) -> HlsResult<Range<usize>> {
        if self.packet_offsets.is_empty() { self.buffer.reset(); }
        let pos = self.packet_offsets.iter().position(|&(typ, _)| typ <= self.current);
        match pos {
            Some(pos) => Ok(self.packet_offsets.remove(pos).1),
            None => loop {
                let start = self.buffer.end();
                let unfilled = self.buffer.unfilled();
                let len = self.socket.recv(unfilled)?;
                let off = start..start + len;
                let flag = QUICFlag::from_raw(unfilled[0]);
                self.buffer.add_len(len);
                #[cfg(feature = "log")]
                trace!("read flag={:?}; cur={:?}; {}", flag.packet_type(), self.current, flag.packet_type() > self.current);
                if flag.packet_type() > self.current {
                    self.packet_offsets.push((flag.packet_type(), off));
                    continue;
                }
                break Ok(off);
            }
        }
    }
}

#[cfg(feature = "aync")]
impl<'a> Future for QUICPacketRead<'a, tokio::net::UdpSocket> {
    type Output = HlsResult<Range<usize>>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let reader = self.get_mut();
        if reader.packet_offsets.is_empty() { reader.buffer.reset(); }
        let pos = reader.packet_offsets.iter().position(|&(typ, _)| typ <= reader.current);
        match pos {
            Some(pos) => Poll::Ready(Ok(reader.packet_offsets.remove(pos).1)),
            None => loop {
                let start = reader.buffer.end();
                let mut buf = ReadBuf::new(reader.buffer.unfilled());
                match Pin::new(&mut reader.socket).poll_recv(cx, &mut buf)? {
                    Poll::Pending => {
                        reader.timeout.read_timeout()?;
                        return Poll::Pending;
                    }
                    Poll::Ready(_) => {
                        reader.timeout.reset_read();
                        let len = buf.filled().len();
                        let off = start..start + len;
                        let flag = QUICFlag::from_raw(buf.filled()[0]);
                        reader.buffer.add_len(len);
                        #[cfg(feature = "log")]
                        trace!("read flag={:?}; cur={:?}; {}", flag.packet_type(), reader.current, flag.packet_type() > reader.current);
                        if flag.packet_type() > reader.current {
                            reader.packet_offsets.push((flag.packet_type(), off));
                            continue;
                        }
                        break Poll::Ready(Ok(off));
                    }
                }
            }
        }
    }
}
