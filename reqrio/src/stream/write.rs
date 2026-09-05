use crate::error::HlsResult;
use crate::stream::Stream;
use crate::*;
use std::io::Write;
#[cfg(feature = "aync")]
use std::pin::Pin;
#[cfg(feature = "aync")]
use std::task::{Context, Poll};
#[cfg(feature = "aync")]
use tokio::io::AsyncWrite;

#[must_use = "do nothing unless `.wait()/.await`"]
pub struct BufWriting<'a, S> {
    pub(crate) stream: &'a mut S,
    pub(crate) buf: &'a mut Writer,
    #[cfg(feature = "aync")]
    pub(crate) timeout: &'a mut Timeout,
}

impl<'a, S: Write> BufWriting<'a, S> {
    pub(crate) fn wait(self) -> HlsResult<()> {
        while !self.buf.is_empty() {
            let len = self.stream.write(self.buf.filled())?;
            self.buf.used_empty(len);
        }
        Ok(())
    }
}
#[cfg(feature = "aync")]
impl<'a, S: AsyncWrite + Unpin> Future for BufWriting<'a, S> {
    type Output = HlsResult<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let writer = self.get_mut();
        while !writer.buf.is_empty() {
            match Pin::new(&mut writer.stream).poll_write(cx, writer.buf.filled())? {
                Poll::Ready(wrote) => {
                    writer.timeout.reset_write();
                    if wrote == 0 { return Poll::Ready(Err(HlsError::PeerClosedConnection)); }
                    if writer.buf.used_empty(wrote) { break; }
                }
                Poll::Pending => {
                    writer.timeout.write_timeout()?;
                    return Poll::Pending;
                }
            }
        }
        writer.buf.reset();
        Poll::Ready(Ok(()))
    }
}

#[must_use = "do nothing unless `.wait()/.await`"]
pub struct StreamWrite<'a> {
    pub(crate) stream: &'a mut Stream,
    pub(crate) buf: &'a mut Writer,
}

impl<'a> StreamWrite<'a> {
    pub fn wait(self) -> HlsResult<()> {
        let stream: &mut dyn Write = match self.stream {
            Stream::NonConnection => return Err("NonConnection".into()),
            Stream::SyncHttp(stream) => stream,
            Stream::SyncHttps(stream) => stream,
            #[cfg(feature = "aync")]
            _ => unreachable!(),
        };
        stream.write_all(self.buf.filled())?;
        self.buf.reset();
        Ok(())
    }
}

#[cfg(feature = "aync")]
impl<'a> Future for StreamWrite<'a> {
    type Output = HlsResult<()>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let writer = self.get_mut();
        let stream: &mut (dyn AsyncWrite + Unpin) = match writer.stream {
            Stream::NonConnection => return Poll::Ready(Err("NonConnection".into())),
            Stream::AsyncHttp(stream) => stream,
            Stream::AsyncHttps(stream) => stream,
            _ => unreachable!(),
        };
        loop {
            match Pin::new(&mut *stream).poll_write(cx, writer.buf.filled())? {
                Poll::Ready(len) => if writer.buf.used_empty(len) { break; },
                Poll::Pending => return Poll::Pending,
            }
        }
        writer.buf.reset();
        Poll::Ready(Ok(()))
    }
}


#[must_use = "do nothing unless `.wait()/.await`"]
pub struct StreamShutdown<'a> {
    pub(crate) stream: &'a mut Stream,
}

impl<'a> StreamShutdown<'a> {
    pub fn wait(self) -> HlsResult<()> {
        match self.stream {
            Stream::NonConnection => Err("NonConnection".into()),
            Stream::SyncHttp(stream) => stream.shutdown(),
            Stream::SyncHttps(stream) => stream.shutdown(),
            #[cfg(feature = "aync")]
            _ => unreachable!(),
        }
    }
}

#[cfg(feature = "aync")]
impl<'a> Future for StreamShutdown<'a> {
    type Output = HlsResult<()>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let reader = self.get_mut();
        let stream: &mut (dyn AsyncWrite + Unpin) = match reader.stream {
            Stream::NonConnection => return Poll::Ready(Err("NonConnection".into())),
            Stream::AsyncHttp(stream) => stream,
            Stream::AsyncHttps(stream) => stream,
            _ => unreachable!(),
        };
        if Pin::new(stream).poll_shutdown(cx)?.is_pending() {
            return Poll::Pending;
        }
        Poll::Ready(Ok(()))
    }
}
