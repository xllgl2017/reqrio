use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use pin_project_lite::pin_project;
use tokio::io::AsyncWrite;
use tokio::time::Sleep;
use crate::error::HlsResult;
use crate::TimeError;
use super::poll_sleep;

pin_project! {
    pub struct WriteTimeout<'a, S> {
        #[pin]
        pub(crate) stream: &'a mut S,
        pub(crate) timeout: bool,
        #[pin]
        pub(crate) sleep: Sleep,
        pub(crate) buf: &'a [u8]
    }
}

impl<'a, S: AsyncWrite + Unpin> Future for WriteTimeout<'a, S> {
    type Output = HlsResult<usize>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let write = self.project();
        if let Poll::Ready(wrote) = write.stream.poll_write(cx, write.buf)? {
            return Poll::Ready(Ok(wrote));
        }
        poll_sleep(*write.timeout, write.sleep, cx, || Err(TimeError::WriteTimeout.into()))
    }
}

pin_project! {
    pub struct WriteAll<'a, S> {
        #[pin]
        pub(crate) stream: &'a mut S,
        pub(crate) timeout: bool,
        #[pin]
        pub(crate) sleep: Sleep,
        pub(crate) buf: &'a [u8]
    }
}

impl<'a, S: AsyncWrite + Unpin> Future for WriteAll<'a, S> {
    type Output = HlsResult<()>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut write = self.project();
        while !write.buf.is_empty() {
            if let Poll::Ready(wrote) = write.stream.as_mut().poll_write(cx, write.buf)? {
                if wrote == 0 { return Poll::Ready(Err(io::ErrorKind::WriteZero.into())); }
                let (_, remain) = write.buf.split_at(wrote);
                *write.buf = remain;
            }
            if let Poll::Ready(ready) = poll_sleep(*write.timeout, write.sleep.as_mut(), cx, || Err(TimeError::WriteTimeout.into())) {
                return Poll::Ready(ready);
            }
        }
        Poll::Ready(Ok(()))
    }
}