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