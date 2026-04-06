use std::pin::Pin;
use std::task::{Context, Poll};
use pin_project_lite::pin_project;
use tokio::io::AsyncWrite;
use tokio::time::Sleep;
use crate::error::HlsResult;
use crate::TimeError;
use super::poll_sleep;

pin_project! {
    pub struct FlushTimeout<'a, S> {
        #[pin]
        pub(crate) stream: &'a mut S,
        pub(crate) timeout: bool,
        #[pin]
        pub(crate) sleep: Sleep
    }
}

impl<'a, S: AsyncWrite + Unpin> Future for FlushTimeout<'a, S> {
    type Output = HlsResult<()>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let flush = self.project();
        if flush.stream.poll_flush(cx)?.is_ready() { return Poll::Ready(Ok(())); }
        poll_sleep(*flush.timeout, flush.sleep, cx, || Err(TimeError::FlushTimeout.into()))
    }
}