use std::pin::Pin;
use std::task::{Context, Poll};
use pin_project_lite::pin_project;
use tokio::io::AsyncWrite;
use tokio::time::Sleep;
use crate::error::HlsResult;
use crate::TimeError;
use super::poll_sleep;

pin_project! {
    pub struct ShutdownTimeout<'a, S> {
        #[pin]
        pub(crate) stream: &'a mut S,
        pub(crate) timeout: bool,
        #[pin]
        pub(crate) sleep: Sleep
        
    }
}

impl<'a, S: AsyncWrite + Unpin> Future for ShutdownTimeout<'a, S> {
    type Output = HlsResult<()>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let shutdown = self.project();
        if shutdown.stream.poll_shutdown(cx)?.is_ready() { return Poll::Ready(Ok(())); }
        poll_sleep(*shutdown.timeout, shutdown.sleep, cx, || Err(TimeError::ShutdownTimeout.into()))
    }
}