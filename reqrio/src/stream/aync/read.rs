use std::pin::Pin;
use std::task::{Context, Poll};
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, ReadBuf};
use tokio::time::Sleep;
use crate::error::HlsResult;
use crate::{Buffer, TimeError};
use super::poll_sleep;

pin_project! {
    pub struct ReadTimeout<'a, S> {
        #[pin]
        pub(crate) stream: &'a mut S,
        pub(crate) timeout: bool,
        #[pin]
        pub(crate) sleep: Sleep,
        pub(crate) buf:&'a mut Buffer
    }
}
impl<'a, S: AsyncRead + Unpin> Future for ReadTimeout<'a, S> {
    type Output = HlsResult<()>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let read = self.project();
        let mut reader = ReadBuf::new(read.buf.unfilled_mut());
        if read.stream.poll_read(cx, &mut reader)?.is_ready() {
            let len = reader.filled().len();
            read.buf.add_len(len);
            return Poll::Ready(Ok(()));
        }
        poll_sleep(*read.timeout, read.sleep, cx, || Err(TimeError::ReadTimeout.into()))
    }
}
