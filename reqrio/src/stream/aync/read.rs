use super::poll_sleep;
use crate::error::HlsResult;
use crate::{Buffer, HlsError, ReadOffset, RecordBuffer, TimeError};
use pin_project_lite::pin_project;
use reqtls::WriteExt;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, ReadBuf, ReadHalf};
use tokio::sync::futures::{Notified, OwnedNotified};
use tokio::sync::mpsc::Sender;
use tokio::sync::Notify;
use tokio::time::Sleep;

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
        let mut reader = ReadBuf::new(read.buf.unfilled());
        if read.stream.poll_read(cx, &mut reader)?.is_ready() {
            let len = reader.filled().len();
            read.buf.add_len(len);
            return Poll::Ready(Ok(()));
        }
        poll_sleep(*read.timeout, read.sleep, cx, || Err(TimeError::ReadTimeout.into()))
    }
}


pin_project! {
    pub struct ReadRecord<'a, S: Send> {
        reader: StreamReading<'a, S>,
        #[pin]
        notified: OwnedNotified,
        #[pin]
        close_notify: Notified<'a>,
        record_len: usize,
    }
}

impl<'a, S: AsyncRead + Unpin + Send> Future for ReadRecord<'a, S> {
    type Output = io::Result<ReadOffset>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut project = self.project();
        if project.close_notify.poll(cx).is_ready() {
            return Poll::Ready(Err(io::Error::other("close by hand")));
        }
        if *project.record_len == 0 {
            match project.reader.read_record_size(project.notified.as_mut(), cx)? {
                Poll::Ready(size) => *project.record_len = size,
                Poll::Pending => return Poll::Pending,
            }
        }
        if project.reader.buffer.current_size() < *project.record_len &&
            project.reader.read_size(*project.record_len, project.notified.as_mut(), cx)?.is_pending() {
            return Poll::Pending;
        }
        let offset = project.reader.buffer.next_record_offset(*project.record_len);
        let read_offset = ReadOffset::new(offset, project.reader.buffer, project.reader.notify.clone());
        Poll::Ready(Ok(read_offset))
    }
}

struct StreamReading<'a, S: Send> {
    buffer: &'a mut RecordBuffer,
    reader: &'a mut ReadHalf<S>,
    notify: &'a Arc<Notify>,
}

impl<'a, S: AsyncRead + Unpin + Send> StreamReading<'a, S> {
    fn read_size(&mut self, want_size: usize, mut notified: Pin<&mut OwnedNotified>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let current_size = self.buffer.current_size();
        if current_size >= want_size { return Poll::Ready(Ok(())); }
        let mut unfilled = loop {
            match self.buffer.unfilled_mut(want_size, current_size) {
                Poll::Ready(res) => break ReadBuf::new(res),
                Poll::Pending => match notified.as_mut().poll(cx) {
                    Poll::Ready(_) => {
                        notified.set(self.notify.clone().notified_owned());
                        continue;
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
        };
        let need_read_size = want_size - current_size;
        while unfilled.filled().len() < need_read_size {
            match Pin::new(&mut self.reader).poll_read(cx, &mut unfilled)? {
                Poll::Ready(_) => {
                    if unfilled.filled().is_empty() {
                        return Poll::Ready(Err(HlsError::PeerClosedConnection.into()));
                    }
                }
                Poll::Pending => {
                    let size = unfilled.filled().len();
                    self.buffer.add_filled(size);
                    return Poll::Pending;
                }
            };
        }
        let size = unfilled.filled().len();
        self.buffer.add_filled(size);
        Poll::Ready(Ok(()))
    }


    fn read_record_size(&mut self, notified: Pin<&mut OwnedNotified>, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        if self.buffer.current_size() < 5 && self.read_size(23, notified, cx)?.is_pending() { return Poll::Pending; };
        Poll::Ready(Ok(self.buffer.next_record_len()))
    }
}


pub struct StreamRead<S: Send> {
    pub buffer: RecordBuffer,
    pub reader: ReadHalf<S>,
    pub sender: Sender<io::Result<ReadOffset>>,
    pub closed: Arc<Notify>,
    pub notify: Arc<Notify>,
}

impl<S: AsyncRead + Unpin + Send> StreamRead<S> {
    fn read_record(&mut self) -> ReadRecord<'_, S> {
        ReadRecord {
            close_notify: self.closed.notified(),
            notified: self.notify.clone().notified_owned(),
            reader: StreamReading {
                buffer: &mut self.buffer,
                reader: &mut self.reader,
                notify: &self.notify,
            },
            record_len: 0,
        }
    }

    async fn read(&mut self) -> bool {
        let res = self.read_record().await;
        let is_err = res.is_err();
        self.sender.send_timeout(res, Duration::from_millis(10)).await.unwrap();
        is_err
    }


    pub async fn run(&mut self) {
        loop {
            tokio::select! {
                _=self.closed.clone().notified_owned()=>break,
                finished = self.read() => if finished { break; },
            }
        }
        println!("stream closed");
    }
}
