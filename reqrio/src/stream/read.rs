use crate::error::HlsResult;
use crate::stream::Stream;
use crate::*;
use std::io::{ErrorKind, Read};
#[cfg(feature = "aync")]
use std::{pin::Pin, task::{Context, Poll}};
use std::io;
#[cfg(feature = "aync")]
use tokio::io::{AsyncRead, ReadBuf};

#[must_use = "streams do nothing unless `.wait()/.await`"]
pub struct BufReading<'a, S> {
    pub(crate) buf: &'a mut Writer,
    pub(crate) stream: &'a mut S,
    pub(crate) want_size: usize,
    #[cfg(feature = "aync")]
    pub(crate) timeout: &'a mut Timeout,
    #[cfg(feature = "aync")]
    pub(crate) timeout_reset: bool,
}

impl<'a, S: Read> BufReading<'a, S> {
    pub(crate) fn wait(self) -> io::Result<usize> {
        if self.buf.len() >= self.want_size { return Ok(self.buf.len()); }
        debug_assert!(self.want_size > 0 && self.buf.len() < self.want_size);
        self.buf.check_move(self.want_size)?;
        while self.buf.len() < self.want_size {
            match self.stream.read(self.buf.unfilled()).map_err(|e| e.kind()) {
                Ok(0) => return Err(io::Error::from(ErrorKind::BrokenPipe)),
                Ok(len) => self.buf.add_len(len),
                Err(ErrorKind::Interrupted) => continue,
                Err(e) => return Err(io::Error::from(e)),
            }
        }
        Ok(self.buf.len())
    }
}


#[cfg(feature = "aync")]
impl<'a, S: AsyncRead + Unpin> Future for BufReading<'a, S> {
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.buf.len() >= self.want_size { return Poll::Ready(Ok(self.buf.len())); }
        let reading = self.get_mut();
        if !reading.timeout_reset {
            reading.timeout.reset_read();
            reading.timeout_reset = true;
        }
        debug_assert!(reading.want_size > 0 && reading.buf.len() < reading.want_size);
        reading.buf.check_move(reading.want_size)?;
        while reading.buf.len() < reading.want_size {
            let stream = Pin::new(&mut reading.stream);
            let mut buf = ReadBuf::new(reading.buf.unfilled());
            match stream.poll_read(cx, &mut buf)? {
                Poll::Pending => {
                    reading.timeout.read_timeout(cx)?;
                    return Poll::Pending;
                }
                Poll::Ready(_) => {
                    reading.timeout.reset_read();
                    let len = buf.filled().len();
                    if len == 0 { return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())); }
                    reading.buf.add_len(len);
                }
            }
        }
        Poll::Ready(Ok(reading.buf.len()))
    }
}

#[must_use = "streams do nothing unless `.wait()/.await`"]
pub struct ChunkReading<'a, S> {
    pub(crate) len_size: usize,
    pub(crate) func: Box<dyn Fn(&[u8]) -> usize + Send + Sync>,
    pub(crate) stream: &'a mut S,
    pub(crate) buf: &'a mut Buffer,
    #[cfg(feature = "aync")]
    pub(crate) timeout: &'a mut Timeout,
}

impl<'a, S: Read> ChunkReading<'a, S> {
    pub fn wait(self) -> io::Result<usize> {
        if self.buf.len() < self.len_size {
            BufReading {
                buf: self.buf,
                stream: self.stream,
                want_size: self.len_size,
                #[cfg(feature = "aync")]
                timeout: self.timeout,
                #[cfg(feature = "aync")]
                timeout_reset: false,
            }.wait()?;
        }
        let chunk_size = (self.func)(self.buf.filled());
        BufReading {
            buf: self.buf,
            stream: self.stream,
            want_size: chunk_size,
            #[cfg(feature = "aync")]
            timeout: self.timeout,
            #[cfg(feature = "aync")]
            timeout_reset: false,
        }.wait()?;
        Ok(chunk_size)
    }
}

#[cfg(feature = "aync")]
impl<'a, S: AsyncRead + Unpin> Future for ChunkReading<'a, S> {
    type Output = HlsResult<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let chunk_reading = self.get_mut();
        if chunk_reading.buf.len() < chunk_reading.len_size {
            let mut reading = BufReading {
                stream: chunk_reading.stream,
                buf: chunk_reading.buf,
                want_size: chunk_reading.len_size,
                timeout: chunk_reading.timeout,
                timeout_reset: false,
            };
            if Pin::new(&mut reading).poll(cx)?.is_pending() { return Poll::Pending; }
        }
        let chunk_size = (chunk_reading.func)(chunk_reading.buf.filled());
        let mut reading = BufReading {
            stream: chunk_reading.stream,
            buf: chunk_reading.buf,
            want_size: chunk_size,
            timeout: chunk_reading.timeout,
            timeout_reset: false,
        };
        if Pin::new(&mut reading).poll(cx)?.is_pending() { return Poll::Pending; }
        Poll::Ready(Ok(chunk_size))
    }
}

unsafe impl<'a, S> Sync for ChunkReading<'a, S> {}
unsafe impl<'a, S> Send for ChunkReading<'a, S> {}

#[must_use = "streams do nothing unless `.wait()/.await`"]
pub struct StreamRead<'a> {
    pub(crate) stream: &'a mut Stream,
    pub(crate) buf: &'a mut Writer,
}

impl<'a> StreamRead<'a> {
    pub fn wait(self) -> HlsResult<()> {
        let stream: &mut dyn Read = match self.stream {
            Stream::NonConnection => return Err("NonConnection".into()),
            Stream::SyncHttp(stream) => stream,
            Stream::SyncHttps(stream) => stream,
            #[cfg(feature = "aync")]
            _ => unreachable!(),
        };
        let len = stream.read(self.buf.unfilled())?;
        self.buf.add_len(len);
        Ok(())
    }
}

#[cfg(feature = "aync")]
impl<'a> Future for StreamRead<'a> {
    type Output = HlsResult<()>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let reader = self.get_mut();
        let stream: &mut (dyn AsyncRead + Unpin) = match reader.stream {
            Stream::NonConnection => return Poll::Ready(Err("NonConnection".into())),
            Stream::AsyncHttp(stream) => stream,
            Stream::AsyncHttps(stream) => stream,
            _ => unreachable!(),
        };
        let mut buf = ReadBuf::new(reader.buf.unfilled());
        match Pin::new(stream).poll_read(cx, &mut buf)? {
            Poll::Ready(_) => {
                let len = buf.filled().len();
                reader.buf.add_len(len);
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
