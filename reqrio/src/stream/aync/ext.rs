use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::Buffer;
use super::read::ReadTimeout;
use super::write::{WriteTimeout, WriteAll};
use super::shutdown::ShutdownTimeout;
use super::flush::FlushTimeout;


pub trait TimeoutRW<S: AsyncReadExt + AsyncWriteExt + Unpin> {
    fn stream(&mut self) -> &mut S;
    fn read_timeout(&self) -> Option<Duration>;
    fn write_timeout(&self) -> Option<Duration>;

    #[inline]
    fn read<'a, 'b: 'a>(&'a mut self, buffer: &'b mut Buffer) -> ReadTimeout<'a, S> {
        let timeout = self.read_timeout();
        ReadTimeout {
            stream: self.stream(),
            timeout: timeout.is_some(),
            sleep: if let Some(timeout) = timeout {
                tokio::time::sleep(timeout)
            } else { tokio::time::sleep(Duration::from_secs(0)) },
            buf: buffer,
        }
    }

    #[allow(dead_code)]
    #[inline]
    fn write<'a, 'b: 'a>(&'a mut self, buf: &'b [u8]) -> WriteTimeout<'a, S> {
        let timeout = self.write_timeout();
        WriteTimeout {
            stream: self.stream(),
            timeout: timeout.is_some(),
            sleep: if let Some(timeout) = timeout {
                tokio::time::sleep(timeout)
            } else { tokio::time::sleep(Duration::from_secs(0)) },
            buf,
        }
    }

    #[allow(dead_code)]
    #[inline]
    fn flush(&mut self) -> FlushTimeout<'_, S> {
        let timeout = self.write_timeout();
        FlushTimeout {
            stream: self.stream(),
            timeout: timeout.is_some(),
            sleep: if let Some(timeout) = timeout {
                tokio::time::sleep(timeout)
            } else { tokio::time::sleep(Duration::from_secs(0)) },
        }
    }

    #[inline]
    fn shutdown(&mut self) -> ShutdownTimeout<'_, S> {
        let timeout = self.write_timeout();
        ShutdownTimeout {
            timeout: timeout.is_some(),
            sleep: if let Some(timeout) = timeout {
                tokio::time::sleep(timeout)
            } else { tokio::time::sleep(Duration::from_secs(0)) },
            stream: self.stream(),
        }
    }

    #[inline]
    fn write_all<'a, 'b: 'a>(&'a mut self, buf: &'b [u8]) -> WriteAll<'a, S> {
        let timeout = self.write_timeout();
        WriteAll {
            stream: self.stream(),
            timeout: timeout.is_some(),
            sleep: if let Some(timeout) = timeout {
                tokio::time::sleep(timeout)
            } else { tokio::time::sleep(Duration::from_secs(0)) },
            buf,
        }
    }
}