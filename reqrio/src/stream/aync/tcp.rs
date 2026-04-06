use std::time::Duration;
use tokio::net::TcpStream;
use crate::{ProxyStream, Timeout};
use super::ext::TimeoutRW;

pub struct TcpStreamA {
    stream: ProxyStream<TcpStream>,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
}

impl TcpStreamA {
    pub fn from_proxy_stream(stream: ProxyStream<TcpStream>, timeout: &Timeout) -> Self {
        TcpStreamA {
            stream,
            read_timeout: Option::from(timeout.read()),
            write_timeout: Option::from(timeout.write()),
        }
    }
}

impl TimeoutRW<ProxyStream<TcpStream>> for TcpStreamA {
    #[inline]
    fn stream(&mut self) -> &mut ProxyStream<TcpStream> {
        &mut self.stream
    }

    #[inline]
    fn read_timeout(&self) -> Option<Duration> {
        self.read_timeout
    }

    #[inline]
    fn write_timeout(&self) -> Option<Duration> {
        self.write_timeout
    }
}
