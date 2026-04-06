#[cfg(feature = "aync")]
use super::async_stream::TlsStream;
use crate::error::HlsResult;
use crate::stream::proxy::ProxyStream;
use crate::stream::ConnParam;
use crate::*;
use std::time::Duration;
use tokio::io;
#[cfg(feature = "aync")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(feature = "aync")]
use tokio::net::TcpStream;

pub trait TimeoutRW<S: AsyncReadExt + AsyncWriteExt + Unpin> {
    fn stream(&mut self) -> &mut S;
    fn read_timeout(&self) -> Option<Duration>;
    fn write_timeout(&self) -> Option<Duration>;

    async fn read(&mut self, buffer: &mut Buffer) -> HlsResult<()> {
        match self.read_timeout() {
            None => buffer.async_read(self.stream()).await,
            Some(timeout) => tokio::time::timeout(timeout, buffer.async_read(self.stream())).await?
        }
    }

    async fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.write_timeout() {
            None => self.stream().write(buf).await,
            Some(timeout) => tokio::time::timeout(timeout, self.stream().write(buf)).await?
        }
    }

    async fn flush(&mut self) -> io::Result<()> {
        match self.write_timeout() {
            None => self.stream().flush().await,
            Some(timeout) => tokio::time::timeout(timeout, self.stream().flush()).await?
        }
    }

    async fn shutdown(&mut self) -> HlsResult<()> {
        match self.write_timeout() {
            None => self.stream().shutdown().await?,
            Some(timeout) => tokio::time::timeout(timeout, self.stream().shutdown()).await??
        }
        Ok(())
    }
}

pub struct AsyncTcpStream {
    stream: ProxyStream<TcpStream>,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
}

impl AsyncTcpStream {
    pub fn from_proxy_stream(stream: ProxyStream<TcpStream>, timeout: &Timeout) -> Self {
        AsyncTcpStream {
            stream,
            read_timeout: Option::from(timeout.read()),
            write_timeout: Option::from(timeout.write()),
        }
    }
}

impl TimeoutRW<ProxyStream<TcpStream>> for AsyncTcpStream {
    fn stream(&mut self) -> &mut ProxyStream<TcpStream> {
        &mut self.stream
    }

    fn read_timeout(&self) -> Option<Duration> {
        self.read_timeout
    }

    fn write_timeout(&self) -> Option<Duration> {
        self.write_timeout
    }
}

pub struct AsyncTlsStream {
    stream: TlsStream<ProxyStream<TcpStream>>,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
}

impl AsyncTlsStream {
    pub async fn connect_timeout(param: ConnParam<'_>, tcp: ProxyStream<TcpStream>) -> HlsResult<AsyncTlsStream> {
        let connect_timeout = param.timeout.connect();
        let read_timeout = param.timeout.read();
        let write_timeout = param.timeout.write();
        let config = ClientConfig {
            sni: param.addr.host(),
            alpn: param.alpn,
            fingerprint: param.fingerprint,
            client_cert: param.cert,
            cert_key: param.key,
            verify: param.verify,
            ca_certs: param.ca_cert,
        };
        Ok(AsyncTlsStream {
            stream: tokio::time::timeout(connect_timeout, TlsStream::connect(tcp, config)).await??,
            read_timeout: Some(read_timeout),
            write_timeout: Some(write_timeout),
        })
    }

    pub fn alpn(&self) -> Option<&ALPN> {
        self.stream.alpn()
    }
}

impl TimeoutRW<TlsStream<ProxyStream<TcpStream>>> for AsyncTlsStream {
    fn stream(&mut self) -> &mut TlsStream<ProxyStream<TcpStream>> {
        &mut self.stream
    }

    fn read_timeout(&self) -> Option<Duration> {
        self.read_timeout
    }

    fn write_timeout(&self) -> Option<Duration> {
        self.write_timeout
    }
}
