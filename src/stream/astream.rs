use crate::error::HlsResult;
use crate::stream::ConnParam;
#[cfg(cls_async)]
use crate::tls::AsyncStream;
#[cfg(all(feature = "std_async", not(feature = "cls_sync")))]
use rustls::pki_types::{DnsName, ServerName};
#[cfg(all(feature = "std_async", not(feature = "cls_sync")))]
use rustls::{ClientConfig, RootCertStore};
#[cfg(all(feature = "std_async", not(feature = "cls_sync")))]
use std::sync::Arc;
use std::time::Duration;
#[cfg(any(feature = "cls_async", feature = "std_async"))]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(any(feature = "cls_async", feature = "std_async"))]
use tokio::net::TcpStream;
#[cfg(all(feature = "std_async", not(feature = "cls_sync")))]
use tokio_rustls::client::TlsStream;
#[cfg(all(feature = "std_async", not(feature = "cls_sync")))]
use tokio_rustls::TlsConnector;

#[cfg(any(feature = "cls_async", feature = "std_async"))]
pub struct AsyncTcpStream {
    stream: TcpStream,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
}

#[cfg(any(feature = "cls_async", feature = "std_async"))]
impl AsyncTcpStream {
    pub async fn connect_timeout(addr: impl tokio::net::ToSocketAddrs, timeout: Duration) -> HlsResult<AsyncTcpStream> {
        Ok(AsyncTcpStream {
            stream: tokio::time::timeout(timeout, TcpStream::connect(addr)).await??,
            read_timeout: None,
            write_timeout: None,
        })
    }

    pub fn set_read_timeout(&mut self, read_timeout: Duration) {
        self.read_timeout = Some(read_timeout);
    }

    pub fn set_write_timeout(&mut self, write_timeout: Duration) {
        self.write_timeout = Some(write_timeout);
    }

    pub async fn read(&mut self, buf: &mut [u8]) -> HlsResult<usize> {
        let res = match self.read_timeout {
            None => self.stream.read(buf).await,
            Some(timeout) => tokio::time::timeout(timeout, self.stream.read(buf)).await?,
        }?;
        Ok(res)
    }

    pub async fn write(&mut self, buf: &[u8]) -> HlsResult<usize> {
        let res = match self.write_timeout {
            None => self.stream.write(buf).await,
            Some(timeout) => tokio::time::timeout(timeout, self.stream.write(buf)).await?
        }?;
        Ok(res)
    }

    pub async fn flush(&mut self) -> HlsResult<()> {
        match self.write_timeout {
            None => self.stream.flush().await?,
            Some(timeout) => tokio::time::timeout(timeout, self.stream.flush()).await??
        }
        Ok(())
    }

    pub async fn shutdown(&mut self) -> HlsResult<()> {
        match self.read_timeout {
            None => self.stream.shutdown().await?,
            Some(timeout) => tokio::time::timeout(timeout, self.stream.shutdown()).await??
        }
        Ok(())
    }
}

#[cfg(std_async)]
pub struct StdAsyncTlsStream {
    stream: TlsStream<TcpStream>,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
}

#[cfg(std_async)]
impl StdAsyncTlsStream {
    pub async fn connect_timeout(param: ConnParam<'_>, tcp: AsyncTcpStream) -> HlsResult<StdAsyncTlsStream> {
        let dns_name = DnsName::try_from(param.url.addr().host().to_string())?;
        let server_name = ServerName::DnsName(dns_name);
        let mut root = RootCertStore::empty();
        root.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut config = ClientConfig::builder()
            .with_root_certificates(root)
            .with_no_client_auth();
        if let ALPN::Http20 = param.alpn {
            println!("111");
            config.alpn_protocols = vec![
                ALPN::Http20.value(),
                ALPN::Http11.value(),
                ALPN::Http10.value(),
            ]
        }
        let connector = TlsConnector::from(Arc::new(config));
        let stream = tokio::time::timeout(param.timeout.connect(), connector.connect(server_name, tcp.stream)).await??;
        Ok(StdAsyncTlsStream {
            stream,
            read_timeout: tcp.read_timeout,
            write_timeout: tcp.write_timeout,
        })
    }

    pub async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.read_timeout {
            None => self.stream.read(buf).await,
            Some(timeout) => tokio::time::timeout(timeout, self.stream.read(buf)).await?
        }
    }

    pub async fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self.write_timeout {
            None => self.stream.write(buf).await,
            Some(timeout) => tokio::time::timeout(timeout, self.stream.write(buf)).await?
        }
    }

    pub async fn flush(&mut self) -> std::io::Result<()> {
        match self.write_timeout {
            None => self.stream.flush().await,
            Some(timeout) => tokio::time::timeout(timeout, self.stream.flush()).await?
        }
    }

    pub async fn shutdown(&mut self) -> std::io::Result<()> {
        match self.write_timeout {
            None => self.stream.shutdown().await,
            Some(timeout) => tokio::time::timeout(timeout, self.stream.shutdown()).await?,
        }
    }

    pub fn alpn(&self) -> Option<ALPN> {
        let alpn = self.stream.get_ref().1.alpn_protocol()?;
        Some(ALPN::from_slice(alpn))
    }
}


#[cfg(cls_async)]
pub struct AsyncTlsStream {
    stream: AsyncStream<TcpStream>,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
}

#[cfg(cls_async)]
impl AsyncTlsStream {
    pub async fn connect_timeout(param: ConnParam<'_>, tcp: AsyncTcpStream) -> HlsResult<AsyncTlsStream> {
        let connect_timeout=param.timeout.connect();
        let stream = AsyncStream::connect(param, tcp.stream);
        Ok(AsyncTlsStream {
            stream: tokio::time::timeout(connect_timeout, stream).await??,
            read_timeout: tcp.read_timeout,
            write_timeout: tcp.write_timeout,
        })
    }

    pub async fn read(&mut self) -> HlsResult<Vec<u8>> {
        match self.read_timeout {
            None => self.stream.read_tls().await,
            Some(timeout) => tokio::time::timeout(timeout, self.stream.read_tls()).await?
        }
    }

    pub async fn write(&mut self, buf: &[u8]) -> HlsResult<()> {
        match self.write_timeout {
            None => self.stream.write_tls(buf).await,
            Some(timeout) => tokio::time::timeout(timeout, self.stream.write_tls(buf)).await?,
        }
    }

    pub async fn flush(&mut self) -> HlsResult<()> {
        match self.write_timeout {
            None => self.stream.flush().await,
            Some(timeout) => tokio::time::timeout(timeout, self.stream.flush()).await?,
        }
    }

    pub async fn shutdown(&mut self) -> HlsResult<()> {
        match self.write_timeout {
            None => self.stream.shutdown().await,
            Some(timeout) => tokio::time::timeout(timeout, self.stream.shutdown()).await?,
        }
    }

    pub fn alpn(&self) -> Option<&str> {
        self.stream.alpn()
    }
}
