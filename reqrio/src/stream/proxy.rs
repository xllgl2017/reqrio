use crate::error::{HlsError, HlsResult};
#[cfg(any(feature = "std_async", feature = "cls_async"))]
use crate::stream::astream::AsyncTcpStream;
use crate::timeout::Timeout;
use crate::url::{Addr, Protocol};
use std::fmt::{Display, Formatter};
use std::net::{TcpStream, ToSocketAddrs};
use crate::Url;

#[derive(Clone, Debug)]
pub enum Proxy {
    Null,
    HttpPlain(Addr),
    Socks5(Addr),
}

impl Proxy {
    fn create_sync(&self, addr: impl AsRef<str>, timeout: &Timeout) -> HlsResult<TcpStream> {
        let socket_addr = addr.as_ref().to_socket_addrs()?.next().ok_or("Invalid address")?;
        let stream = TcpStream::connect_timeout(&socket_addr, timeout.connect())?;
        stream.set_read_timeout(Some(timeout.read()))?;
        stream.set_write_timeout(Some(timeout.write()))?;
        Ok(stream)
    }

    #[cfg(aync)]
    async fn create_async(&self, addr: impl AsRef<str>, timeout: &Timeout) -> HlsResult<AsyncTcpStream> {
        let mut stream = AsyncTcpStream::connect_timeout(addr.as_ref(), timeout.connect()).await?;
        stream.set_read_timeout(timeout.read());
        stream.set_write_timeout(timeout.write());
        return Ok(stream);
    }

    pub fn create_sync_stream(&self, peer_addr: &Addr, timeout: &Timeout) -> HlsResult<TcpStream> {
        match self {
            Proxy::Null => self.create_sync(peer_addr.to_string(), timeout),
            Proxy::HttpPlain(addr) => {
                let mut stream = self.create_sync(addr.to_string(), timeout)?;
                let context = vec![
                    format!("CONNECT {} HTTP/1.1", peer_addr.to_string()),
                    format!("Host: {}", peer_addr.to_string()),
                    "Proxy-Connection: Keep-Alive".to_string(),
                    "".to_string(),
                    "".to_string()
                ];
                std::io::Write::write(&mut stream, context.join("\r\n").as_bytes())?;
                std::io::Write::flush(&mut stream)?;
                let mut buf = [0; 1024];
                let len = std::io::Read::read(&mut stream, &mut buf)?;
                let res = String::from_utf8(buf[..len].to_vec())?;
                if !res.starts_with("HTTP/1.1 200") { return Err("connect to proxy error".into()); }
                Ok(stream)
            }
            Proxy::Socks5(addr) => {
                let mut stream = self.create_sync(addr.to_string(), timeout)?;
                std::io::Write::write(&mut stream, &[5, 1, 0])?;
                std::io::Write::flush(&mut stream)?;
                let mut buf = [0; 2];
                let len = std::io::Read::read(&mut stream, &mut buf)?;
                if len != 2 { return Err("socks5 handshake fail".into()); }
                let mut data = vec![5, 1, 0, 3];
                data.push(peer_addr.host().len() as u8);
                data.extend_from_slice(peer_addr.host().as_bytes());
                data.extend(peer_addr.port().to_be_bytes());
                std::io::Write::write(&mut stream, &data)?;
                std::io::Write::flush(&mut stream)?;
                let mut buf = [0; 256];
                let len = std::io::Read::read(&mut stream, &mut buf)?;
                if len == 0 { return Err("connection closed by proxy".into()); }
                Ok(stream)
            }
        }
    }

    #[cfg(aync)]
    pub async fn create_async_stream(&self, peer_addr: &Addr, timeout: &Timeout) -> HlsResult<AsyncTcpStream> {
        match self {
            Proxy::Null => self.create_async(peer_addr.to_string(), timeout).await,
            Proxy::HttpPlain(addr) => {
                let mut stream = self.create_async(addr.to_string(), timeout).await?;
                let context = vec![
                    format!("CONNECT {} HTTP/1.1", peer_addr.to_string()),
                    format!("Host: {}", peer_addr.to_string()),
                    "Proxy-Connection: Keep-Alive".to_string(),
                    "".to_string(),
                    "".to_string()
                ];
                stream.write(context.join("\r\n").as_bytes()).await?;
                stream.flush().await?;
                let mut buf = [0; 1024];
                let len = stream.read(&mut buf).await?;
                let res = String::from_utf8(buf[..len].to_vec())?;
                if !res.starts_with("HTTP/1.1 200") { return Err("connect to proxy error".into()); }
                Ok(stream)
            }
            Proxy::Socks5(addr) => {
                let mut stream = self.create_async(addr.to_string(), timeout).await?;
                stream.write(&[5, 1, 0]).await?;
                stream.flush().await?;
                let mut buf = [0; 2];
                let len = stream.read(&mut buf).await?;
                if len != 2 { return Err("socks5 handshake fail".into()); }
                let mut data = vec![5, 1, 0, 3];
                data.push(peer_addr.host().len() as u8);
                data.extend_from_slice(peer_addr.host().as_bytes());
                data.extend(peer_addr.port().to_be_bytes());
                stream.write(&data).await?;
                stream.flush().await?;
                let mut buf = [0; 256];
                let len = stream.read(&mut buf).await?;
                if len == 0 { return Err("connection closed by proxy".into()); }
                Ok(stream)
            }
        }
    }
}

impl Display for Proxy {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Proxy::Null => f.write_str(""),
            Proxy::HttpPlain(addr) => f.write_str(&addr.to_string()),
            Proxy::Socks5(addr) => f.write_str(&addr.to_string()),
        }
    }
}

impl TryFrom<&str> for Proxy {
    type Error = HlsError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let url = Url::try_from(value)?;
        match url.protocol() {
            Protocol::Http => Ok(Proxy::HttpPlain(url.addr().clone())),
            Protocol::Socks5 => Ok(Proxy::Socks5(url.addr().clone())),
            _ => Err("unsupported proxy scheme".into())
        }
    }
}

impl TryFrom<String> for Proxy {
    type Error = HlsError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Proxy::try_from(value.as_str())
    }
}