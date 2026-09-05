use crate::error::{HlsError, HlsResult};
use crate::stream::connect::{ProxyConnecting, ProxyState};
use crate::stream::read::BufReading;
use crate::*;
use std::fmt::{Display, Formatter};
use std::io;
use std::io::Read;
use std::net::SocketAddr;
use std::net::{IpAddr, Shutdown};
#[cfg(feature = "aync")]
use std::pin::Pin;
use std::str::FromStr;
#[cfg(feature = "aync")]
use std::task::{Context, Poll};
#[cfg(feature = "aync")]
use tokio::io::AsyncRead;
#[cfg(feature = "aync")]
use tokio::io::ReadBuf;

#[derive(Clone, Debug)]
pub enum Proxy {
    Null,
    HttpPlain(Url),
    Socks5(Url),
}

impl Proxy {
    pub fn new_http_plain(host: impl ToString, port: u16) -> Proxy {
        let mut url = Url::default();
        url.set_addr(Addr::new_addr(host, port));
        url.set_scheme(Scheme::Http);
        Proxy::HttpPlain(url)
    }

    pub fn new_socks5(host: impl ToString, port: u16) -> Proxy {
        let mut url = Url::default();
        url.set_addr(Addr::new_addr(host, port));
        url.set_scheme(Scheme::Socks5);
        Proxy::Socks5(url)
    }

    pub(crate) fn write_context(&self, peer_addr: &Addr, writer: &mut Writer, index: usize) -> HlsResult<bool> {
        match self {
            Proxy::Null => return Ok(true),
            Proxy::HttpPlain(v) => {
                let peer_addr = peer_addr.to_string();
                //line1
                writer.write_slice(b"CONNECT ")?;
                writer.write_slice(peer_addr.as_bytes())?;
                writer.write_slice(b" HTTP/1.1\r\n")?;
                //line2
                writer.write_slice(b"Host: ")?;
                writer.write_slice(peer_addr.as_bytes())?;
                writer.write_slice(b"\r\n")?;
                if !v.username().is_empty() && !v.password().is_empty() {
                    writer.write_slice(b"Proxy-Authorization: Basic ")?;
                    let auth = base64::b64encode(format!("{}:{}", v.username(), v.password()))?;
                    writer.write_slice(auth.as_bytes())?;
                    writer.write_slice(b"\r\n")?;
                }
                //line3
                writer.write_slice(b"Proxy-Connection: Keep-Alive\r\n\r\n")?;
                return Ok(true);
            }
            Proxy::Socks5(v) => {
                if index == 0 {
                    if v.username().is_empty() || v.password().is_empty() {
                        //认证方法-无认证
                        writer.write_slice(&[5, 1, 0])?;
                    } else {
                        //认证方法-账号密码
                        writer.write_slice(&[5, 1, 2])?;
                    }
                }
                if index == 1 {
                    if v.username().is_empty() || v.password().is_empty() {
                        //认证方法-无认证
                        // index = 2;
                    } else {
                        //认证方法-账号密码
                        writer.write_u8(1)?;
                        writer.write_u8(v.username().len() as u8)?;
                        writer.write_slice(v.username().as_bytes())?;
                        writer.write_u8(v.password().len() as u8)?;
                        writer.write_slice(v.password().as_bytes())?;
                    }
                }
                if index == 2 {
                    writer.write_slice(&[5, 1, 0])?;
                    if let Ok(addr) = IpAddr::from_str(peer_addr.host()) {
                        writer.write_u8(1)?;
                        match addr {
                            IpAddr::V4(v4) => writer.write_slice(&v4.octets())?,
                            IpAddr::V6(v6) => writer.write_slice(&v6.octets())?,
                        }
                    } else {
                        writer.write_u8(3)?;
                        writer.write_u8(peer_addr.host().len() as u8)?;
                        writer.write_slice(peer_addr.host().as_bytes())?;
                    }
                    writer.write_u16(peer_addr.port())?;
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Proxy::Null)
    }

    pub fn socket_addr(&self, peer_addr: &Addr, ech: bool) -> HlsResult<SocketAddr> {
        match self {
            Proxy::Null => Ok(peer_addr.socket_addr(ech)?),
            Proxy::HttpPlain(url) => Ok(url.addr().socket_addr(ech)?),
            Proxy::Socks5(url) => Ok(url.addr().socket_addr(ech)?),
        }
    }
}

impl Display for Proxy {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Proxy::Null => f.write_str("Null"),
            Proxy::HttpPlain(url) => write!(f, "HttpPlain({})", url),
            Proxy::Socks5(url) => write!(f, "Socks5({})", url),
        }
    }
}

impl TryFrom<&str> for Proxy {
    type Error = HlsError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let url = Url::try_from(value)?;
        match url.protocol() {
            Scheme::Http => Ok(Proxy::HttpPlain(url)),
            Scheme::Socks5 => Ok(Proxy::Socks5(url)),
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

pub struct ProxyStream<S> {
    pub(crate) stream: S,
    pub(crate) handle_proxy: bool,
    pub(crate) http_proxy: bool,
    pub(crate) buffer: Writer,
    pub(crate) resp: Response,
    #[cfg(feature = "aync")]
    pub(crate) timeout: Timeout,
}

impl<S> ProxyStream<S> {
    pub fn connect<'a>(stream: S, addr: &'a Addr, proxy: &'a Proxy, mut timeout: Timeout) -> ProxyConnecting<'a, S> {
        timeout.reset_connect();
        ProxyConnecting {
            state: ProxyState::Connecting {
                stream,
                timeout,
                buffer: Writer::with_capacity(1024),
            },
            proxy,
            dst_addr: addr,
            #[cfg(feature = "aync")]
            index: 0,
            #[cfg(feature = "aync")]
            finish: false,
        }
    }
}


impl ProxyStream<std::net::TcpStream> {
    // fn create_sync(addr: &SocketAddr, timeout: &Timeout) -> HlsResult<std::net::TcpStream> {
    //     let stream = std::net::TcpStream::connect_timeout(addr, timeout.connect())?;
    //     stream.set_read_timeout(Some(timeout.read()))?;
    //     stream.set_write_timeout(Some(timeout.write()))?;
    //     Ok(stream)
    // }
    // pub fn sync_connect(proxy: &Proxy, peer_addr: &Addr, timeout: &Timeout, ech: bool) -> HlsResult<ProxyStream<std::net::TcpStream>> {
    //     #[cfg(feature = "log")]
    //     debug!("[ProxyStream] Proxy: {} | PeerAddr: {}",proxy,peer_addr);
    //     let addr = proxy.socket_addr(peer_addr, ech)?;
    //     let mut stream = ProxyStream::create_sync(&addr, timeout)?;
    //     let mut buffer = Buffer::with_capacity(1024);
    //     for i in 0..4 {
    //         buffer.reset();
    //         let finish = proxy.write_context(peer_addr, &mut buffer, i)?;
    //         if buffer.is_empty() { continue; }
    //         io::Write::write_all(&mut stream, buffer.filled())?;
    //         if finish { break; }
    //     }
    //     buffer.reset();
    //     Ok(ProxyStream {
    //         stream,
    //         handle_proxy: matches!(proxy,Proxy::Null),
    //         http_proxy: matches!(proxy, Proxy::HttpPlain(_)),
    //         buffer,
    //         resp: Response::new(),
    //         #[cfg(feature = "aync")]
    //         timeout: timeout.clone(),
    //     })
    // }

    pub fn shutdown(&mut self) -> HlsResult<()> {
        self.stream.shutdown(Shutdown::Both)?;
        Ok(())
    }
}

impl Read for ProxyStream<std::net::TcpStream> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.handle_proxy {
            self.handle_proxy = true;
            self.buffer.reset();
            if self.http_proxy {
                loop {
                    BufReading {
                        stream: &mut self.stream,
                        want_size: self.buffer.len() + 1,
                        buf: &mut self.buffer,
                        #[cfg(feature = "aync")]
                        timeout: &mut self.timeout,
                    }.wait()?;
                    if self.resp.extend_buffer(&mut self.buffer)? { break; }
                }
                let status = self.resp.header().status().code();
                if status != 200 { return Err(io::Error::other(format!("connect http proxy error-{}", status))); }
            } else {
                BufReading {
                    stream: &mut self.stream,
                    buf: &mut self.buffer,
                    want_size: 12,
                    #[cfg(feature = "aync")]
                    timeout: &mut self.timeout,
                }.wait()?;
                if self.buffer.filled().starts_with(&[5, 2]) {
                    if self.buffer.filled()[3] != 0 { return Err(io::Error::other("socks5 auth fail")); }
                    self.buffer.used_empty(2);
                }
                self.buffer.used_empty(2);
                self.buffer.used_empty(10);
            }
            return Ok(0);
        }
        if !self.buffer.is_empty() {
            buf[..self.buffer.len()].copy_from_slice(self.buffer.filled());
            let len = self.buffer.len();
            self.buffer.reset();
            return Ok(len);
        }
        self.stream.read(buf)
    }
}

impl io::Write for ProxyStream<std::net::TcpStream> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if !self.handle_proxy { Read::read(self, &mut [])?; }
        io::Write::write(&mut self.stream, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        io::Write::flush(&mut self.stream)
    }
}

// #[cfg(feature = "aync")]
// impl ProxyStream<tokio::net::TcpStream> {
//     pub async fn async_connect(proxy: &Proxy, peer_addr: &Addr, timeout: &Timeout, ech: bool) -> HlsResult<ProxyStream<tokio::net::TcpStream>> {
//         #[cfg(feature = "log")]
//         debug!("[ProxyStream] Proxy: {} | PeerAddr: {}",proxy,peer_addr);
//         // let st = Time::now_mills();
//         let addr = proxy.socket_addr(peer_addr, ech)?;
//         // println!("DNS TIME: {}", Time::now_mills() - st);
//         let mut stream = tokio::net::TcpStream::connect(addr).await?;
//         let mut buffer = Buffer::with_capacity(1024);
//         for i in 0..4 {
//             buffer.reset();
//             let finish = proxy.write_context(peer_addr, &mut buffer, i)?;
//             if buffer.is_empty() { continue; }
//             tokio::io::AsyncWriteExt::write_all(&mut stream, buffer.filled()).await?;
//             if finish { break; }
//         }
//         buffer.reset();
//         Ok(ProxyStream {
//             stream,
//             handle_proxy: matches!(proxy,Proxy::Null),
//             http_proxy: matches!(proxy, Proxy::HttpPlain(_)),
//             buffer,
//             resp: Response::new(),
//             timeout: timeout.clone(),
//         })
//     }
// }

#[cfg(feature = "aync")]
impl AsyncRead for ProxyStream<tokio::net::TcpStream> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let stream = self.get_mut();
        if !stream.handle_proxy {
            if stream.http_proxy {
                loop {
                    let mut reader = BufReading {
                        stream: &mut stream.stream,
                        want_size: stream.buffer.len() + 1,
                        buf: &mut stream.buffer,
                        timeout: &mut stream.timeout,
                    };
                    match Pin::new(&mut reader).poll(cx)? {
                        Poll::Ready(_) => if stream.resp.extend_buffer(&mut stream.buffer)? { break; },
                        Poll::Pending => return Poll::Pending,
                    }
                }
                let status = stream.resp.header().status();
                if status.code() != 200 { return Poll::Ready(Err(io::Error::other(format!("connect http proxy fail-{:?}", status)))); }
            } else {
                let mut reader = BufReading {
                    stream: &mut stream.stream,
                    want_size: 12,
                    buf: &mut stream.buffer,
                    timeout: &mut stream.timeout,
                };
                match Pin::new(&mut reader).poll(cx)? {
                    Poll::Ready(_) => {
                        if stream.buffer.filled()[1] == 2 {
                            if stream.buffer.filled()[3] == 0 {
                                if stream.buffer.len() >= 14 {
                                    stream.buffer.used_empty(14);
                                }
                            } else { return Poll::Ready(Err(io::Error::other("socks5 auth fail"))); }
                        } else if stream.buffer.len() >= 12 {
                            stream.buffer.used_empty(12);
                        }
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
            stream.handle_proxy = true;
            return Poll::Ready(Ok(()));
        }
        if !stream.buffer.is_empty() {
            buf.put_slice(stream.buffer.filled());
            stream.buffer.reset();
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut stream.stream).poll_read(cx, buf)
    }
}

#[cfg(feature = "aync")]
impl tokio::io::AsyncWrite for ProxyStream<tokio::net::TcpStream> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
        if !self.handle_proxy {
            match self.as_mut().poll_read(cx, &mut ReadBuf::new(&mut [])) {
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
        }
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
