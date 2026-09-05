use crate::error::HlsResult;
use crate::stream::http1::*;
use crate::stream::http2::*;
use crate::stream::write::BufWriting;
use crate::stream::{HTTPStream, Stream};
use crate::*;
#[cfg(feature = "aync")]
use std::future::Future;
use std::io::{Read, Write};
use std::ops::{Deref, DerefMut};
#[cfg(feature = "aync")]
use std::pin::Pin;
#[cfg(feature = "aync")]
use std::task::{Context, Poll};
use std::mem;
#[cfg(feature = "aync")]
use tokio::io::{AsyncRead, AsyncWrite};

pub(crate) enum ConnState<S> {
    Connecting(Box<TlsStream<S>>),
    Connected,
}

impl<S> ConnState<S> {
    pub(super) fn take(&mut self) -> TlsStream<S> {
        let state = mem::replace(self, ConnState::Connected);
        match state {
            ConnState::Connecting(stream) => *stream,
            ConnState::Connected => unreachable!(),
        }
    }
}

impl<S> Deref for ConnState<S> {
    type Target = TlsStream<S>;

    fn deref(&self) -> &Self::Target {
        match self {
            ConnState::Connecting(stream) => stream,
            ConnState::Connected => unreachable!()
        }
    }
}

impl<S> DerefMut for ConnState<S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            ConnState::Connecting(stream) => stream,
            ConnState::Connected => unreachable!()
        }
    }
}

pub struct TlsConnecting<'a, S> {
    pub(super) sent_client_hello: bool,
    pub(super) config: Config<'a>,
    pub(crate) state: ConnState<S>,
    pub(super) app_buf: Writer,
}

impl<'a, S: Read + Write> TlsConnecting<'a, S> {
    pub fn wait(mut self) -> HlsResult<TlsStream<S>> {
        let tls_stream = self.state.deref_mut();
        if !self.sent_client_hello {
            tls_stream.handle_client_hello(self.config.client_mut().ok_or("missing config")?)?;
            self.sent_client_hello = true;
        }
        let mut stream = loop {
            tls_stream.write_buffer().wait()?;
            if tls_stream.handshake_finished && tls_stream.write_buffer.is_empty() { break self.state.take(); }
            let record_len = tls_stream.read_next_record().wait()?;
            tls_stream.handle_record(record_len, Some(&mut self.config), self.app_buf.unfilled())?;
            tls_stream.read_buffer.used_empty(record_len);
        };
        if stream.conn.version() == &Version::TLS_1_3 { stream.conn.make_cipher(false)?; }
        Ok(stream)
    }
}

#[cfg(feature = "aync")]
impl<'a, S: AsyncRead + AsyncWrite + Unpin> Future for TlsConnecting<'a, S> {
    type Output = HlsResult<TlsStream<S>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let connector = self.get_mut();
        if !connector.sent_client_hello {
            if connector.state.write_buffer.is_empty() {
                connector.state.handle_client_hello(connector.config.client_mut().ok_or("missing config")?)?;
            }
            connector.sent_client_hello = true;
        }
        let mut stream = loop {
            if !connector.state.write_buffer.is_empty() {
                let mut writer = connector.state.write_buffer();
                if Pin::new(&mut writer).poll(cx)?.is_pending() {
                    connector.state.timeout.connect_timeout()?;
                    return Poll::Pending;
                }
            }
            if connector.state.handshake_finished && connector.state.write_buffer.is_empty() {
                break connector.state.take();
            }
            let mut reader = connector.state.read_next_record();
            let record_len = match Pin::new(&mut reader).poll(cx)? {
                Poll::Ready(len) => len,
                Poll::Pending => {
                    connector.state.timeout.connect_timeout()?;
                    return Poll::Pending;
                }
            };
            connector.state.handle_record(record_len, Some(&mut connector.config), connector.app_buf.unfilled())?;
            connector.state.read_buffer.used_empty(record_len);
        };
        if stream.conn.version() == &Version::TLS_1_3 { stream.conn.make_cipher(false)?; }
        Poll::Ready(Ok(stream))
    }
}

pub enum ProxyState<S> {
    Connecting {
        stream: S,
        timeout: Timeout,
        buffer: Writer,
    },
    Finish,
}

pub struct ProxyConnecting<'a, S> {
    pub(crate) state: ProxyState<S>,
    pub(crate) proxy: &'a Proxy,
    pub(crate) dst_addr: &'a Addr,
    #[cfg(feature = "aync")]
    pub(crate) index: usize,
    #[cfg(feature = "aync")]
    pub(crate) finish: bool,
}

impl<'a, S: Write> ProxyConnecting<'a, S> {
    pub fn wait(mut self) -> HlsResult<ProxyStream<S>> {
        let (mut stream, mut buffer, mut timeout) = match mem::replace(&mut self.state, ProxyState::Finish) {
            ProxyState::Connecting { stream, buffer, timeout } => (stream, buffer, timeout),
            ProxyState::Finish => unreachable!(),
        };
        timeout.reset_connect();
        for i in 0..4 {
            let finish = self.proxy.write_context(self.dst_addr, &mut buffer, i)?;
            BufWriting {
                stream: &mut stream,
                buf: &mut buffer,
                #[cfg(feature = "aync")]
                timeout: &mut timeout,
            }.wait()?;
            if finish { break; }
        }
        Ok(ProxyStream {
            stream,
            handle_proxy: matches!(self.proxy,  Proxy::Null),
            http_proxy: matches!(self.proxy, Proxy::HttpPlain(_)),
            buffer,
            resp: Response::new(),
            #[cfg(feature = "aync")]
            timeout,
        })
    }
}

#[cfg(feature = "aync")]
impl<'a, S: AsyncWrite + Unpin> Future for ProxyConnecting<'a, S> {
    type Output = HlsResult<ProxyStream<S>>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let connector = self.get_mut();
        let (stream, buffer, timeout) = match &mut connector.state {
            ProxyState::Connecting { stream, buffer, timeout } => (stream, buffer, timeout),
            ProxyState::Finish => unreachable!(),
        };
        for i in 0..4 {
            if i < connector.index { continue; }
            let finish = if buffer.is_empty() {
                connector.proxy.write_context(connector.dst_addr, buffer, i)?
            } else { connector.finish };
            let mut writing = BufWriting {
                stream,
                buf: buffer,
                timeout,
            };
            match Pin::new(&mut writing).poll(cx)? {
                Poll::Ready(_) => if finish { break; },
                Poll::Pending => return Poll::Pending,
            }
        }
        let (stream, buffer, timeout) = match mem::replace(&mut connector.state, ProxyState::Finish) {
            ProxyState::Connecting { stream, buffer, timeout } => (stream, buffer, timeout),
            ProxyState::Finish => unreachable!(),
        };
        Poll::Ready(Ok(ProxyStream {
            stream,
            handle_proxy: matches!(connector.proxy,  Proxy::Null),
            http_proxy: matches!(connector.proxy, Proxy::HttpPlain(_)),
            buffer,
            resp: Response::new(),
            timeout,
        }))
    }
}


pub struct StreamConnect<'a, S> {
    pub(crate) url: &'a Url,
    pub(crate) fingerprint: &'a Fingerprint,
    pub(crate) proxy_connecting: ProxyConnecting<'a, S>,
    pub(crate) tls_connecting: TlsConnecting<'a, ProxyStream<S>>,
    #[cfg(feature = "aync")]
    pub(crate) proxy_connected: bool,
    #[cfg(feature = "aync")]
    pub(crate) stream: Stream,
    #[cfg(feature = "aync")]
    pub(crate) buffer: Writer,
    #[cfg(feature = "aync")]
    pub(crate) tls_connected: bool,
}

impl<'a> StreamConnect<'a, std::net::TcpStream> {
    pub fn wait(mut self) -> HlsResult<(ALPN, HTTPStream)> {
        let proxy_stream = self.proxy_connecting.wait()?;
        match self.url.scheme() {
            Scheme::Http | Scheme::Ws => {
                let stream = HTTPStream::SyncH1(HTTP1StreamS::new(Stream::SyncHttp(proxy_stream)));
                Ok((ALPN::Http11, stream))
            }
            Scheme::Https | Scheme::Wss => {
                let config = self.tls_connecting.config.client_mut().ok_or("missing client config")?;
                config.fingerprint = self.fingerprint.tls();
                let session = config.session.as_ref().cloned().unwrap_or_default();
                let conn = Connection::new_client(session, mem::take(&mut config.key_log), false)
                    .with_verify(config.verify).with_mtls(!config.client_cert.is_empty());
                self.tls_connecting.state = ConnState::Connecting(Box::new(TlsStream::new(conn, proxy_stream)));
                let tls_stream = self.tls_connecting.wait()?;
                let alpn = tls_stream.alpn().cloned().unwrap_or(ALPN::Http11);
                let stream = match alpn {
                    ALPN::Http20 => HTTPStream::SyncH2(HTTP2StreamS::new(Stream::SyncHttps(tls_stream), self.fingerprint)?),
                    _ => HTTPStream::SyncH1(HTTP1StreamS::new(Stream::SyncHttps(tls_stream)))
                };
                Ok((alpn, stream))
            }
            _ => Err("stream not supported".into())
        }
    }
}

#[cfg(feature = "aync")]
impl<'a> Future for StreamConnect<'a, tokio::net::TcpStream> {
    type Output = HlsResult<(ALPN, HTTPStream)>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let connector = self.get_mut();
        if !connector.proxy_connected {
            let proxy_stream = match Pin::new(&mut connector.proxy_connecting).poll(cx)? {
                Poll::Ready(proxy_stream) => proxy_stream,
                Poll::Pending => return Poll::Pending,
            };
            match connector.url.scheme() {
                Scheme::Http | Scheme::Ws => {
                    let stream = HTTPStream::AsyncH1(HTTP1StreamA::new(Stream::AsyncHttp(proxy_stream)));
                    return Poll::Ready(Ok((ALPN::Http11, stream)));
                }
                Scheme::Https | Scheme::Wss => {
                    let config = connector.tls_connecting.config.client_mut().ok_or("missing client config")?;
                    config.fingerprint = connector.fingerprint.tls();
                    let session = config.session.as_ref().cloned().unwrap_or_default();
                    let conn = Connection::new_client(session, mem::take(&mut config.key_log), false)
                        .with_verify(config.verify).with_mtls(!config.client_cert.is_empty());
                    connector.tls_connecting.state = ConnState::Connecting(Box::new(TlsStream::new(conn, proxy_stream)));
                    connector.proxy_connected = true;
                    let mut buffer = Writer::with_capacity(24657);
                    buffer.write_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")?;
                    connector.fingerprint.h2().build_setting().write_to(&mut buffer)?;
                    connector.fingerprint.h2().build_window_update().write_to(&mut buffer)?;
                    connector.buffer = buffer;
                }
                _ => return Poll::Ready(Err("stream not supported".into()))
            }
        };
        if !connector.tls_connected {
            match Pin::new(&mut connector.tls_connecting).poll(cx)? {
                Poll::Ready(tls_stream) => {
                    let alpn = tls_stream.alpn().cloned().unwrap_or(ALPN::Http11);
                    if alpn != ALPN::Http20 {
                        return Poll::Ready(Ok((ALPN::Http11, HTTPStream::AsyncH1(HTTP1StreamA::new(Stream::AsyncHttps(tls_stream))))));
                    }
                    connector.stream = Stream::AsyncHttps(tls_stream);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        let mut writer = connector.stream.write(&mut connector.buffer);
        match Pin::new(&mut writer).poll(cx)? {
            Poll::Ready(_) => {
                let stream = mem::replace(&mut connector.stream, Stream::NonConnection);
                let buffer = mem::replace(&mut connector.buffer, Writer::none());
                Poll::Ready(Ok((ALPN::Http20, HTTPStream::AsyncH2(HTTP2StreamA::new(stream, buffer)))))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}