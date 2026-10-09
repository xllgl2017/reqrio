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
    pub(super) sent_server_hello: bool,
    pub(super) config: Config<'a>,
    pub(crate) state: ConnState<S>,
    pub(super) app_buf: Writer,
    #[cfg(feature = "aync")]
    pub(super) timeout_reset: bool,
}

impl<'a, S> TlsConnecting<'a, S> {
    fn gen_server(&mut self) -> HlsResult<bool> {
        if self.sent_server_hello || self.state.conn.alpn().is_empty() { return Ok(false); }
        let Config::Server(ref mut config) = self.config else { return Ok(false) };
        self.sent_server_hello = true;
        let tls_stream = self.state.deref_mut();
        let mut certificates = Certificates::default();
        for certificate in config.server_cert.iter_mut() {
            certificates.add_certificate(certificate.as_der()?.as_slice());
        }
        match tls_stream.conn.version() {
            Version::TLS_1_2 | Version::TLCP => {
                tls_stream.write_buffer.write_u8(RecordType::ApplicationData.as_u8())?;
                tls_stream.write_buffer.write_u16(Version::TLS_1_2.into_inner())?;
                let start = tls_stream.write_buffer.end();
                tls_stream.write_buffer.write_u16(0)?;
                tls_stream.write_buffer.filled_mut()[0] = RecordType::HandShake.as_u8();
                certificates.write_to(&mut tls_stream.write_buffer, tls_stream.conn.version())?;
                tls_stream.conn.gen_server_hello(&mut tls_stream.write_buffer, config.cert_key)?;
                tls_stream.write_buffer.write_u16_in(3, (tls_stream.write_buffer.len() - 5) as u16)?;
                tls_stream.conn.update_session(&tls_stream.write_buffer.filled()[5..])?;
                tls_stream.write_buffer.write_u16_in(start, (tls_stream.write_buffer.end() - start - 2) as u16)?;
            }
            _ => {
                let writer = &mut self.app_buf;
                writer.write_u8(HandshakeType::EncryptedExtensions.into_inner())?;
                writer.write_u24(2)?;
                writer.write_u16(0)?;
                certificates.write_to(writer, tls_stream.conn.version())?;
                tls_stream.conn.gen_server_hello(writer, config.cert_key)?;
                let len = tls_stream.conn.make_message(RecordType::HandShake, writer.filled(), tls_stream.write_buffer.unfilled())?;
                tls_stream.write_buffer.add_len(len);
            }
        };

        Ok(true)
    }
}

impl<'a, S: Read + Write> TlsConnecting<'a, S> {
    pub fn wait(mut self) -> HlsResult<TlsStream<S>> {
        let mut tls_stream = self.state.deref_mut();
        if !self.sent_client_hello {
            tls_stream.build_client_hello(self.config.client_mut().ok_or(HandShakeError::MissingClientConfig)?)?;
            self.sent_client_hello = true;
        }
        let mut stream = loop {
            tls_stream.write_buffer().wait()?;
            if self.gen_server()? {
                tls_stream = self.state.deref_mut();
                continue;
            }
            tls_stream = self.state.deref_mut();
            if tls_stream.handshake_finished && tls_stream.write_buffer.is_empty() { break self.state.take(); }
            let record_len = tls_stream.read_next_record().wait()?;
            tls_stream.handle_record(record_len, Some(&mut self.config), self.app_buf.unfilled())?;
            tls_stream.read_buffer.used_empty(record_len);
        };
        if stream.conn.version() == Version::TLS_1_3 { stream.conn.make_cipher(false)?; }
        Ok(stream)
    }
}

#[cfg(feature = "aync")]
impl<'a, S: AsyncRead + AsyncWrite + Unpin> Future for TlsConnecting<'a, S> {
    type Output = HlsResult<TlsStream<S>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let connector = self.get_mut();
        if !connector.timeout_reset {
            connector.timeout_reset = true;
            connector.state.timeout.reset_connect();
        }
        if !connector.sent_client_hello {
            if connector.state.write_buffer.is_empty() {
                connector.state.build_client_hello(connector.config.client_mut().ok_or(HandShakeError::MissingClientConfig)?)?;
            }
            connector.sent_client_hello = true;
        }
        let mut stream = loop {
            if !connector.state.write_buffer.is_empty() {
                let mut writer = connector.state.write_buffer();
                if Pin::new(&mut writer).poll(cx)?.is_pending() {
                    connector.state.timeout.connect_timeout(cx)?;
                    return Poll::Pending;
                }
            }
            if connector.gen_server()? { continue; }
            if connector.state.handshake_finished && connector.state.write_buffer.is_empty() {
                break connector.state.take();
            }
            let mut reader = connector.state.read_next_record();
            let record_len = match Pin::new(&mut reader).poll(cx)? {
                Poll::Ready(len) => len,
                Poll::Pending => {
                    connector.state.timeout.connect_timeout(cx)?;
                    return Poll::Pending;
                }
            };
            connector.state.handle_record(record_len, Some(&mut connector.config), connector.app_buf.unfilled())?;
            connector.state.read_buffer.used_empty(record_len);
        };
        if stream.conn.version() == Version::TLS_1_3 { stream.conn.make_cipher(false)?; }
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
    #[cfg(feature = "aync")]
    pub(crate) timeout_reset: bool,
}

impl<'a, S: Write> ProxyConnecting<'a, S> {
    pub fn wait(mut self) -> HlsResult<ProxyStream<S>> {
        #[allow(unused)]
        let (mut stream, mut buffer, mut timeout) = match mem::replace(&mut self.state, ProxyState::Finish) {
            ProxyState::Connecting { stream, buffer, timeout } => (stream, buffer, timeout),
            ProxyState::Finish => unreachable!(),
        };
        for i in 0..4 {
            let finish = self.proxy.write_context(self.dst_addr, &mut buffer, i)?;
            BufWriting {
                stream: &mut stream,
                buf: &mut buffer,
                #[cfg(feature = "aync")]
                timeout: &mut timeout,
                #[cfg(feature = "aync")]
                timeout_reset: false,
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
        if !connector.timeout_reset {
            timeout.reset_connect();
            connector.timeout_reset = true;
        }
        for i in 0..4 {
            if i < connector.index { continue; }
            let finish = if buffer.is_empty() {
                connector.proxy.write_context(connector.dst_addr, buffer, i)?
            } else { connector.finish };
            let mut writing = BufWriting {
                stream,
                buf: buffer,
                timeout,
                timeout_reset: false,
            };
            match Pin::new(&mut writing).poll(cx)? {
                Poll::Ready(_) => if finish { break; },
                Poll::Pending => {
                    timeout.connect_timeout(cx)?;
                    return Poll::Pending;
                }
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
                Ok((ALPN::HTTP11, stream))
            }
            Scheme::Https | Scheme::Wss => {
                let config = self.tls_connecting.config.client_mut().ok_or("missing client config")?;
                config.fingerprint = self.fingerprint.tls();
                let session = config.session.as_ref().cloned().unwrap_or_default();
                let conn = Connection::new_client(session, mem::take(&mut config.key_log), false)
                    .with_verify(config.verify).with_mtls(!config.client_cert.is_empty());
                self.tls_connecting.state = ConnState::Connecting(Box::new(TlsStream::new(conn, proxy_stream, Timeout::longer())));
                let tls_stream = self.tls_connecting.wait()?;
                let alpn = tls_stream.alpn().clone();
                let stream = match &alpn {
                    h2 if h2 == ALPN::HTTP20 => HTTPStream::SyncH2(HTTP2StreamS::new(Stream::SyncHttps(tls_stream), self.fingerprint)?),
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
                    return Poll::Ready(Ok((ALPN::HTTP11, stream)));
                }
                Scheme::Https | Scheme::Wss => {
                    let config = connector.tls_connecting.config.client_mut().ok_or("missing client config")?;
                    config.fingerprint = connector.fingerprint.tls();
                    let session = config.session.as_ref().cloned().unwrap_or_default();
                    let conn = Connection::new_client(session, mem::take(&mut config.key_log), false)
                        .with_verify(config.verify).with_mtls(!config.client_cert.is_empty());
                    let timeout = proxy_stream.timeout.clone();
                    connector.tls_connecting.state = ConnState::Connecting(Box::new(TlsStream::new(conn, proxy_stream, timeout)));
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
                    let alpn = tls_stream.alpn().clone();
                    if alpn != ALPN::HTTP20 {
                        return Poll::Ready(Ok((ALPN::HTTP11, HTTPStream::AsyncH1(HTTP1StreamA::new(Stream::AsyncHttps(tls_stream))))));
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
                Poll::Ready(Ok((ALPN::HTTP20, HTTPStream::AsyncH2(HTTP2StreamA::new(stream, buffer)))))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}