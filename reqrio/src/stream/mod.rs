mod sync_stream;
mod proxy;
mod ws;
#[cfg(feature = "aync")]
mod aync;
#[cfg(feature = "aync")]
mod buffer;

use crate::*;
#[cfg(feature = "aync")]
pub use aync::*;
#[cfg(feature = "aync")]
pub use buffer::{ReadOffset, RecordBuffer};
pub use proxy::Proxy;
pub use proxy::ProxyStream;
use std::io::Write;
#[cfg(feature = "aync")]
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{env, io};
use std::pin::Pin;
use std::task::{Context, Poll};
pub use sync_stream::SyncStream;
#[cfg(feature = "aync")]
use tokio::io::{AsyncRead, AsyncReadExt, ReadHalf};
use tokio::sync::futures::Notified;
#[cfg(feature = "aync")]
use tokio::sync::mpsc::Sender;
use tokio::sync::Notify;
pub use ws::{WebSocket, WebSocketBuilder};


pub struct ConnParam<'a> {
    pub url: &'a Url,
    pub proxy: &'a Proxy,
    pub timeout: &'a Timeout,
    pub fingerprint: &'a mut Fingerprint,
    pub alpn: &'a ALPN,
    pub verify: bool,
    pub cert: &'a mut Vec<Certificate>,
    pub key: &'a RsaKey,
    pub ca_cert: &'a Vec<Certificate>,
    pub key_log: &'a Option<PathBuf>,
    pub ech: bool,
    pub session: &'a Option<TlsSession>,
}

impl<'a> From<ConnParam<'a>> for ClientConfig<'a> {
    fn from(param: ConnParam<'a>) -> Self {
        ClientConfig {
            sni: param.url.sni(),
            alpn: param.alpn,
            fingerprint: param.fingerprint.tls_mut(),
            client_cert: param.cert,
            cert_key: param.key,
            verify: param.verify,
            ca_certs: param.ca_cert,
            key_log: param.key_log.clone().or_else(|| match env::var("SSLKEYLOGFILE") {
                Ok(key_log) => Some(Path::new(&key_log).to_path_buf()),
                Err(_) => None
            }),
            session: param.session,
        }
    }
}

pub enum Stream {
    NonConnection,
    //同步
    SyncHttp(ProxyStream<std::net::TcpStream>),
    SyncHttps(SyncStream<ProxyStream<std::net::TcpStream>>),
    //异步
    #[cfg(feature = "aync")]
    AsyncHttp(TcpStreamA),
    #[cfg(feature = "aync")]
    AsyncHttps(TlsStreamA),
}

impl Stream {
    pub fn scheme(&self) -> Option<Scheme> {
        match self {
            Stream::NonConnection => None,
            Stream::SyncHttp(_) => Some(Scheme::Http),
            Stream::SyncHttps(_) => Some(Scheme::Https),
            #[cfg(feature = "aync")]
            Stream::AsyncHttp(_) => Some(Scheme::Http),
            #[cfg(feature = "aync")]
            Stream::AsyncHttps(_) => Some(Scheme::Https),
        }
    }

    pub fn tls_session(&self) -> Option<&TlsSession> {
        match self {
            Stream::SyncHttps(s) => Some(s.connection().session()),
            #[cfg(feature = "aync")]
            Stream::AsyncHttps(s) => Some(s.get_ref().connection().session()),
            _ => None
        }
    }
}

#[cfg(feature = "aync")]
impl Stream {
    pub async fn async_conn(&mut self, param: ConnParam<'_>) -> HlsResult<ALPN> {
        let _ = self.async_shutdown().await;
        // let st = Time::now_mills();
        let connect = ProxyStream::async_connect(param.proxy, param.url.addr(), param.ech);
        let stream = tokio::time::timeout(param.timeout.connect(), connect).await??;
        // println!("TCP TIME: {}", Time::now_mills() - st);
        match param.url.scheme() {
            Scheme::Http | Scheme::Ws => {
                *self = Stream::AsyncHttp(TcpStreamA::from_proxy_stream(stream, param.timeout));
                Ok(ALPN::Http11)
            }
            Scheme::Https | Scheme::Wss => {
                // let st = Time::now_mills();
                let tls_stream = TlsStreamA::connect_timeout(param, stream).await?;
                // println!("TLS TIME: {}", Time::now_mills() - st);
                let alpn = tls_stream.alpn().cloned().unwrap_or(ALPN::Http11);
                *self = Stream::AsyncHttps(tls_stream);
                Ok(alpn)
            }
            _ => Err("stream not supported".into())
        }
    }


    pub async fn async_write(&mut self, buf: &[u8]) -> HlsResult<()> {
        match self {
            Stream::AsyncHttp(s) => s.write_all(buf).await,
            Stream::AsyncHttps(s) => s.write_all(buf).await,
            _ => Err("Unsupported async write".into()),
        }
    }

    pub async fn async_read(&mut self, buffer: &mut Buffer) -> HlsResult<()> {
        match self {
            Stream::AsyncHttp(s) => s.read(buffer).await,
            Stream::AsyncHttps(s) => Ok(s.read(buffer).await?),
            _ => Err("Unsupported async read".into()),
        }
    }

    pub async fn async_shutdown(&mut self) -> HlsResult<()> {
        match self {
            Stream::AsyncHttp(s) => Ok(s.shutdown().await?),
            Stream::AsyncHttps(s) => Ok(s.shutdown().await?),
            _ => Err("Unsupported async read".into()),
        }
    }
}

impl Stream {
    pub fn sync_conn(&mut self, param: ConnParam) -> HlsResult<ALPN> {
        let _ = self.sync_shutdown();
        let stream = ProxyStream::sync_connect(param.proxy, param.url.addr(), param.timeout, param.ech)?;
        match param.url.scheme() {
            Scheme::Http | Scheme::Ws => {
                *self = Stream::SyncHttp(stream);
                Ok(ALPN::Http11)
            }
            Scheme::Https | Scheme::Wss => {
                let tls_stream = SyncStream::connect(ClientConfig::from(param), stream)?;
                let alpn = tls_stream.alpn().cloned().unwrap_or(ALPN::Http11);
                *self = Stream::SyncHttps(tls_stream);
                Ok(alpn)
            }
            _ => Err("stream not supported".into())
        }
    }

    pub fn sync_write(&mut self, buf: &[u8]) -> HlsResult<()> {
        match self {
            Stream::SyncHttp(s) => {
                s.write_all(buf)?;
                Ok(())
            }
            Stream::SyncHttps(s) => {
                s.write_all(buf)?;
                Ok(())
            }
            _ => Err("Unsupported sync write".into()),
        }
    }

    pub fn sync_read(&mut self, buffer: &mut Buffer) -> HlsResult<()> {
        match self {
            Stream::SyncHttp(stream) => {
                let len = io::Read::read(stream, buffer.unfilled())?;
                if len == 0 { return Err(HlsError::PeerClosedConnection); }
                buffer.add_len(len);
                Ok(())
            }
            Stream::SyncHttps(stream) => {
                let len = io::Read::read(stream, buffer.unfilled())?;
                if len == 0 { return Err(HlsError::PeerClosedConnection); }
                buffer.add_len(len);
                Ok(())
            }
            _ => Err("Unsupported async read".into()),
        }
    }

    pub fn sync_shutdown(&mut self) -> HlsResult<()> {
        match self {
            Stream::SyncHttp(s) => Ok(s.shutdown()?),
            Stream::SyncHttps(s) => Ok(s.shutdown()?),
            _ => Err("Unsupported async read".into()),
        }
    }
}

pub struct ReadRecord<'a, S: Send> {
    closed: &'a Arc<AtomicBool>,
    reader: &'a mut ReadHalf<S>,
    buffer: &'a mut RecordBuffer,
    notify: &'a Notify,
    notified: Notified<'a>,
}

impl<'a, S: Send> Future for ReadRecord<'a, S> {
    type Output = io::Result<Range<usize>>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}


#[cfg(feature = "aync")]
pub struct StreamRead<S: Send> {
    pub buffer: RecordBuffer,
    pub reader: ReadHalf<S>,
    pub sender: Sender<io::Result<ReadOffset>>,
    pub closed: Arc<AtomicBool>,
    pub notify: Arc<Notify>,
}

#[cfg(feature = "aync")]
impl<S: AsyncRead + Unpin + Send> StreamRead<S> {
    async fn read_size(&mut self, want_size: usize) -> HlsResult<()> {
        let current_size = self.buffer.current_size();
        if current_size >= want_size { return Ok(()); }
        let unfilled = self.buffer.unfilled_mut(want_size, current_size, self.notify.clone()).await;
        let mut filled_len = 0;
        let need_read_size = want_size - current_size;
        while filled_len < need_read_size {
            let len = self.reader.read(&mut unfilled[filled_len..]).await?;
            if len == 0 { return Err(HlsError::PeerClosedConnection); }
            filled_len += len;
        }
        self.buffer.add_filled(filled_len);
        Ok(())
    }


    async fn read_record_size(&mut self) -> HlsResult<usize> {
        if self.buffer.current_size() < 5 {
            self.read_size(23).await?;
        }
        Ok(self.buffer.next_record_len())
    }

    async fn read_record(&mut self) -> io::Result<Range<usize>> {
        // let record=ReadRecord{
        //     closed: &self.closed,
        //     reader: &mut self.reader,
        //     notified: self.notify.notified(),
        //     notify: &self.notify,
        //     buffer: &mut self.buffer,
        // }
        let record_len = self.read_record_size().await?;
        if self.buffer.current_size() < record_len {
            self.read_size(record_len).await?;
        }
        Ok(self.buffer.next_record_offset(record_len))
    }

    fn read_record2(&mut self) -> ReadRecord<'_, S> {
        ReadRecord {
            closed: &self.closed,
            reader: &mut self.reader,
            buffer: &mut self.buffer,
            notify: &self.notify,
            notified: self.notify.notified(),
        }
    }


    pub async fn run(&mut self) {
        loop {
            if self.closed.load(Ordering::SeqCst) { break; }
            match self.read_record().await {
                Ok(record_offset) => {
                    // println!("send: {:?}", record_offset);
                    let offset = ReadOffset::new(record_offset, &self.buffer, self.notify.clone());
                    let ret = self.sender.send(Ok(offset)).await;
                    if ret.is_err() { break; }
                }
                Err(e) => {
                    let _ = self.sender.send(Err(e)).await;
                    break;
                }
            }
        }
        println!("stream closed");
    }
}


