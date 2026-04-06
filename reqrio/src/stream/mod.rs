#[cfg(feature = "aync")]
use crate::stream::aync::{TlsStreamA, TcpStreamA, TimeoutRW};
#[cfg(feature = "aync")]
pub use stream::aync::TlsStream;
use crate::stream::config::Config;
use crate::*;
pub use config::{ClientConfig, ServerConfig};
pub use proxy::Proxy;
pub use proxy::ProxyStream;
use std::io::Write;
pub use sync_stream::SyncStream;
pub use ws::{WebSocket, WebSocketBuilder};

#[cfg(feature = "aync")]
mod async_stream;

mod sync_stream;

mod proxy;
mod ws;
mod config;
mod aync;

pub struct ConnParam<'a> {
    pub scheme: &'a Scheme,
    pub addr: &'a Addr,
    pub proxy: &'a Proxy,
    pub timeout: &'a Timeout,
    pub fingerprint: &'a mut Fingerprint,
    pub alpn: &'a ALPN,
    pub verify: bool,
    pub cert: &'a mut Vec<Certificate>,
    pub key: &'a RsaKey,
    pub ca_cert: &'a Vec<Certificate>,
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

#[cfg(feature = "aync")]
impl Stream {
    pub async fn async_conn(&mut self, param: ConnParam<'_>) -> HlsResult<ALPN> {
        let _ = self.async_shutdown().await;
        let stream = tokio::time::timeout(param.timeout.connect(), ProxyStream::async_connect(param.proxy, param.addr)).await??;
        match param.scheme {
            Scheme::Http | Scheme::Ws => {
                *self = Stream::AsyncHttp(TcpStreamA::from_proxy_stream(stream, param.timeout));
                Ok(ALPN::Http11)
            }
            Scheme::Https | Scheme::Wss => {
                let tls_stream = TlsStreamA::connect_timeout(param, stream).await?;
                let alpn = tls_stream.alpn().cloned().unwrap_or(ALPN::Http11);
                *self = Stream::AsyncHttps(tls_stream);
                Ok(alpn)
            }
            _ => Err("stream not supported".into())
        }
    }


    pub async fn async_write(&mut self, buf: &[u8]) -> HlsResult<()> {
        match self {
            Stream::AsyncHttp(s) => {
                s.write(buf).await?;
                s.flush().await?;
                Ok(())
            }
            Stream::AsyncHttps(s) => {
                s.write(buf).await?;
                s.flush().await?;
                Ok(())
            }
            _ => Err("Unsupported aync write".into()),
        }
    }

    pub async fn async_read(&mut self, buffer: &mut Buffer) -> HlsResult<()> {
        match self {
            Stream::AsyncHttp(s) => s.read(buffer).await,
            Stream::AsyncHttps(s) => s.read(buffer).await,
            _ => Err("Unsupported aync read".into()),
        }
    }

    pub async fn async_shutdown(&mut self) -> HlsResult<()> {
        match self {
            Stream::AsyncHttp(s) => Ok(s.shutdown().await?),
            Stream::AsyncHttps(s) => Ok(s.shutdown().await?),
            _ => Err("Unsupported aync read".into()),
        }
    }
}

impl Stream {
    pub fn sync_conn(&mut self, param: ConnParam) -> HlsResult<ALPN> {
        let _ = self.sync_shutdown();
        let stream = ProxyStream::sync_connect(param.proxy, param.addr, param.timeout)?;
        match param.scheme {
            Scheme::Http | Scheme::Ws => {
                *self = Stream::SyncHttp(stream);
                Ok(ALPN::Http11)
            }
            Scheme::Https | Scheme::Wss => {
                let tls_stream = SyncStream::connect(ClientConfig {
                    sni: param.addr.host(),
                    alpn: param.alpn,
                    fingerprint: param.fingerprint,
                    client_cert: param.cert,
                    cert_key: param.key,
                    verify: param.verify,
                    ca_certs: param.ca_cert,
                }, stream)?;
                let alpn = tls_stream.alpn().map(|x| ALPN::from_slice(x.as_bytes())).unwrap_or(ALPN::Http11);
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
            Stream::SyncHttp(s) => buffer.sync_read(s),
            Stream::SyncHttps(s) => buffer.sync_read(s),
            _ => Err("Unsupported aync read".into()),
        }
    }

    pub fn sync_shutdown(&mut self) -> HlsResult<()> {
        match self {
            Stream::SyncHttp(s) => Ok(s.shutdown()?),
            Stream::SyncHttps(s) => Ok(s.shutdown()?),
            _ => Err("Unsupported aync read".into()),
        }
    }
}


pub trait TlsStreamHandle {
    fn conn_wbuf(&mut self) -> (&mut Connection, &mut Buffer);

    fn conn_rbuf(&mut self) -> (&mut Connection, &mut Buffer);

    fn handle_client_hello(&mut self, config: &mut ClientConfig) -> HlsResult<()> {
        let (conn, buffer) = self.conn_wbuf();
        let session_id = rand::random::<[u8; 32]>();
        let mut client_hello = RecordLayer::from_bytes(&mut config.fingerprint.client_hello, false, None)?;
        client_hello.messages[0].client_mut().ok_or(HlsError::NullPointer)?.set_random(conn.client_random());
        client_hello.messages[0].client_mut().ok_or(HlsError::NullPointer)?.set_server_name(config.sni);
        client_hello.messages[0].client_mut().ok_or(HlsError::NullPointer)?.set_session_id(&session_id);
        match config.alpn {
            ALPN::Http20 => client_hello.messages[0].client_mut().ok_or(HlsError::NullPointer)?.add_h2_alpn(),
            _ => client_hello.messages[0].client_mut().ok_or(HlsError::NullPointer)?.remove_h2_alpn()
        }
        client_hello.messages[0].client_mut().ok_or(HlsError::NullPointer)?.remove_tls13();
        let len = client_hello.write_to(buffer, 1)?;
        buffer.set_len(len);
        conn.update_session(&buffer.filled()[5..])?;
        Ok(())
    }

    fn handle_by_server_hello_done(&mut self, config: &mut Config) -> HlsResult<()> {
        let config = config.client_mut().ok_or("missing config")?;
        let (conn, buffer) = self.conn_wbuf();
        let offset = buffer.len();
        if conn.mtls() {
            //client certificate
            let mut certificate = Certificates::default();
            if let Some(cert) = config.client_cert.get_mut(0) {
                certificate.add_certificate(cert.as_der()?.as_slice());
            }
            let mut record = RecordLayer::handshake();
            record.messages.push(Message::Certificate(certificate));
            let len = record.write_to(buffer, 1)?;
            buffer.set_len(offset + len);
            conn.update_session(&buffer[offset + 5..offset + len])?;
        }
        let offset = buffer.len();
        //client key exchange
        let mut record = RecordLayer::from_bytes(&mut config.fingerprint.client_key_exchange, false, None)?;
        let client_key_exchange = record.messages.get_mut(0).ok_or(HlsError::NullPointer)?;
        let key_size = conn.cipher_suite().key_size();
        let pub_key = conn.pub_share_key()?;
        client_key_exchange.client_key_exchange_mut().unwrap().set_pub_key(pub_key.as_ref());
        let len = record.write_to(buffer, key_size)?;
        buffer.set_len(offset + len);
        conn.update_session(&buffer[offset + 5..offset + len])?;
        conn.make_cipher(false)?;
        //certificate verify
        if conn.mtls() && !config.client_cert.is_empty() {
            let offset = buffer.len();
            let len = conn.handle_mtls_client(buffer, config.cert_key)?;
            buffer.set_len(offset + len);
            conn.update_session(&buffer[offset + 5..offset + len])?;
        }
        buffer.write_slice(&config.fingerprint.change_cipher_spec)?;


        let record_len = conn.make_finish_message(buffer.unfilled_mut(), false)?;
        buffer.add_len(record_len);
        Ok(())
    }

    fn handle_by_alert(&mut self, handshake: bool, record_len: usize) -> Result<Alert, RlsError> {
        let (conn, buffer) = self.conn_rbuf();
        match handshake {
            true => {
                let mut out = vec![0; 40];
                let len = conn.read_message(&buffer[..record_len], &mut out)?;
                Ok(Alert::from_bytes(&out[..len])?)
            }
            false => Ok(Alert::from_bytes(&buffer[5..7])?)
        }
    }
}