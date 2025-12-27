use crate::error::HlsResult;
use rustls::pki_types::{DnsName, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::Arc;
use crate::alpn::ALPN;
use crate::stream::ConnParam;

pub struct StdSyncTlsStream {
    stream: StreamOwned<ClientConnection, TcpStream>,
}


impl StdSyncTlsStream {
    pub fn connect(param: ConnParam, mut stream: TcpStream) -> HlsResult<StdSyncTlsStream> {
        let dns_name = DnsName::try_from(param.url.addr().host().to_string())?;
        let server_name = ServerName::DnsName(dns_name);
        let mut root = RootCertStore::empty();
        root.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut config = ClientConfig::builder()
            .with_root_certificates(root)
            .with_no_client_auth();
        if let ALPN::Http20 = param.alpn {
            config.alpn_protocols = vec![
                ALPN::Http20.value(),
                ALPN::Http11.value(),
                ALPN::Http10.value(),
            ];
        }

        let mut conn = ClientConnection::new(Arc::new(config), server_name)?;
        conn.complete_io(&mut stream)?;
        Ok(StdSyncTlsStream { stream: StreamOwned::new(conn, stream) })
    }

    pub fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.read(buf)
    }

    pub fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stream.write(buf)
    }

    pub fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }

    pub fn shutdown(&mut self) -> std::io::Result<()> {
        self.stream.conn.send_close_notify();
        self.stream.conn.complete_io(&mut self.stream.sock)?;
        self.stream.sock.shutdown(Shutdown::Both)
    }

    pub fn alpn(&self) -> Option<ALPN> {
        match self.stream.conn.alpn_protocol() {
            None => None,
            Some(alpn) => Some(ALPN::from_slice(alpn)),
        }
    }
}

// impl Read for StdSyncTlsStream {
//     fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
//         self.stream.read(buf)
//     }
// }
//
// impl Write for StdSyncTlsStream {
//     fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
//         self.stream.write(buf)
//     }
//
//     fn flush(&mut self) -> std::io::Result<()> {
//         self.stream.flush()
//     }
// }