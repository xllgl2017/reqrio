use crate::{Certificate, NamedCurve, RsaKey, TlsFinger, TlsSession, Version, ALPN};
use std::sync::Arc;

pub enum Config<'a> {
    Server(ServerConfig<'a>),
    Client(ClientConfig<'a>),
}

impl<'a> Config<'a> {
    pub fn client_mut(&mut self) -> Option<&mut ClientConfig<'a>> {
        match self {
            Config::Server(_) => None,
            Config::Client(v) => Some(v)
        }
    }

    pub fn server_mut(&mut self) -> Option<&mut ServerConfig<'a>> {
        match self {
            Config::Server(v) => Some(v),
            Config::Client(_) => None
        }
    }
}

pub struct ClientConfig<'a> {
    /// Domain name, i.e. `ServerName`.
    pub sni: &'a str,
    /// Select the ALPN protocol to use; generally the highest-priority protocol is chosen here.
    pub alpn: &'a ALPN,
    /// TLS fingerprint information.
    pub fingerprint: &'a TlsFinger<'a>,
    /// Certificate used for mTLS client authentication.
    pub client_cert: &'a mut Vec<Certificate>,
    /// Certificate private key used for mTLS client authentication.
    pub cert_key: &'a RsaKey,
    /// Whether to verify the server certificate chain signature.
    pub verify: bool,
    /// Additional CA certificates used for self-signed certificates.
    pub ca_certs: &'a [Certificate],
    /// TLS key export path; `None` disables exporting.
    pub key_log: Option<Arc<String>>,
    /// Resume a TLS session using saved TLS session data.
    pub session: Option<TlsSession>,
    /// TLS version.
    pub version: Version,
}


pub struct ServerConfig<'a> {
    pub alpn: &'a ALPN,
    pub server_cert: &'a mut Vec<Certificate>,
    pub ca: &'a mut Certificate,
    pub cert_key: &'a RsaKey,
    pub verify: bool,
    pub ca_certs: &'a Vec<Certificate>,
    pub key_log: Option<Arc<String>>,
    /// TLS handshake version. The config value takes priority; otherwise the first available value is selected automatically.
    pub version: Version,
    /// Key exchange algorithm. The config value takes priority; otherwise the last available value is selected automatically.
    pub named_curve: NamedCurve
}