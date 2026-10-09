use crate::{Certificate, RsaKey, TlsFinger, TlsSession, Version, ALPN, NamedCurve};
use std::path::PathBuf;

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
    ///域名，ServerName
    pub sni: &'a str,
    ///设置应用层使用哪个协议，这里一般设置最高那个
    pub alpn: &'a ALPN,
    ///Tls指纹信息，
    pub fingerprint: &'a TlsFinger<'a>,
    ///证书，mTls设置客户端证书
    pub client_cert: &'a mut Vec<Certificate>,
    ///证书私钥，mTls设置客户端证书私钥
    pub cert_key: &'a RsaKey,
    ///是否对服务器证书链签名进行校验
    pub verify: bool,
    ///额外的ca证书，用于自签证书
    pub ca_certs: &'a [Certificate],
    ///tls密钥导出路径，None不导出
    pub key_log: Option<PathBuf>,
    ///使用tls会话数据恢复会话
    pub session: &'a Option<TlsSession>,
    ///TLS版本
    pub version: Version,
}


pub struct ServerConfig<'a> {
    pub alpn: &'a ALPN,
    pub server_cert: &'a mut Vec<Certificate>,
    pub ca: &'a mut Certificate,
    pub cert_key: &'a RsaKey,
    pub verify: bool,
    pub ca_certs: &'a Vec<Certificate>,
    pub key_log: Option<PathBuf>,
    ///tls握手版本，优先选择config的，没有的情况下自动选择第一个
    pub version: Version,
    ///密钥交换算法，优先选择config的，没有的情况下自动选择最后一个
    pub named_curve: NamedCurve
}