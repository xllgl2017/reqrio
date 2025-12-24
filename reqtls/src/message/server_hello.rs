use crate::error::RlsResult;
use super::super::cipher::suite::CipherSuite;
use super::super::extend::Extension;
use super::super::message::HandshakeType;
use super::super::version::Version;
use super::super::bytes::Bytes;
use super::super::extend::alps::ALPN;
use super::super::extend::ExtensionKind;

#[derive(Debug)]
pub struct ServerHello {
    handshake_type: HandshakeType,
    len: u32,
    version: Version,
    pub(crate) random: Bytes,
    session_id_len: u8,
    session_id: Bytes,
    pub(crate) cipher_suite: CipherSuite,
    compress_method: u8,
    extend_len: u16,
    extensions: Vec<Extension>,
}

impl ServerHello {
    pub fn new() -> ServerHello {
        ServerHello {
            handshake_type: HandshakeType::ServerHello,
            len: 0,
            version: Version::new(0),
            random: Bytes::new(vec![]),
            session_id_len: 0,
            session_id: Bytes::new(vec![]),
            cipher_suite: CipherSuite::new(0),
            compress_method: 0,
            extend_len: 0,
            extensions: vec![],
        }
    }

    pub fn from_bytes(ht: HandshakeType, bytes: &[u8]) -> RlsResult<ServerHello> {
        let mut res = ServerHello::new();
        res.handshake_type = ht;
        res.len = u32::from_be_bytes([0, bytes[1], bytes[2], bytes[3]]);
        res.version = Version::new(u16::from_be_bytes([bytes[4], bytes[5]]));
        res.random = Bytes::new(bytes[6..38].to_vec());
        res.session_id_len = bytes[38];
        let index = 39 + res.session_id_len as usize;
        res.session_id = Bytes::new(bytes[39..index].to_vec());
        let v = u16::from_be_bytes([bytes[index], bytes[index + 1]]);
        res.cipher_suite = CipherSuite::new(v);
        res.compress_method = bytes[index + 2];
        res.extend_len = u16::from_be_bytes([bytes[index + 3], bytes[index + 4]].try_into()?);
        res.extensions = Extension::from_bytes(&bytes[index + 5..index + 5 + res.extend_len as usize])?;
        Ok(res)
    }

    pub fn use_ems(&self) -> bool {
        self.extensions.iter().find(|x| x.extension_type().as_u16() == ExtensionKind::MasterSecret as u16).is_some()
    }

    pub fn alpn(&self) -> Option<ALPN> {
        let extend = self.extensions.iter().find(|x| x.extension_type().as_u16() == ExtensionKind::ApplicationLayerProtocolNegotiation as u16)?;
        let protocol = extend.application_layer_protocol_negotiation()?;
        let alpn = protocol.values().get(0)?.clone();
        Some(alpn)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = vec![self.handshake_type.as_u8(), 0, 0, 0];
        // res.extend_from_slice(&(self.len as u32).to_be_bytes()[1..]);
        res.extend(self.version.as_bytes());
        res.extend(self.random.as_bytes());
        res.push(self.session_id.len() as u8);
        res.extend(self.session_id.as_bytes());
        res.extend(self.cipher_suite.as_bytes());
        res.push(self.compress_method);
        let mut ebs = vec![];
        for extension in &self.extensions {
            ebs.extend(extension.as_bytes());
        };
        res.extend((ebs.len() as u16).to_be_bytes());
        res.extend(ebs);
        let len = (res.len() - 4) as u32;
        res[1..4].copy_from_slice(len.to_be_bytes()[1..].as_ref());
        res
    }


}

#[derive(Debug)]
pub struct ServerHelloDone {
    handshake_type: HandshakeType,
    len: usize,
}

impl ServerHelloDone {
    pub fn new() -> ServerHelloDone {
        ServerHelloDone {
            handshake_type: HandshakeType::ServerHelloDone,
            len: 0,
        }
    }

    pub fn from_bytes(ht: HandshakeType, bytes: &[u8]) -> RlsResult<ServerHelloDone> {
        let mut res = ServerHelloDone::new();
        res.handshake_type = ht;
        res.len = u32::from_be_bytes([0, bytes[1], bytes[2], bytes[3]].try_into()?) as usize;
        Ok(res)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = vec![self.handshake_type.as_u8()];
        res.extend_from_slice(&(self.len as u32).to_be_bytes()[1..]);
        res
    }
}