use crate::error::HlsResult;
use super::super::extend::algorithm::SignatureAlgorithm;
use super::super::message::HandshakeType;
use super::super::bytes::Bytes;

#[derive(Debug, Copy, Clone)]
pub enum CurveType {
    NamedCurve = 0x3
}

impl CurveType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x3 => Some(Self::NamedCurve),
            _ => None
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
pub enum NamedCurve {
    x25519 = 0x1d,
    Secp256r1 = 0x17,
}

impl NamedCurve {
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            0x1d => Some(Self::x25519),
            0x17 => Some(Self::Secp256r1),
            _ => None
        }
    }
    pub fn as_bytes(&self) -> [u8; 2] {
        (*self as u16).to_be_bytes()
    }
}

#[derive(Debug)]
pub struct ServerHellmanParam {
    curve_type: CurveType,
    named_curve: NamedCurve,
    pub_key_len: u8,
    pub_key: Bytes,
    signature_algorithm: SignatureAlgorithm,
    signature_len: u16,
    signature: Bytes,
}

impl ServerHellmanParam {
    pub fn new() -> ServerHellmanParam {
        ServerHellmanParam {
            curve_type: CurveType::NamedCurve,
            named_curve: NamedCurve::x25519,
            pub_key_len: 0,
            pub_key: Bytes::none(),
            signature_algorithm: SignatureAlgorithm::SHA1_DSA,
            signature_len: 0,
            signature: Bytes::none(),
        }
    }
    pub fn from_bytes(bytes: &[u8]) -> HlsResult<ServerHellmanParam> {
        let mut res = ServerHellmanParam::new();
        res.curve_type = CurveType::from_u8(bytes[0]).ok_or("CurveType Unknown")?;
        let v = u16::from_be_bytes([bytes[1], bytes[2]].try_into()?);
        res.named_curve = NamedCurve::from_u16(v).ok_or("NamedCurve Unknown")?;
        res.pub_key_len = bytes[3];
        res.pub_key = Bytes::new(bytes[4..res.pub_key_len as usize + 4].to_vec());
        let index = res.pub_key_len as usize + 4;
        let v = u16::from_be_bytes([bytes[index], bytes[index + 1]].try_into()?);
        res.signature_algorithm = SignatureAlgorithm::from_u16(v).ok_or("SignatureAlgorithm Unknown")?;
        res.signature_len = u16::from_be_bytes([bytes[index + 2], bytes[index + 3]].try_into()?);
        res.signature = Bytes::new(bytes[index + 4..index + 4 + res.signature_len as usize].to_vec());
        Ok(res)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = vec![self.curve_type.as_u8()];
        res.extend(self.named_curve.as_bytes());
        res.push(self.pub_key.len() as u8);
        res.extend(self.pub_key.as_bytes());
        res.extend(self.signature_algorithm.as_bytes());
        res.extend((self.signature.len() as u16).to_be_bytes());
        res.extend(self.signature.as_bytes());
        res
    }

    pub fn pub_key(&self) -> &Bytes {
        &self.pub_key
    }

    pub fn named_curve(&self) -> &NamedCurve {
        &self.named_curve
    }
}

#[derive(Debug)]
pub struct ServerKeyExchange {
    handshake_type: HandshakeType,
    len: usize,
    hellman_param: ServerHellmanParam,
}

impl ServerKeyExchange {
    pub fn new() -> ServerKeyExchange {
        ServerKeyExchange {
            handshake_type: HandshakeType::ClientHello,
            len: 0,
            hellman_param: ServerHellmanParam::new(),
        }
    }
    pub fn from_bytes(ht: HandshakeType, bytes: &[u8]) -> HlsResult<ServerKeyExchange> {
        let mut res = ServerKeyExchange::new();
        res.handshake_type = ht;
        res.len = u32::from_be_bytes([0, bytes[1], bytes[2], bytes[3]].try_into()?) as usize;
        res.hellman_param = ServerHellmanParam::from_bytes(&bytes[4..])?;
        Ok(res)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = vec![self.handshake_type.as_u8()];
        res.extend_from_slice(&(self.len as u32).to_be_bytes()[1..]);
        res.extend(self.hellman_param.as_bytes());
        res
    }

    pub fn hellman_param(&self) -> &ServerHellmanParam {
        &self.hellman_param
    }
}

#[derive(Debug)]
pub struct ClientHellmanParam {
    pub_key_len: usize,
    pub_key: Bytes,
}

impl ClientHellmanParam {
    pub fn new() -> ClientHellmanParam {
        ClientHellmanParam {
            pub_key_len: 0,
            pub_key: Bytes::new(vec![]),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> HlsResult<ClientHellmanParam> {
        let mut res = ClientHellmanParam::new();
        res.pub_key_len = bytes[0] as usize;
        res.pub_key = Bytes::new(bytes[1..res.pub_key_len + 1].to_vec());
        Ok(res)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = vec![self.pub_key.len() as u8];
        res.extend(self.pub_key.as_bytes());
        res
    }
}

#[derive(Debug)]
pub struct ClientKeyExchange {
    handshake_type: HandshakeType,
    len: usize,
    hellman_param: ClientHellmanParam,
}

impl ClientKeyExchange {
    pub fn new() -> ClientKeyExchange {
        ClientKeyExchange {
            handshake_type: HandshakeType::ClientHello,
            len: 0,
            hellman_param: ClientHellmanParam::new(),
        }
    }

    pub fn from_bytes(ht: HandshakeType, bytes: &[u8]) -> HlsResult<ClientKeyExchange> {
        let mut res = ClientKeyExchange::new();
        res.handshake_type = ht;
        res.len = u32::from_be_bytes([0, bytes[1], bytes[2], bytes[3]].try_into()?) as usize;
        res.hellman_param = ClientHellmanParam::from_bytes(&bytes[4..])?;
        Ok(res)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = vec![self.handshake_type.as_u8()];
        let vbs = self.hellman_param.as_bytes();
        res.extend_from_slice(&(vbs.len() as u32).to_be_bytes()[1..]);
        res.extend(vbs);
        res
    }

    pub fn set_pub_key(&mut self, pub_key: Vec<u8>) {
        self.hellman_param.pub_key = Bytes::new(pub_key);
        self.hellman_param.pub_key_len = self.hellman_param.pub_key.len();
    }
}

