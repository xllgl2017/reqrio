use crate::error::HlsResult;
use super::super::bytes::Bytes;
use super::super::message::HandshakeType;

#[derive(Debug)]
pub struct TlsSessionTicket {
    lifetime: i64,
    len: u16,
    value: Bytes,
}

impl TlsSessionTicket {
    pub fn new() -> TlsSessionTicket {
        TlsSessionTicket {
            lifetime: 0,
            len: 0,
            value: Bytes::none(),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> HlsResult<TlsSessionTicket> {
        let mut res = TlsSessionTicket::new();
        res.lifetime = u32::from_be_bytes(bytes[0..4].try_into()?) as i64;
        res.len = u16::from_be_bytes(bytes[4..6].try_into()?);
        res.value = Bytes::new(bytes[6..6 + res.len as usize].to_vec());
        Ok(res)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = (self.lifetime as u32).to_be_bytes().to_vec();
        res.extend((self.value.len() as u16).to_be_bytes());
        res.extend(self.value.as_bytes());
        res
    }
}

#[derive(Debug)]
pub struct SessionTicket {
    handshake_type: HandshakeType,
    len: u32,
    tls_ticket: TlsSessionTicket,
}

impl SessionTicket {
    pub fn new() -> SessionTicket {
        SessionTicket {
            handshake_type: HandshakeType::ClientHello,
            len: 0,
            tls_ticket: TlsSessionTicket::new(),
        }
    }

    pub fn from_bytes(ht: HandshakeType, bytes: &[u8]) -> HlsResult<SessionTicket> {
        let mut res = SessionTicket::new();
        res.handshake_type = ht;
        res.len = u32::from_be_bytes([0, bytes[1], bytes[2], bytes[3]]);
        res.tls_ticket = TlsSessionTicket::from_bytes(&bytes[4..])?;
        Ok(res)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = vec![self.handshake_type as u8];
        let tbs = self.tls_ticket.as_bytes();
        res.extend_from_slice(&(tbs.len() as u32).to_be_bytes()[1..]);
        res.extend(tbs);
        res
    }
}