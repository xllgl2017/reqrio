use std::fmt::{Debug, Formatter};
use crate::error::RlsResult;

#[derive(Debug, Clone, Copy)]
pub enum CompressionKind {
    Null = 0x0,
    Deflate = 0x1,
    Brotli = 0x2,
}

impl CompressionKind {
    pub fn from_u16(value: u16) -> Option<CompressionKind> {
        match value {
            0 => Some(CompressionKind::Null),
            1 => Some(CompressionKind::Deflate),
            0x2 => Some(CompressionKind::Brotli),
            _ => None
        }
    }
}


pub struct CompressionType(u16);

impl CompressionType {
    pub fn as_bytes(&self) -> [u8; 2] {
        self.0.to_be_bytes()
    }
}


impl Debug for CompressionType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match CompressionKind::from_u16(self.0) {
            None => f.write_str(&format!("Reserved({})", self.0)),
            Some(kind) => f.write_str(&format!("{:?}", kind))
        }
    }
}

#[derive(Debug)]
pub struct CompressionCertificate {
    len: u8,
    types: Vec<CompressionType>,
}

impl CompressionCertificate {
    pub fn new() -> CompressionCertificate {
        CompressionCertificate {
            len: 0,
            types: vec![],
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> RlsResult<CompressionCertificate> {
        let mut res = CompressionCertificate::new();
        res.len = bytes[0];
        let mut index = 1;
        while index < bytes.len() {
            let v = u16::from_be_bytes([bytes[index], bytes[index + 1]]);
            res.types.push(CompressionType(v));
            index += 2;
        }

        Ok(res)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = vec![0];
        for ty in &self.types {
            res.extend(ty.as_bytes());
        }
        res[0] = (res.len() - 1) as u8;
        res
    }
}



