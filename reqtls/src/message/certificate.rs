use super::HandshakeType;
use std::fmt::Debug;
use crate::error::RlsResult;
use super::super::bytes::Bytes;

#[derive(Debug)]
pub struct Certificate {
    len: u32,
    value: Bytes,
}

impl Certificate {
    pub fn new() -> Certificate {
        Certificate {
            len: 0,
            value: Bytes::new(vec![]),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> RlsResult<Vec<Certificate>> {
        let mut res = vec![];
        let mut index = 0;
        while index < bytes.len() {
            let mut v = Certificate::new();
            v.len = u32::from_be_bytes([0, bytes[index], bytes[index + 1], bytes[index + 2]].try_into()?);
            index = index + v.len as usize + 3;
            v.value = Bytes::new(bytes[index - v.len as usize..index].to_vec());
            res.push(v);
        }
        Ok(res)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = (self.value.len() as u32).to_be_bytes()[1..].to_vec();
        res.extend(self.value.as_bytes());
        res
    }
}

#[derive(Debug)]
pub struct Certificates {
    handshake_type: HandshakeType,
    len: u32,
    certificate_len: u32,
    certificates: Vec<Certificate>,
}

impl Certificates {
    pub fn new() -> Certificates {
        Certificates {
            handshake_type: HandshakeType::ClientHello,
            len: 0,
            certificate_len: 0,
            certificates: vec![],
        }
    }
    pub fn from_bytes(ht: HandshakeType, bytes: &[u8]) -> RlsResult<Certificates> {
        let mut res = Certificates::new();
        res.handshake_type = ht;
        res.len = u32::from_be_bytes([0, bytes[1], bytes[2], bytes[3]]);
        res.certificate_len = u32::from_be_bytes([0, bytes[4], bytes[5], bytes[6]]);
        res.certificates = Certificate::from_bytes(&bytes[7..7 + res.certificate_len as usize])?;
        Ok(res)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = vec![self.handshake_type as u8, 0, 0, 0, 0, 0, 0];
        // res.extend_from_slice(&(self.len as u32).to_be_bytes()[1..]);
        // res.extend_from_slice(&(self.certificate_len as u32).to_be_bytes()[1..]);
        for certificate in &self.certificates {
            res.extend(certificate.as_bytes())
        };
        let len = (res.len() - 4) as u32;
        res[1..4].copy_from_slice(len.to_be_bytes()[1..].as_ref());
        let len = (res.len() - 7) as u32;
        res[4..7].copy_from_slice(len.to_be_bytes()[1..].as_ref());
        res
    }

    pub fn len(&self) -> u32 {
        self.len
    }
}

#[derive(Debug)]
pub struct CertificateStatus {
    // handshake_type: HandshakeType,
    bytes: Bytes,
}

impl CertificateStatus {
    pub fn from_bytes(_ht: HandshakeType, bytes: &[u8]) -> CertificateStatus {
        CertificateStatus {
            // handshake_type:ht,
            bytes: Bytes::new(bytes.to_vec()),
        }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        self.bytes.as_bytes()
    }

    pub fn len(&self) -> u32 {
        (self.bytes.len() - 4) as u32
    }
}