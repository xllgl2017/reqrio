use std::fmt::{Debug, Formatter};
use sha2::{Digest, Sha256, Sha384};
use crate::error::HlsResult;
use super::super::extend::Aead;

pub enum Hasher {
    None,
    Sha256(Sha256),
    Sha384(Sha384),
}

impl Hasher {
    fn update(&mut self, data: &[u8]) -> HlsResult<()> {
        match self {
            Hasher::None => Err("HasherNonePointer".into()),
            Hasher::Sha256(v) => Ok(v.update(data)),
            Hasher::Sha384(v) => Ok(v.update(data)),
        }
    }

    fn finalize(&self) -> HlsResult<Vec<u8>> {
        match self {
            Hasher::None => Err("HasherNonePointer".into()),
            Hasher::Sha256(v) => Ok(v.clone().finalize().to_vec()),
            Hasher::Sha384(v) => Ok(v.clone().finalize().to_vec()),
        }
    }

    fn from_kind(kind: Option<&CipherSuiteKind>) -> Hasher {
        match kind {
            None => Hasher::None,
            Some(kind) => {
                let text = format!("{:?}", kind).to_lowercase();
                if text.contains("sha256") {
                    Hasher::Sha256(Sha256::new())
                } else if text.contains("sha384") {
                    Hasher::Sha384(Sha384::new())
                } else {
                    Hasher::None
                }
            }
        }
    }

    pub fn is_none(&self) -> bool {
        match self {
            Hasher::None => true,
            _ => false,
        }
    }
}


pub struct CipherSuite {
    kind: u16,
    hasher: Hasher,
    aead: Option<Aead>,
}

impl CipherSuite {
    pub fn new(v: u16) -> CipherSuite {
        let kind = CipherSuiteKind::from_u16(v);
        CipherSuite {
            kind: v,
            hasher: Hasher::from_kind(kind.as_ref()),
            aead: Aead::from_cipher_kind(kind),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> HlsResult<Vec<CipherSuite>> {
        let mut res = vec![];
        for chuck in bytes.chunks(2) {
            let v = u16::from_be_bytes(chuck.try_into()?);
            res.push(CipherSuite::new(v));
        }
        Ok(res)
    }

    pub fn is_reserved(&self) -> bool {
        CipherSuiteKind::from_u16(self.kind).is_none()
    }

    pub fn as_bytes(&self) -> [u8; 2] {
        self.kind.to_be_bytes()
    }

    pub fn as_u16(&self) -> u16 {
        self.kind
    }

    pub fn update(&mut self, data: impl AsRef<[u8]>) -> HlsResult<()> {
        self.hasher.update(data.as_ref())
    }

    pub fn session_hash(&self) -> HlsResult<Vec<u8>> {
        self.hasher.finalize()
    }

    pub fn aead(&self) -> Option<&Aead> {
        self.aead.as_ref()
    }

    pub fn hasher(&self) -> &Hasher {
        &self.hasher
    }
}

impl Debug for CipherSuite {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match CipherSuiteKind::from_u16(self.kind) {
            None => f.write_str(&format!("Reserved({})", self.kind)),
            Some(kind) => f.write_str(&format!("{:?}", kind))
        }
    }
}
#[allow(non_camel_case_types)]
#[derive(Debug, Clone)]
pub enum CipherSuiteKind {
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xc02c,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xc030,
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = 0x009f,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca9,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca8,
    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xccaa,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xc02b,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xc02f,
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = 0x009e,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = 0xc024,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 0xc028,
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = 0x006b,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0xc023,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0xc027,
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = 0x0067,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0xc00a,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xc014,
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA = 0x0039,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0xc009,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xc013,
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA = 0x0033,
    TLS_RSA_WITH_AES_256_GCM_SHA384 = 0x009d,
    TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009c,
    TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x003d,
    TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003c,
    TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035,
    TLS_RSA_WITH_AES_128_CBC_SHA = 0x002f,
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00ff,
    TLS_AES_128_GCM_SHA256 = 0x1301,
    TLS_AES_256_GCM_SHA384 = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,

}

impl CipherSuiteKind {
    pub fn from_u16(byte: u16) -> Option<CipherSuiteKind> {
        match byte {
            0xc02c => Some(CipherSuiteKind::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384),
            0xc030 => Some(CipherSuiteKind::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384),
            0x009f => Some(CipherSuiteKind::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384),
            0xcca9 => Some(CipherSuiteKind::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256),
            0xcca8 => Some(CipherSuiteKind::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256),
            0xccaa => Some(CipherSuiteKind::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256),
            0xc02b => Some(CipherSuiteKind::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
            0xc02f => Some(CipherSuiteKind::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
            0x009e => Some(CipherSuiteKind::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256),
            0xc024 => Some(CipherSuiteKind::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384),
            0xc028 => Some(CipherSuiteKind::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384),
            0x006b => Some(CipherSuiteKind::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256),
            0xc023 => Some(CipherSuiteKind::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256),
            0xc027 => Some(CipherSuiteKind::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256),
            0x0067 => Some(CipherSuiteKind::TLS_DHE_RSA_WITH_AES_128_CBC_SHA256),
            0xc00a => Some(CipherSuiteKind::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA),
            0xc014 => Some(CipherSuiteKind::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA),
            0x0039 => Some(CipherSuiteKind::TLS_DHE_RSA_WITH_AES_256_CBC_SHA),
            0xc009 => Some(CipherSuiteKind::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA),
            0xc013 => Some(CipherSuiteKind::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA),
            0x0033 => Some(CipherSuiteKind::TLS_DHE_RSA_WITH_AES_128_CBC_SHA),
            0x009d => Some(CipherSuiteKind::TLS_RSA_WITH_AES_256_GCM_SHA384),
            0x009c => Some(CipherSuiteKind::TLS_RSA_WITH_AES_128_GCM_SHA256),
            0x003d => Some(CipherSuiteKind::TLS_RSA_WITH_AES_256_CBC_SHA256),
            0x003c => Some(CipherSuiteKind::TLS_RSA_WITH_AES_128_CBC_SHA256),
            0x0035 => Some(CipherSuiteKind::TLS_RSA_WITH_AES_256_CBC_SHA),
            0x002f => Some(CipherSuiteKind::TLS_RSA_WITH_AES_128_CBC_SHA),
            0x00ff => Some(CipherSuiteKind::TLS_EMPTY_RENEGOTIATION_INFO_SCSV),
            0x1301 => Some(CipherSuiteKind::TLS_AES_128_GCM_SHA256),
            0x1302 => Some(CipherSuiteKind::TLS_AES_256_GCM_SHA384),
            0x1303 => Some(CipherSuiteKind::TLS_CHACHA20_POLY1305_SHA256),

            _ => None
        }
    }
}
