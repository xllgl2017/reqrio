use crate::error::HlsResult;
use super::super::bytes::Bytes;
use super::super::cipher::suite::CipherSuiteKind;

#[derive(Debug, Clone, Copy)]
enum ClientHelloType {
    OuterClientHello = 0,
}

impl ClientHelloType {
    fn from_u8(v: u8) -> Option<ClientHelloType> {
        match v {
            0 => Some(ClientHelloType::OuterClientHello),
            _ => None
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

#[derive(Debug, Clone, Copy)]
#[allow(non_camel_case_types)]
enum KDF {
    HKDF_SHA256 = 0x1,
}

impl KDF {
    fn from_u16(v: u16) -> Option<KDF> {
        match v {
            0x01 => Some(KDF::HKDF_SHA256),
            _ => None
        }
    }

    pub fn as_bytes(&self) -> [u8; 2] {
        (*self as u16).to_be_bytes()
    }
}

#[derive(Debug, Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum Aead {
    AES_128_GCM = 0x1,
    AES_256_GCM = 0x2,
    ChaCha20_POLY1305 = 0x3,
    AES_128_CCM = 0x4,
    AES_128_CCM_8 = 0x5,
}

impl Aead {
    fn from_u16(v: u16) -> Option<Aead> {
        match v {
            0x01 => Some(Aead::AES_128_GCM),
            0x02 => Some(Aead::AES_256_GCM),
            0x03 => Some(Aead::ChaCha20_POLY1305),
            0x04 => Some(Aead::AES_128_CCM),
            0x05 => Some(Aead::AES_128_CCM_8),
            _ => None
        }
    }
    pub fn as_bytes(&self) -> [u8; 2] {
        (*self as u16).to_be_bytes()
    }

    pub fn from_cipher_kind(kind: Option<CipherSuiteKind>) -> Option<Aead> {
        let kind = kind?;
        let text = format!("{:?}", kind).to_lowercase();
        if text.contains("aes_128_gcm") {
            Some(Aead::AES_128_GCM)
        } else if text.contains("aes_256_gcm") {
            Some(Aead::AES_256_GCM)
        } else {
            None
        }
    }

    pub fn as_aws_aead(&self) -> &'static aws_lc_rs::aead::Algorithm {
        match self {
            Aead::AES_128_GCM => &aws_lc_rs::aead::AES_128_GCM,
            Aead::AES_256_GCM => &aws_lc_rs::aead::AES_256_GCM,
            // Aead::ChaCha20_POLY1305 => {}
            // Aead::AES_128_CCM => {}
            // Aead::AES_128_CCM_8 => {}
            _ => panic!("unknown aead"),
        }
    }

    pub fn key_len(&self) -> usize {
        match self {
            Aead::AES_128_GCM => 16,
            Aead::AES_256_GCM => 32,
            _ => 0
        }
    }
}

#[derive(Debug)]
struct CipherSuite {
    kdf: KDF,
    aead: Aead,
}

impl CipherSuite {
    pub fn from_bytes(bytes: &[u8]) -> HlsResult<CipherSuite> {
        Ok(CipherSuite {
            kdf: KDF::from_u16(u16::from_be_bytes([bytes[0], bytes[1]])).ok_or("KDF Unknown")?,
            aead: Aead::from_u16(u16::from_be_bytes([bytes[2], bytes[3]])).ok_or("AEAD Unknown")?,
        })
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = self.kdf.as_bytes().to_vec();
        res.extend(self.aead.as_bytes());
        res
    }
}

#[derive(Debug)]
pub struct EncryptClientHello {
    type_: ClientHelloType,
    cipher_suite: CipherSuite,
    config_id: u8,
    enc_len: u16,
    enc: Bytes,
    payload_len: u16,
    payload: Bytes,
}

impl EncryptClientHello {
    pub fn new() -> EncryptClientHello {
        EncryptClientHello {
            type_: ClientHelloType::OuterClientHello,
            cipher_suite: CipherSuite {
                kdf: KDF::HKDF_SHA256,
                aead: Aead::AES_128_GCM,
            },
            config_id: 0,
            enc_len: 0,
            enc: Bytes::none(),
            payload_len: 0,
            payload: Bytes::none(),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> HlsResult<EncryptClientHello> {
        let mut res = EncryptClientHello::new();
        res.type_ = ClientHelloType::from_u8(bytes[0]).ok_or("ClientHelloType Unknown")?;
        res.cipher_suite = CipherSuite::from_bytes(&bytes[1..])?;
        res.config_id = bytes[5];
        res.enc_len = u16::from_be_bytes([bytes[6], bytes[7]]);
        res.enc = Bytes::new(bytes[8..8 + res.enc_len as usize].to_vec());
        let index = res.enc_len as usize + 8;
        res.payload_len = u16::from_be_bytes([bytes[index], bytes[index + 1]]);
        res.payload = Bytes::new(bytes[index + 2..index + res.payload_len as usize + 2].to_vec());
        Ok(res)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = vec![self.type_.as_u8()];
        res.extend(self.cipher_suite.as_bytes());
        res.push(self.config_id);
        res.extend((self.enc.len() as u16).to_be_bytes());
        res.extend(self.enc.as_bytes());
        res.extend((self.payload.len() as u16).to_be_bytes());
        res.extend(self.payload.as_bytes());
        res
    }
}