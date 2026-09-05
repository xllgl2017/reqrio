mod aead;
mod kdf;

use super::client_hello::CipherSuite;
use crate::bytes::Bytes;
use crate::dns::DNSError;
use crate::Reader;
pub use aead::Aead;
pub use kdf::KDF;
use std::fmt::Debug;

#[derive(Debug)]
#[allow(dead_code)]
pub struct EchConfig {
    len: u16,
    ver: u16,
    content: EchContent,
}

impl EchConfig {
    pub fn new() -> EchConfig {
        EchConfig {
            len: 0,
            ver: 0,
            content: EchContent {
                config_id: 0,
                kem_id: DHKem(0),
                key: Bytes::none(),
                ciphers: vec![],
                max_name_len: 0,
                name: "".to_string(),
                ext_len: 0,
            },
        }
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<EchConfig, DNSError> {
        let mut reader = Reader::from_slice(bytes);
        Ok(EchConfig {
            ver: reader.read_u16()?,
            len: reader.read_u16()?,
            content: EchContent::from_reader(&mut reader)?,
        })
    }
}

struct DHKem(u16);

impl DHKem {
    const X25519_HDK: u16 = 0x0020;

    fn spec(&self) -> &str {
        match self.0 {
            DHKem::X25519_HDK => "X25519",
            _ => "Reversed"
        }
    }
}

impl Debug for DHKem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}(0x{:x})", self.spec(), self.0)
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct EchContent {
    config_id: u8,
    kem_id: DHKem,
    key: Bytes,
    ciphers: Vec<CipherSuite>,
    max_name_len: u8,
    name: String,
    ext_len: u16,
}

impl EchContent {
    pub fn from_reader(reader: &mut Reader) -> Result<EchContent, DNSError> {
        let config_id = reader.read_u8()?;
        let kem_id = DHKem(reader.read_u16()?);
        let key_len = reader.read_u16()?;
        let key = reader.read_slice(key_len as usize)?;
        let cipher_len = reader.read_u16()?;
        let mut ciphers = Vec::with_capacity(cipher_len as usize);
        for _ in (0..cipher_len).step_by(4) {
            let aead = Aead::from_u16(reader.read_u16()?).ok_or(DNSError::UnknownAead)?;
            let kdf = KDF::from_u16(reader.read_u16()?).ok_or(DNSError::UnknownKDF)?;
            ciphers.push(CipherSuite { aead, kdf });
        }
        let max_name_len = reader.read_u8()?;
        let name_len = reader.read_u8()?;
        let name = reader.read_str(name_len as usize)?;
        let ext_len = reader.read_u16()?;
        Ok(EchContent {
            config_id,
            kem_id,
            key: Bytes::new(key.to_vec()),
            ciphers,
            max_name_len,
            name: name.to_string(),
            ext_len,
        })
    }
}