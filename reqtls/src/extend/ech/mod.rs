mod aead;
mod kdf;

use super::client_hello::CipherSuite;
use crate::{Aead, Buf, BufferError, Reader};
pub use kdf::KDF;
#[cfg(debug_assertions)]
use std::fmt::Debug;

#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Default)]
pub struct EchConfig {
    len: u16,
    ver: u16,
    content: EchContent,
}

impl EchConfig {
    pub fn new() -> EchConfig {
        EchConfig::default()
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<EchConfig, BufferError> {
        let mut reader = Reader::from_slice(bytes);
        Ok(EchConfig {
            ver: reader.read_u16()?,
            len: reader.read_u16()?,
            content: EchContent::from_reader(&mut reader)?,
        })
    }
}

#[derive(Default)]
struct DHKem(u16);

impl DHKem {
    #[allow(unused)]
    const X25519_HDK: u16 = 0x0020;

    #[cfg(debug_assertions)]
    fn spec(&self) -> &str {
        match self.0 {
            DHKem::X25519_HDK => "X25519",
            _ => "Reversed"
        }
    }
}

#[cfg(debug_assertions)]
impl Debug for DHKem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}(0x{:x})", self.spec(), self.0)
    }
}

#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Default)]
pub struct EchContent {
    config_id: u8,
    kem_id: DHKem,
    key: Buf<'static>,
    ciphers: Vec<CipherSuite>,
    max_name_len: u8,
    name: String,
    ext_len: u16,
}

impl EchContent {
    pub fn from_reader(reader: &mut Reader) -> Result<EchContent, BufferError> {
        let config_id = reader.read_u8()?;
        let kem_id = DHKem(reader.read_u16()?);
        let key_len = reader.read_u16()?;
        let key = reader.read_slice(key_len as usize)?;
        let cipher_len = reader.read_u16()?;
        let mut ciphers = Vec::with_capacity(cipher_len as usize);
        for _ in (0..cipher_len).step_by(4) {
            let aead = Aead::from_u16(reader.read_u16()?).unwrap();
            let kdf = KDF::from_u16(reader.read_u16()?).unwrap();
            ciphers.push(CipherSuite { aead, kdf });
        }
        let max_name_len = reader.read_u8()?;
        let name_len = reader.read_u8()?;
        let name = reader.read_str(name_len as usize)?;
        let ext_len = reader.read_u16()?;
        Ok(EchContent {
            config_id,
            kem_id,
            key: Buf::Vec(key.to_vec()),
            ciphers,
            max_name_len,
            name: name.to_string(),
            ext_len,
        })
    }
}