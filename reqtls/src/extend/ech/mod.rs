mod aead;
mod kdf;

use crate::dns::DNSError;
use crate::{Buf, HashType, NamedCurve, Reader};
pub use aead::Aead;
pub use kdf::KDF;
use crate::hpke::HpkeSuite;
#[cfg(debug_assertions)]
use std::fmt::Debug;

#[cfg_attr(debug_assertions, derive(Debug))]
#[allow(dead_code)]
pub struct EchConfig {
    ver: u16,
    len: u16,
    content: HpkeKeyConfig,
}

impl EchConfig {
    pub fn new() -> EchConfig {
        EchConfig {
            len: 0,
            ver: 0,
            content: HpkeKeyConfig {
                config_id: 0,
                kem_id: Kem::RESERVED,
                key: Buf::default(),
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
            content: HpkeKeyConfig::from_reader(&mut reader)?,
        })
    }
}

#[allow(unused)]
#[derive(PartialEq, Eq, Copy, Clone)]
pub struct Kem(u16);

#[allow(unused)]
impl Kem {
    pub const RESERVED: Kem = Kem::new(0);
    pub const P256_HKDF_SHA256: Kem = Kem::new(0x0010);
    pub const P384_HKDF_SHA384: Kem = Kem::new(0x0011);
    pub const P521_HKDF_SHA512: Kem = Kem::new(0x0022);
    pub const X25519_HKDF_SHA256: Kem = Kem::new(0x0020);
    pub const X448_HKDF_SHA512: Kem = Kem::new(0x0020);

    pub const fn hash_type(&self) -> HashType {
        match *self {
            Kem::P256_HKDF_SHA256 => HashType::Sha256,
            Kem::P384_HKDF_SHA384 => HashType::Sha384,
            Kem::P521_HKDF_SHA512 => HashType::Sha512,
            Kem::X25519_HKDF_SHA256 => HashType::Sha256,
            Kem::X448_HKDF_SHA512 => HashType::Sha512,
            _ => unreachable!()
        }
    }

    pub const fn named_curve(&self) -> NamedCurve {
        match *self {
            Kem::P256_HKDF_SHA256 => NamedCurve::SecP256r1,
            Kem::P384_HKDF_SHA384 => NamedCurve::SecP384r1,
            Kem::P521_HKDF_SHA512 => NamedCurve::SecP521r1,
            Kem::X25519_HKDF_SHA256 => NamedCurve::X25519,
            Kem::X448_HKDF_SHA512 => NamedCurve::X448,
            _ => unreachable!()
        }
    }


    pub const fn new(val: u16) -> Kem {
        Kem(val)
    }

    #[cfg(debug_assertions)]
    pub const fn spec(&self) -> &str {
        match *self {
            Kem::P256_HKDF_SHA256 => "P256_HKDF_SHA256",
            Kem::P384_HKDF_SHA384 => "P384_HKDF_SHA384",
            Kem::P521_HKDF_SHA512 => "P521_HKDF_SHA512",
            Kem::X25519_HKDF_SHA256 => "X25519_HKDF_SHA256",
            Kem::X448_HKDF_SHA512 => "X448_HKDF_SHA512",
            _ => "Reversed"
        }
    }

    pub const fn inner(&self) -> u16 { self.0 }

    pub const fn into_inner(self) -> u16 { self.0 }
}

#[cfg(debug_assertions)]
impl Debug for Kem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}(0x{:x})", self.spec(), self.0)
    }
}


#[cfg_attr(debug_assertions, derive(Debug))]
#[allow(dead_code)]
pub struct HpkeKeyConfig {
    config_id: u8,
    kem_id: Kem,
    key: Buf<'static>,
    ciphers: Vec<&'static HpkeSuite>,
    max_name_len: u8,
    name: String,
    ext_len: u16,
}

impl HpkeKeyConfig {
    pub fn from_reader(reader: &mut Reader) -> Result<HpkeKeyConfig, DNSError> {
        let config_id = reader.read_u8()?;
        let kem_id = reader.read_u16()?;
        let key_len = reader.read_u16()?;
        let key = reader.read_slice(key_len as usize)?;
        let cipher_len = reader.read_u16()?;
        let mut ciphers = Vec::with_capacity(cipher_len as usize);
        for _ in (0..cipher_len).step_by(4) {
            ciphers.push(HpkeSuite::find(kem_id, reader.read_u16()?, reader.read_u16()?));
        }
        let max_name_len = reader.read_u8()?;
        let name_len = reader.read_u8()?;
        let name = reader.read_str(name_len as usize)?;
        let ext_len = reader.read_u16()?;
        Ok(HpkeKeyConfig {
            config_id,
            kem_id: Kem::new(kem_id),
            key: Buf::Vec(key.to_vec()),
            ciphers,
            max_name_len,
            name: name.to_string(),
            ext_len,
        })
    }
}