use super::super::extend::Aead;
use aws_lc_rs::aead::{TlsProtocolId, TlsRecordOpeningKey, TlsRecordSealingKey};
use crate::error::HlsResult;

pub enum Key {
    None,
    Read(TlsRecordOpeningKey),
    Write(TlsRecordSealingKey),
}

impl Key {
    pub fn read(key: Vec<u8>, aead: &Aead) -> HlsResult<Key> {
        let key = TlsRecordOpeningKey::new(aead.as_aws_aead(), TlsProtocolId::TLS13, &key)?;
        Ok(Key::Read(key))
    }

    pub fn write(key: Vec<u8>, aead: &Aead) -> HlsResult<Key> {
        let key = TlsRecordSealingKey::new(aead.as_aws_aead(), TlsProtocolId::TLS13, &key)?;
        Ok(Key::Write(key))
    }

    pub fn encrypter(&mut self) -> Option<&mut TlsRecordSealingKey> {
        match self {
            Key::Write(w) => Some(w),
            _ => None,
        }
    }

    pub fn decrypter(&self) -> Option<&TlsRecordOpeningKey> {
        match self {
            Key::Read(r) => Some(r),
            _ => None
        }
    }
}