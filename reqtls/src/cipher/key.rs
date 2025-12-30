use super::super::extend::Aead;
use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, Tag, TlsProtocolId, TlsRecordOpeningKey, TlsRecordSealingKey, UnboundKey};
use crate::error::RlsResult;
use crate::RlsError;

pub enum Key {
    None,
    AesGcmRead(TlsRecordOpeningKey),
    AesGcmWrite(TlsRecordSealingKey),
    ChaCha20Poly1305Read(LessSafeKey),
    ChaCha20Poly1305Write(LessSafeKey),
}

impl Key {
    pub fn read(key: &[u8], aead: &Aead) -> RlsResult<Key> {
        match aead {
            Aead::AES_128_GCM | Aead::AES_256_GCM => Key::aes_gcm_read(key, aead),
            Aead::ChaCha20_POLY1305 => Key::chacha20_poly1350_read(key, aead),
            Aead::AES_128_CCM | Aead::AES_128_CCM_8 => Err(RlsError::GenKeyFromAeadNone)
        }
    }

    pub fn write(key: &[u8], aead: &Aead) -> RlsResult<Key> {
        match aead {
            Aead::AES_128_GCM | Aead::AES_256_GCM => Key::aes_gcm_write(key, aead),
            Aead::ChaCha20_POLY1305 => Key::chacha20_poly1305_write(key, aead),
            Aead::AES_128_CCM | Aead::AES_128_CCM_8 => Err(RlsError::GenKeyFromAeadNone)
        }
    }

    fn aes_gcm_read(key: &[u8], aead: &Aead) -> RlsResult<Key> {
        let key = TlsRecordOpeningKey::new(aead.as_aws_aead(), TlsProtocolId::TLS13, key)?;
        Ok(Key::AesGcmRead(key))
    }

    fn aes_gcm_write(key: &[u8], aead: &Aead) -> RlsResult<Key> {
        let key = TlsRecordSealingKey::new(aead.as_aws_aead(), TlsProtocolId::TLS13, key)?;
        Ok(Key::AesGcmWrite(key))
    }

    fn chacha20_poly1350_read(key: &[u8], aead: &Aead) -> RlsResult<Key> {
        let unbound_key = UnboundKey::new(aead.as_aws_aead(), key)?;
        Ok(Key::ChaCha20Poly1305Read(LessSafeKey::new(unbound_key)))
    }

    fn chacha20_poly1305_write(key: &[u8], aead: &Aead) -> RlsResult<Key> {
        let unbound_key = UnboundKey::new(aead.as_aws_aead(), key)?;
        Ok(Key::ChaCha20Poly1305Write(LessSafeKey::new(unbound_key)))
    }

    pub fn encrypt(&mut self, nonce: Nonce, aad: Aad<&[u8; 13]>, in_out: &mut [u8]) -> RlsResult<Tag> {
        match self {
            Key::AesGcmWrite(w) => Ok(w.seal_in_place_separate_tag(nonce, aad, in_out)?),
            Key::ChaCha20Poly1305Write(w) => Ok(w.seal_in_place_separate_tag(nonce, aad, in_out)?),
            _ => Err(RlsError::EncrypterNone)
        }
    }

    pub fn decrypt(&mut self, nonce: Nonce, aad: Aad<&[u8; 13]>, in_out: &mut [u8]) -> RlsResult<usize> {
        let res = match self {
            Key::AesGcmRead(r) => r.open_in_place(nonce, aad, in_out)?,
            Key::ChaCha20Poly1305Read(r) => r.open_in_place(nonce, aad, in_out)?,
            _ => return Err(RlsError::DecrypterNone)
        };
        Ok(res.len())
    }
}