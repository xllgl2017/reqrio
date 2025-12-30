use super::record::RecordLayer;
use crate::error::{RlsError, RlsResult};
use aws_lc_rs::aead::{Aad, Nonce};
use iv::Iv;
use key::Key;
use crate::extend::Aead;

pub mod iv;
pub mod key;
pub mod suite;

pub struct Cipher {
    key: Key,
    iv: Iv,
    seq: u64,
}


impl Cipher {
    pub fn none() -> Cipher {
        Cipher {
            key: Key::None,
            iv: Iv::new(&vec![], vec![]),
            seq: 0,
        }
    }

    pub fn set_key(&mut self, key: Key) {
        self.key = key;
    }

    pub fn set_iv(&mut self, iv: Iv) {
        self.iv = iv;
    }

    fn build_aad(&self, layer: &RecordLayer, aead: &Aead) -> RlsResult<[u8; 13]> {
        let mut res = [0; 13];
        res[0..8].copy_from_slice(self.seq.to_be_bytes().as_ref());
        res[8] = layer.context_type.as_u8();
        res[9..11].copy_from_slice(&layer.version.as_bytes()); // TLS1.2
        let payload = layer.messages[0].payload().ok_or(RlsError::PayloadNone)?;
        let payload_len = payload.len() as u16 - aead.explicit_len() as u16 - 16;
        res[11..13].copy_from_slice(&payload_len.to_be_bytes());
        Ok(res)
    }

    pub fn encrypt<'a>(&mut self, record: &'a mut RecordLayer<'a>, aead: &Aead) -> RlsResult<()> {
        let add_arr = self.build_aad(&record, aead)?;
        let aad = Aad::from(&add_arr);
        let nonce = Nonce::assume_unique_for_key(self.iv.as_array(self.seq));
        let payload = record.messages[0].payload_mut().ok_or(RlsError::PayloadNone)?;
        let payload_len = payload.len();
        payload.insert_explicit(aead, &nonce.as_ref()[4..]);
        let tag = self.key.encrypt(nonce, aad, payload.encrypting_payload(aead))?;
        payload[payload_len - 16..].copy_from_slice(tag.as_ref());
        self.seq += 1;
        Ok(())
    }

    pub fn decrypt<'a>(&mut self, record: &'a mut RecordLayer<'a>, aead: &Aead) -> RlsResult<usize> {
        let add_arr = self.build_aad(&record, aead)?;
        let aad = Aad::from(&add_arr);
        let payload = record.messages[0].payload_mut().ok_or(RlsError::PayloadNone)?;
        self.iv.set_explicit(payload.explicit(aead).to_vec());
        let nonce=match aead {
            Aead::AES_128_GCM | Aead::AES_256_GCM => Nonce::assume_unique_for_key(self.iv.as_ref()),
            Aead::ChaCha20_POLY1305 => Nonce::assume_unique_for_key(self.iv.as_array(self.seq)),
            _=> return Err("gen nonce none".into())
        };
        let len = self.key.decrypt(nonce, aad, payload.decrypting_payload(aead))?;
        self.seq += 1;
        Ok(len)
    }
}


#[cfg(test)]
mod tests {
    use crate::cipher::iv::Iv;
    use crate::cipher::key::Key;
    use crate::cipher::Cipher;
    use crate::extend::Aead;
    use crate::message::Payload;
    use crate::version::VersionKind;
    use crate::{rand, Message, RecordLayer, RecordType, Version};

    #[test]
    fn test_cipher() {
        let mut cipher = Cipher::none();
        let key_bs = rand::random::<[u8; 32]>().to_vec();
        let iv = rand::random::<[u8; 12]>();
        // let explicit = rand::random::<[u8; 8]>();
        let aead = Aead::ChaCha20_POLY1305;
        let key = Key::write(&key_bs, &aead).unwrap();
        let iv = Iv::new(&iv, vec![]);
        cipher.set_key(key);
        cipher.set_iv(iv);
        let mut payload_buffer = [0; 37];
        payload_buffer[5..21].copy_from_slice(&rand::random::<[u8; 16]>());
        println!("{:?}", payload_buffer);
        let mut layer = RecordLayer {
            context_type: RecordType::HandShake,
            version: Version::new(VersionKind::TLS_1_2 as u16),
            len: 0,
            messages: vec![Message::Payload(Payload::from_slice(&mut payload_buffer))],
        };
        cipher.encrypt(&mut layer, &aead).unwrap();
        println!("{:?}", payload_buffer);
        let mut layer = RecordLayer {
            context_type: RecordType::HandShake,
            version: Version::new(VersionKind::TLS_1_2 as u16),
            len: 0,
            messages: vec![Message::Payload(Payload::from_slice(&mut payload_buffer))],
        };
        let key = Key::read(&key_bs, &aead).unwrap();
        cipher.set_key(key);
        cipher.decrypt(&mut layer, &aead).unwrap();
        println!("{:?}", payload_buffer);
        // cipher.encrypt(&mut layer).unwrap(); //单独运行这个不报错，在前面的Finish后会偶尔会报错
        // let _res = cipher.decrypt(layer).unwrap();
    }
}