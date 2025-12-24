use super::record::RecordLayer;
use aws_lc_rs::aead::{Aad, Nonce};
use key::Key;
use iv::Iv;
use crate::error::{RlsError, RlsResult};

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
            iv: Iv::new(vec![], vec![]),
            seq: 0,
        }
    }

    pub fn set_key(&mut self, key: Key) {
        self.key = key;
    }

    pub fn set_iv(&mut self, iv: Iv) {
        self.iv = iv;
    }

    fn build_aad(&self, layer: &RecordLayer, encrypt: bool) -> RlsResult<[u8; 13]> {
        let mut res = [0; 13];
        res[0..8].copy_from_slice(self.seq.to_be_bytes().as_ref());
        res[8] = layer.context_type.as_u8();
        res[9..11].copy_from_slice(&layer.version.as_bytes()); // TLS1.2
        let payload = layer.message.payload().ok_or(RlsError::PayloadNone)?;
        let payload_len = match encrypt {
            true => payload.len() as u16,
            //data+explicit+tag
            false => (payload.len() - 8 - 16) as u16,
        };
        res[11..13].copy_from_slice(&payload_len.to_be_bytes());
        Ok(res)
    }

    pub fn encrypt(&mut self, record: &mut RecordLayer) -> RlsResult<()> {
        let add_arr = self.build_aad(&record, true)?;
        let aad = Aad::from(&add_arr);
        let encrypter = self.key.encrypter().ok_or(RlsError::EncrypterNone)?;
        let nonce = Nonce::assume_unique_for_key(self.iv.as_array(self.seq));
        let payload = record.message.payload_mut().ok_or(RlsError::PayloadNone)?;
        payload.as_mut().splice(0..0, nonce.as_ref()[4..].to_vec());
        let tag = encrypter.seal_in_place_separate_tag(nonce, aad, &mut payload.as_mut()[8..])?;
        payload.as_mut().extend(tag.as_ref());
        record.len = payload.len() as u16;
        self.seq += 1;
        Ok(())
    }

    pub fn decrypt(&mut self, mut record: RecordLayer) -> RlsResult<Vec<u8>> {
        let add_arr = self.build_aad(&record, false)?;
        let aad = Aad::from(&add_arr);
        let decrypter = self.key.decrypter().ok_or(RlsError::DecrypterNone)?;
        let mut payload = record.message.take_payload().ok_or(RlsError::PayloadNone)?.to_bytes();
        let explicit = payload.drain(0..8).collect::<Vec<u8>>();
        self.iv.set_explicit(explicit);
        let nonce = Nonce::assume_unique_for_key(self.iv.as_ref());
        let out = decrypter.open_in_place(nonce, aad, &mut payload)?;
        let len = out.len();
        let content = payload.drain(0..len).collect::<Vec<u8>>();
        self.seq += 1;
        Ok(content)
    }
}


#[cfg(test)]
mod tests {
    use crate::cipher::Cipher;
    use crate::cipher::iv::Iv;
    use crate::cipher::key::Key;
    use crate::extend::Aead;
    use crate::{Message, RecordLayer, RecordType, Version};
    use crate::bytes::Bytes;
    use crate::version::VersionKind;

    #[test]
    fn test_cipher() {
        let mut cipher = Cipher::none();
        let key = rand::random::<[u8; 32]>().to_vec();
        let iv = rand::random::<[u8; 4]>();
        let explicit = rand::random::<[u8; 8]>();
        let key = Key::write(key, &Aead::AES_256_GCM).unwrap();
        let iv = Iv::new(iv.to_vec(), explicit.to_vec());
        cipher.set_key(key);
        cipher.set_iv(iv);
        let mut layer = RecordLayer {
            context_type: RecordType::HandShake,
            version: Version::new(VersionKind::TLS_1_2 as u16),
            len: 0,
            message: Message::Payload(Bytes::new(rand::random::<[u8; 16]>().to_vec())),
        };
        cipher.encrypt(&mut layer).unwrap();
        // let mut layer = RecordLayer {
        //     context_type: RecordType::ApplicationData,
        //     version: Version::new(VersionKind::TLS_1_2 as u16),
        //     len: 0,
        //     message: Message::Payload(Bytes::new("GET / HTTP/1.1\r\nHost: qnh.meituan.com\r\n\r\n".as_bytes().to_vec())),
        // };
        // cipher.encrypt(&mut layer).unwrap(); //单独运行这个不报错，在前面的Finish后会偶尔会报错
        // let _res = cipher.decrypt(layer).unwrap();
    }
}