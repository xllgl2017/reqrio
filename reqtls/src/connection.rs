use super::bytes::Bytes;
use super::cipher::iv::Iv;
use super::cipher::key::Key;
use super::cipher::suite::CipherSuite;
use super::cipher::Cipher;
use super::extend::alps::ALPN;
use super::message::key_exchange::NamedCurve;
use super::message::server_hello::ServerHello;
use super::message::{Message, Payload};
use super::prf::Prf;
use super::record::{RecordLayer, RecordType};
use super::version::Version;
use super::version::VersionKind;
use crate::error::RlsResult;
use std::fs::OpenOptions;
use std::io::Write;
use crate::extend::Aead;
use crate::RlsError;

pub struct Connection {
    client_random: Bytes,
    server_random: Bytes,
    read: Cipher,
    write: Cipher,
    use_ems: bool,
    master_secret: Vec<u8>,
    named_curve: NamedCurve,
    server_pub_key: Bytes,
    alpn: Option<ALPN>,
    cipher_suite: CipherSuite,
    session_bytes: Vec<u8>,
    prf: Prf,
}
impl Connection {
    pub fn new(client_random: Vec<u8>) -> Connection {
        Connection {
            client_random: Bytes::new(client_random),
            server_random: Bytes::none(),
            read: Cipher::none(),
            write: Cipher::none(),
            use_ems: false,
            master_secret: vec![],
            named_curve: NamedCurve::x25519,
            server_pub_key: Bytes::none(),
            alpn: None,
            cipher_suite: CipherSuite::new(0),
            session_bytes: vec![],
            prf: Prf::default(),
        }
    }

    pub fn set_by_server_hello(&mut self, server_hello: ServerHello) -> RlsResult<()> {
        self.use_ems = server_hello.use_ems();
        self.alpn = server_hello.alpn();
        self.server_random = server_hello.random;
        self.cipher_suite = server_hello.cipher_suite;
        self.cipher_suite.init_aead_hasher()?;
        let hasher = self.cipher_suite.hasher().as_ref().ok_or(RlsError::HasherNone)?;
        self.prf = Prf::from_hasher(hasher);
        Ok(())
    }

    pub fn set_by_exchange_key(&mut self, server_pub_key: Bytes, named_curve: NamedCurve) {
        self.server_pub_key = server_pub_key;
        self.named_curve = named_curve;
    }

    pub fn make_cipher(&mut self, share_secret: &[u8], session_hash: Vec<u8>) -> RlsResult<()> {
        let (label, seed) = match self.use_ems {
            true => ("extended master secret", session_hash),
            false => ("master secret", [self.client_random.as_bytes(), self.server_random.as_bytes()].concat())
        };
        let mut master_secret = [0u8; 48];
        self.prf.prf(&share_secret, label, &seed, &mut master_secret)?; //"master secret"
        let mut f = OpenOptions::new().create(true).append(true).open("2.log")?;
        f.write(format!("CLIENT_RANDOM {} {}\r\n", hex::encode(self.client_random.as_ref()), hex::encode(&master_secret)).as_bytes())?;
        f.flush()?;
        let aead = self.cipher_suite.aead().ok_or(RlsError::AeadNone)?;
        let block_size = (aead.key_len() + aead.fix_iv_len()) * 2 + aead.explicit_len();
        let mut key_block = Vec::with_capacity(block_size);
        key_block.resize(block_size, 0);
        let seed = [self.server_random.as_bytes(), self.client_random.as_bytes()].concat();
        self.prf.prf(&master_secret, "key expansion", &seed, key_block.as_mut_slice())?;
        let (wk, remain) = key_block.split_at(aead.key_len());
        let (rk, remain) = remain.split_at(aead.key_len());
        let (wi, remain) = remain.split_at(aead.fix_iv_len());
        let (ri, remain) = remain.split_at(aead.fix_iv_len());
        let (explicit, _) = remain.split_at(aead.explicit_len());
        self.write.set_key(Key::write(wk, aead)?);
        self.write.set_iv(Iv::new(wi, explicit.to_vec()));
        self.read.set_key(Key::read(rk, aead)?);
        self.read.set_iv(Iv::new(ri, vec![]));
        self.master_secret = master_secret.to_vec();
        Ok(())
    }

    ///#### tls Record结构-5bytes(头部)
    /// * aes-gcm: payload(8byte的explicit+16payload+16byte的tag)
    /// * chacha20_poly1305: payload(16payload+16byte tag)
    pub fn make_finish_message<'a>(&mut self, session_hash: &[u8], buffer: &'a mut [u8]) -> RlsResult<usize> {
        let aead = self.cipher_suite.aead().ok_or(RlsError::AeadNone)?;
        buffer[aead.payload_start()..aead.payload_start() + 4].copy_from_slice(&[0x14, 0x00, 0x0, 0xc]);
        self.prf.prf(&self.master_secret, "client finished", &session_hash, &mut buffer[aead.payload_start() + 4..aead.payload_start() + 16])?;
        self.make_message(RecordType::HandShake, buffer, 16)
    }

    pub fn make_message(&mut self, cty: RecordType, buffer: &mut [u8], payload_len: usize) -> RlsResult<usize> {
        let aead = self.cipher_suite.aead().ok_or(RlsError::AeadNone)?;
        let payload_len = aead.encrypted_payload_len(payload_len);
        buffer[0] = cty.as_u8();
        buffer[1..3].copy_from_slice(&(VersionKind::TLS_1_2 as u16).to_be_bytes());
        buffer[3..5].copy_from_slice(&(payload_len as u16).to_be_bytes());
        let payload = &mut buffer[5..payload_len + 5];
        let mut layer = RecordLayer {
            context_type: cty,
            version: Version::new(VersionKind::TLS_1_2 as u16),
            len: payload_len as u16,
            messages: vec![Message::Payload(Payload::from_slice(payload))],
        };
        self.write.encrypt(&mut layer, self.cipher_suite.aead().ok_or(RlsError::AeadNone)?)?;
        Ok(payload_len + 5)
    }

    pub fn read_message<'a>(&mut self, layer: &'a mut RecordLayer<'a>) -> RlsResult<usize> {
        self.read.decrypt(layer, self.cipher_suite.aead().ok_or(RlsError::AeadNone)?)
    }

    pub fn named_curve(&self) -> &NamedCurve {
        &self.named_curve
    }

    pub fn server_pub_key(&self) -> &Bytes {
        &self.server_pub_key
    }

    pub fn alpn(&self) -> Option<&ALPN> {
        self.alpn.as_ref()
    }

    pub fn update_session(&mut self, data: impl AsRef<[u8]>) -> RlsResult<()> {
        if self.cipher_suite.hasher().is_none() {
            self.session_bytes.extend_from_slice(data.as_ref());
        } else {
            if !self.session_bytes.is_empty() {
                self.cipher_suite.update(&self.session_bytes);
                self.session_bytes.clear();
            }
            self.cipher_suite.update(data.as_ref());
        }
        Ok(())
    }

    pub fn session_hash(&self) -> RlsResult<Vec<u8>> {
        self.cipher_suite.session_hash()
    }

    pub fn aead(&self) -> Option<&Aead> {
        self.cipher_suite.aead()
    }
}