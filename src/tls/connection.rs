use std::fs::OpenOptions;
use std::io::Write;
use crate::error::HlsResult;
use super::bytes::Bytes;
use super::cipher::iv::Iv;
use super::cipher::key::Key;
use super::cipher::suite::{CipherSuite, Hasher};
use super::cipher::Cipher;
use super::extend::alps::ALPN;
use super::message::key_exchange::NamedCurve;
use super::message::server_hello::ServerHello;
use super::message::Message;
use super::prf::Prf;
use super::version::Version;
use super::version::VersionKind;
use super::record::{RecordType, RecordLayer};

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
            prf: Prf::from_hasher(&Hasher::None),
        }
    }

    pub fn set_by_server_hello(&mut self, server_hello: ServerHello) {
        self.use_ems = server_hello.use_ems();
        self.alpn = server_hello.alpn();
        self.server_random = server_hello.random;
        self.cipher_suite = server_hello.cipher_suite;
        self.prf = Prf::from_hasher(self.cipher_suite.hasher());
    }

    pub fn set_by_exchange_key(&mut self, server_pub_key: Bytes, named_curve: NamedCurve) {
        self.server_pub_key = server_pub_key;
        self.named_curve = named_curve;
    }

    pub fn make_cipher(&mut self, share_secret: &[u8], session_hash: Vec<u8>) -> HlsResult<()> {
        let (label, seed) = match self.use_ems {
            true => ("extended master secret", session_hash),
            false => ("master secret", [self.client_random.as_bytes(), self.server_random.as_bytes()].concat())
        };
        let mut master_secret = [0u8; 48];
        self.prf.prf(&share_secret, label, &seed, &mut master_secret)?; //"master secret"
        let mut f = OpenOptions::new().create(true).append(true).open("2.log")?;
        f.write(format!("CLIENT_RANDOM {} {}\r\n", hex::encode(self.client_random.as_ref()), hex::encode(&master_secret)).as_bytes())?;
        f.flush()?;
        let aead = self.cipher_suite.aead().ok_or("aead none")?;
        let block_size = (aead.key_len() + 4) * 4 + 8;
        let mut key_block = Vec::with_capacity(block_size);
        key_block.resize(block_size, 0);
        let seed = [self.server_random.as_bytes(), self.client_random.as_bytes()].concat();
        self.prf.prf(&master_secret, "key expansion", &seed, key_block.as_mut_slice())?;
        let wk = key_block.drain(..aead.key_len()).collect::<Vec<_>>();
        let rk = key_block.drain(..aead.key_len()).collect::<Vec<_>>();
        let wi = key_block.drain(..4).collect::<Vec<_>>();
        let ri = key_block.drain(..4).collect::<Vec<_>>();
        let explicit = key_block.drain(..8).collect::<Vec<_>>();
        self.write.set_key(Key::write(wk, aead)?);
        self.write.set_iv(Iv::new(wi, explicit));
        self.read.set_key(Key::read(rk, aead)?);
        self.read.set_iv(Iv::new(ri, vec![]));
        self.master_secret = master_secret.to_vec();
        Ok(())
    }

    pub fn make_finish_message(&mut self, session_hash: &[u8]) -> HlsResult<RecordLayer> {
        let mut data = vec![0x14, 0x00, 0x0, 0xc];
        data.resize(16, 0);
        self.prf.prf(&self.master_secret, "client finished", &session_hash, &mut data[4..])?;
        let layer = self.make_message(RecordType::HandShake, data)?;
        Ok(layer)
    }

    pub fn make_message(&mut self, cty: RecordType, data: Vec<u8>) -> HlsResult<RecordLayer> {
        let mut layer = RecordLayer {
            context_type: cty,
            version: Version::new(VersionKind::TLS_1_2 as u16),
            len: 0,
            message: Message::Payload(Bytes::new(data)),
        };
        self.write.encrypt(&mut layer).unwrap();
        Ok(layer)
    }

    pub fn read_message(&mut self, layer: RecordLayer) -> HlsResult<Vec<u8>> {
        self.read.decrypt(layer)
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

    pub fn update_session(&mut self, data: impl AsRef<[u8]>) -> HlsResult<()> {
        if self.cipher_suite.hasher().is_none() {
            self.session_bytes.extend_from_slice(data.as_ref());
        } else {
            if !self.session_bytes.is_empty() {
                self.cipher_suite.update(&self.session_bytes)?;
                self.session_bytes.clear();
            }
            self.cipher_suite.update(data.as_ref())?;
        }
        Ok(())
    }

    pub fn session_hash(&self) -> HlsResult<Vec<u8>> {
        self.cipher_suite.session_hash()
    }
}