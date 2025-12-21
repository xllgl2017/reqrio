use std::fmt::{Debug, Formatter};
use super::super::bytes::Bytes;

pub struct KeyShareType(u16);
impl KeyShareType {
    pub fn new(v: u16) -> Self {
        KeyShareType(v)
    }

    pub fn as_bytes(&self) -> [u8; 2] {
        self.0.to_be_bytes()
    }
}

impl Debug for KeyShareType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match KeyShareKind::from_u16(self.0) {
            None => f.write_str(&format!("Reserved({})", self.0)),
            Some(kind) => f.write_str(&format!("{:?}", kind))
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug)]
pub enum KeyShareKind {
    X25519MLKEM768 = 0x11ec, //len 1216
    x25519 = 0x1d, //len 32
    // MLKEM768 = 0x6a6a, //len 1184
}

impl KeyShareKind {
    pub fn from_u16(v: u16) -> Option<KeyShareKind> {
        match v {
            0x11ec => Some(KeyShareKind::X25519MLKEM768),
            0x1d => Some(KeyShareKind::x25519),
            _ => None
        }
    }

    // pub fn gen_x25519(&self) -> (EphemeralSecret, PublicKey) {
    //     let mut rng = rand::rngs::ThreadRng::default();
    //     let keypair = EphemeralSecret::random_from_rng(&mut rng);
    //     let alice_public = PublicKey::from(&keypair);
    //     (keypair, alice_public)
    // }
    //
    // fn gen_x25519mlkem768(&self) -> (EphemeralSecret, PublicKey) {
    //     let mut rng = rand::rngs::ThreadRng::default();
    //     let keypair = EphemeralSecret::random_from_rng(&mut rng);
    //     let alice_public = PublicKey::from(&keypair);
    //     let (pq_pub, pq_sec) = pqcrypto_kyber::kyber768::keypair();
    //
    // }
}

#[derive(Debug)]
pub struct KeyShareEntry {
    group: KeyShareType,
    exchange_len: u16,
    exchange: Bytes,
}

impl KeyShareEntry {
    fn new() -> KeyShareEntry {
        KeyShareEntry {
            group: KeyShareType(0),
            exchange_len: 0,
            exchange: Bytes::none(),
        }
    }

    fn from_bytes(bytes: &[u8]) -> Vec<KeyShareEntry> {
        let mut index = 0;
        let mut res = vec![];
        while index < bytes.len() {
            let mut key = KeyShareEntry::new();
            key.group = KeyShareType::new(u16::from_be_bytes([bytes[index], bytes[index + 1]]));
            key.exchange_len = u16::from_be_bytes([bytes[index + 2], bytes[index + 3]]);
            index = index + 4 + key.exchange_len as usize;
            key.exchange = Bytes::new(bytes[index - key.exchange_len as usize..index].to_vec());
            res.push(key);
        }
        res
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = self.group.as_bytes().to_vec();
        let vs = self.exchange.as_bytes();
        res.extend((vs.len() as u16).to_be_bytes());
        res.extend(vs);
        res
    }
}

#[derive(Debug)]
pub struct KeyShare {
    len: usize,
    entries: Vec<KeyShareEntry>,
}

impl KeyShare {
    pub fn new() -> KeyShare {
        KeyShare {
            len: 0,
            entries: vec![],
        }
    }
    pub fn from_bytes(bytes: &[u8]) -> KeyShare {
        let mut res = KeyShare::new();
        res.len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        res.entries = KeyShareEntry::from_bytes(&bytes[2..res.len + 2]);
        res
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = (self.len as u16).to_be_bytes().to_vec();
        for entry in &self.entries {
            res.extend(entry.as_bytes());
        }
        res
    }
}

