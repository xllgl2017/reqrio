use super::block::{KeyBlock, TlsSession};
use super::{Key, TrafficSecret};
use crate::error::RlsResult;
use crate::hkdf::Hkdf;
use crate::prf::Prf;
use crate::{CipherSuite, HandShakeError, HashType, Hmac, Version};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

pub(crate) struct DerivedKey {
    prf: Prf,
    hash: HashType,
    client_random: [u8; 32],
    server_random: [u8; 32],
    use_ems: bool,
    traffic_secret: TrafficSecret,
    key_block: KeyBlock,
    prk: Vec<u8>,
    session: TlsSession,
    key_log: Option<PathBuf>,
}

impl DerivedKey {
    const ZERO: [u8; 64] = [0; 64];
    pub fn new(client_random: [u8; 32], server_random: [u8; 32], session: TlsSession, key_log: Option<PathBuf>) -> Self {
        DerivedKey {
            prf: Prf::default(),
            hash: HashType::Sha256,
            client_random,
            server_random,
            use_ems: false,
            traffic_secret: TrafficSecret {
                client_traffic: [0; 48],
                server_traffic: [0; 48],
                size: 32,
            },
            key_block: KeyBlock::default(),
            prk: vec![],
            session,
            key_log,
        }
    }


    pub fn init(&mut self, suite: &'static CipherSuite) {
        self.prf = Prf::from_hasher(suite.hash());
        self.hash = suite.hash();
        self.traffic_secret.size = self.hash.hash_size();
        self.key_block.init(suite);
    }

    ///gen tls 1.2 master secret key
    fn make_tls12_master(&mut self, share_secret: Vec<u8>, session_hash: &[u8]) -> RlsResult<()> {
        let (label, seed) = match self.use_ems {
            true => ("extended master secret", session_hash.to_vec()),
            false => ("master secret", [self.client_random, self.server_random].concat())
        };
        self.prf.prf(&share_secret, label, &seed, self.session.master_secret_mut())?;
        self.export_key("CLIENT_RANDOM", hex::encode(self.session.master_secret()))?;
        Ok(())
    }

    fn export_key(&self, label: &str, key: String) -> RlsResult<()> {
        if let Some(ref key_log) = self.key_log {
            let mut f = OpenOptions::new().create(true).append(true).open(key_log)?;
            write!(f, "{} {} {}\r\n", label, hex::encode(self.client_random), key)?;
        }
        Ok(())
    }

    pub fn make_handshake_traffic_secret(&mut self, share_secret: Vec<u8>, session_hash: &[u8]) -> RlsResult<()> {
        let mut derived_hkdf = Hkdf::new(&[], &Self::ZERO[..self.hash.hash_size()], self.hash)?;
        let mut derived = vec![0; self.hash.hash_size()];
        derived_hkdf.hkdf("tls13 derived", self.hash.tls13_secret()?, &mut derived)?;
        //client handshake traffic
        let mut hkdf = Hkdf::new(&derived, &share_secret, self.hash)?;
        hkdf.hkdf("tls13 c hs traffic", session_hash, self.traffic_secret.client_traffic_mut())?;
        self.export_key("CLIENT_HANDSHAKE_TRAFFIC_SECRET", hex::encode(self.traffic_secret.client_traffic()))?;
        //server handshake traffic
        hkdf.hkdf("tls13 s hs traffic", session_hash, self.traffic_secret.server_traffic_mut())?;
        self.prk = hkdf.into_prk().to_vec();
        self.export_key("SERVER_HANDSHAKE_TRAFFIC_SECRET", hex::encode(self.traffic_secret.server_traffic()))?;
        Ok(())
    }

    pub fn make_application_traffic_secret(&mut self, session_hash: &[u8]) -> RlsResult<()> {
        let mut hkdf = Hkdf::from_prk(&self.prk, self.hash);
        let mut salt = vec![0; self.hash.hash_size()];
        hkdf.hkdf("tls13 derived", self.hash.tls13_secret()?, &mut salt)?;
        let mut hkdf = Hkdf::new(&salt, &Self::ZERO[..self.hash.hash_size()], self.hash)?;
        hkdf.hkdf("tls13 c ap traffic", session_hash, self.traffic_secret.client_traffic_mut())?;
        self.export_key("CLIENT_TRAFFIC_SECRET_0", hex::encode(self.traffic_secret.client_traffic()))?;
        hkdf.hkdf("tls13 s ap traffic", session_hash, self.traffic_secret.server_traffic_mut())?;
        self.export_key("SERVER_TRAFFIC_SECRET_0", hex::encode(self.traffic_secret.server_traffic()))?;
        Ok(())
    }

    ///make tls1.3 finish verify data
    fn make_tls13_finish(&self, server: bool, session_hash: &[u8]) -> RlsResult<Vec<u8>> {
        let traffic_secret = match server {
            true => self.traffic_secret.server_traffic(),
            false => self.traffic_secret.client_traffic()
        };
        let mut hkdf = Hkdf::from_prk(traffic_secret, self.hash);
        let mut out = vec![0; self.hash.hash_size() + 4];
        out[0] = 20;
        out[3] = self.hash.hash_size() as u8;
        hkdf.hkdf("tls13 finished", &[], &mut out[4..])?;
        let mut hmac = Hmac::new(&out[4..], self.hash)?;
        hmac.update(session_hash)?;
        hmac.finalize_extract(&mut out[4..])?;
        Ok(out)
    }

    ///make tls1.2 finish verify data
    fn make_tls12_finish(&self, server: bool, session_hash: &[u8]) -> RlsResult<Vec<u8>> {
        let mut finish = vec![0; 16];
        finish[0..4].copy_from_slice(&[0x14, 0x00, 0x0, 0xc]);
        let label = if !server { "client finished" } else { "server finished" };
        self.prf.prf(self.session.master_secret(), label, session_hash, &mut finish[4..16])?;
        Ok(finish)
    }

    pub fn make_master(&mut self, version: Version, share_secret: Vec<u8>, session_hash: &[u8]) -> RlsResult<()> {
        match version {
            Version::TLS_1_2 => self.make_tls12_master(share_secret, session_hash),
            Version::TLS_1_3 => Ok(()),
            _ => Err(HandShakeError::UnsupportedVersion(version).into()),
        }
    }

    fn make_tls12_cipher_key(&mut self) -> RlsResult<&KeyBlock> {
        let seed = [self.server_random, self.client_random].concat();
        self.prf.prfs(self.session.master_secret(), "key expansion", &seed, self.key_block.bufs())?;
        Ok(&self.key_block)
    }

    pub fn make_tls13_cipher_key(&mut self) -> RlsResult<&KeyBlock> {
        //client
        let mut hkdf = Hkdf::from_prk(self.traffic_secret.client_traffic(), self.hash);
        hkdf.hkdf("tls13 key", &[], self.key_block.client_key_mut())?;
        hkdf.hkdf("tls13 iv", &[], self.key_block.client_iv_mut())?;
        //server
        let mut hkdf = Hkdf::from_prk(self.traffic_secret.server_traffic(), self.hash);
        hkdf.hkdf("tls13 key", &[], self.key_block.server_key_mut())?;
        hkdf.hkdf("tls13 iv", &[], self.key_block.server_iv_mut())?;
        Ok(&self.key_block)
    }


    pub fn make_cipher_key(&mut self, version: &Version, server: bool) -> RlsResult<Key<'_>> {
        Ok(match *version {
            Version::TLS_1_2 => self.make_tls12_cipher_key()?,
            Version::TLS_1_3 => self.make_tls13_cipher_key()?,
            _ => return Err(HandShakeError::UnsupportedVersion(*version).into()),
        }.get_side(version, server))
    }


    pub fn make_finish(&self, version: Version, server: bool, session_hash: &[u8]) -> RlsResult<Vec<u8>> {
        match version {
            Version::TLS_1_2 => self.make_tls12_finish(server, session_hash),
            Version::TLS_1_3 => self.make_tls13_finish(server, session_hash),
            _ => Err(HandShakeError::UnsupportedVersion(version).into()),
        }
    }

    pub fn set_client_random(&mut self, client_random: [u8; 32]) {
        self.client_random = client_random;
    }

    pub fn set_server_random(&mut self, server_random: [u8; 32]) {
        self.server_random = server_random;
    }

    pub fn client_random(&self) -> &[u8] {
        &self.client_random
    }

    pub fn server_random(&self) -> &[u8] {
        &self.server_random
    }

    pub fn set_ems(&mut self, ems: bool) {
        self.use_ems = ems
    }

    pub fn session(&self) -> &TlsSession { &self.session }

    pub fn session_mut(&mut self) -> &mut TlsSession { &mut self.session }
}