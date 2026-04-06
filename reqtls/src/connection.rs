use super::bytes::Bytes;
use super::message::key_exchange::{NamedCurve, ServerKeyExchange};
use super::message::server_hello::{ServerHello, ServerHelloDone};
use super::prf::Prf;
use super::record::{RecordLayer, RecordType};
use super::suite::iv::Iv;
use super::suite::CipherSuite;
use super::suite::TlsCipher;
use super::version::Version;
use crate::boring::{certificate, AlgorithmSigner, HashError};
use crate::buffer::{Buf, RecordDecodeBuffer, RecordEncodeBuffer};
use crate::error::RlsResult;
use crate::message::certificate::CertificateRequest;
use crate::share_key::SharedKey;
use crate::*;
use std::fs::OpenOptions;
use std::io::Write;
use std::mem;

pub struct Connection {
    client_random: [u8; 32],
    server_random: [u8; 32],
    read: TlsCipher,
    write: TlsCipher,
    use_ems: bool,
    master_secret: [u8; 48],
    named_curve: NamedCurve,
    exchange_pub_key: Bytes,
    alpn: Option<ALPN>,
    cipher_suite: CipherSuite,
    session_bytes: Vec<u8>,
    prf: Prf,
    certificates: Vec<Certificate>,
    shared_key: SharedKey,
    verify: bool,
    root_stores: &'static CertStore,
    mtls_hash: SignatureAlgorithm,
    version: Version,
}
impl Default for Connection {
    fn default() -> Self {
        Connection {
            client_random: rand::random(),
            server_random: [0; 32],
            read: TlsCipher::none(),
            write: TlsCipher::none(),
            use_ems: false,
            master_secret: [0; 48],
            named_curve: NamedCurve::x25519,
            exchange_pub_key: Bytes::none(),
            alpn: None,
            cipher_suite: CipherSuite::new(0),
            session_bytes: vec![],
            prf: Prf::default(),
            certificates: vec![],
            shared_key: SharedKey::None,
            verify: false,
            root_stores: &certificate::ROOT_STORES,
            mtls_hash: SignatureAlgorithm::new(0),
            version: Version::TLS_1_2,
        }
    }
}

impl Connection {
    pub fn client_random(&self) -> &[u8] {
        &self.client_random
    }

    pub fn with_verify(mut self, verify: bool) -> Connection {
        self.verify = verify;
        self
    }

    pub fn disable_verify(mut self) -> Connection {
        self.verify = false;
        self
    }

    pub fn set_by_server_hello(&mut self, server_hello: &ServerHello) -> RlsResult<()> {
        self.use_ems = server_hello.use_ems();
        self.alpn = server_hello.alpn();
        self.server_random = server_hello.random.as_ref().try_into()?;
        self.cipher_suite = server_hello.cipher_suite.clone();
        self.cipher_suite.init_aead_hasher()?;
        self.cipher_suite.update(&self.session_bytes)?;
        let hasher = self.cipher_suite.hasher().as_ref().ok_or(HashError::HasherNone)?;
        self.prf = Prf::from_hasher(hasher);
        Ok(())
    }

    pub fn set_by_certificate(&mut self, certificate: Certificates, ext_cas: &[Certificate], sni: &str) -> RlsResult<()> {
        for certificate in certificate.certificates() {
            self.certificates.push(Certificate::from_der(certificate.as_ref())?);
        }
        if !self.verify { return Ok(()); }
        self.root_stores.verify_cert(&mut self.certificates, ext_cas, sni)
    }

    fn gen_key_sign_data(&self, server_key: &ServerKeyExchange) -> Vec<u8> {
        let mut sign_data = vec![];
        sign_data.extend_from_slice(self.client_random.as_ref());
        sign_data.extend_from_slice(self.server_random.as_ref());
        sign_data.push(*server_key.hellman_param().curve_type() as u8);
        sign_data.extend(server_key.hellman_param().named_curve().as_u16().to_be_bytes());
        sign_data.push(server_key.hellman_param().pub_key().len() as u8);
        sign_data.extend(server_key.hellman_param().pub_key().as_bytes());
        sign_data
    }

    pub fn set_by_cert_req(&mut self, req: CertificateRequest, cert: Option<&mut Certificate>) -> RlsResult<()> {
        if let Some(cert) = cert {
            for hash in req.into_hashes() {
                match (&hash, cert.cert_type()?) {
                    (&SignatureAlgorithm::RSA_PSS_RSAE_SHA256, CertType::RSA) => self.mtls_hash = hash,
                    (&SignatureAlgorithm::RSA_PSS_RSAE_SHA384, CertType::RSA) => self.mtls_hash = hash,
                    (&SignatureAlgorithm::RSA_PSS_RSAE_SHA512, CertType::RSA) => self.mtls_hash = hash,
                    (&SignatureAlgorithm::ECDSA_SECP256R1_SHA256, CertType::ECDSA) => self.mtls_hash = hash,
                    (&SignatureAlgorithm::ECDSA_SECP384R1_SHA384, CertType::ECDSA) => self.mtls_hash = hash,
                    (&SignatureAlgorithm::ECDSA_SECP521R1_SHA512, CertType::ECDSA) => self.mtls_hash = hash,
                    (&SignatureAlgorithm::RSA_PKCS1_SHA1, CertType::RSA) => self.mtls_hash = hash,
                    (&SignatureAlgorithm::RSA_PKCS1_SHA256, CertType::RSA) => self.mtls_hash = hash,
                    (&SignatureAlgorithm::RSA_PKCS1_SHA384, CertType::RSA) => self.mtls_hash = hash,
                    (&SignatureAlgorithm::RSA_PKCS1_SHA512, CertType::RSA) => self.mtls_hash = hash,
                    _ => continue,
                }
                break;
            }
        } else { self.mtls_hash = SignatureAlgorithm::RSA_PKCS1_SHA1 }
        Ok(())
    }

    pub fn set_by_server_exchange_key(&mut self, server_key: ServerKeyExchange) -> RlsResult<()> {
        if self.verify {
            let sign_data = self.gen_key_sign_data(&server_key);
            let signature = AlgorithmSigner::new_verify(self.certificates[0].pub_key()?, server_key.hellman_param().signature_algorithm())?;
            signature.verify(sign_data, server_key.hellman_param().signature().as_ref())?;
        }
        self.exchange_pub_key = server_key.hellman_param().pub_key().clone();
        self.named_curve = *server_key.hellman_param().named_curve();
        self.shared_key = SharedKey::new(&self.named_curve)?;
        Ok(())
    }

    pub fn set_by_client_exchange_key(&mut self, client_key: ClientKeyExchange) {
        self.exchange_pub_key = Bytes::new(client_key.hellman_param().pub_key().to_vec());
    }

    pub fn pub_share_key(&mut self) -> RlsResult<Buf<'_>> {
        if let SharedKey::None = self.shared_key {
            self.shared_key = SharedKey::new_pre_master_secret()?;
            let rsa = RsaCipher::new(self.certificates[0].pub_key()?)?;
            return Ok(Buf::Vec(rsa.encrypt(self.shared_key.pub_key()?.as_ref())?));
        }
        self.shared_key.pub_key()
    }

    pub fn make_cipher(&mut self, server: bool) -> RlsResult<()> {
        let share_secret = self.shared_key.diffie_hellman(self.exchange_pub_key.as_ref())?;
        let (label, seed) = match self.use_ems {
            true => ("extended master secret", self.cipher_suite.current_session_hash()?.to_vec()),
            false => ("master secret", [self.client_random, self.server_random].concat())
        };
        self.prf.prf(&share_secret, label, &seed, &mut self.master_secret)?;
        let mut f = OpenOptions::new().create(true).append(true).open("2.log")?;
        f.write_all(format!("CLIENT_RANDOM {} {}\r\n", hex::encode(self.client_random.as_ref()), hex::encode(self.master_secret)).as_bytes())?;
        let aead = self.cipher_suite.aead().ok_or(RlsError::AeadNone)?;
        let block_size = (aead.mac_key_len() + aead.key_len() + aead.fix_iv_len()) * 2 + aead.explicit_len();
        let mut key_block = vec![0; block_size];
        let seed = [self.server_random, self.client_random].concat();
        self.prf.prf(&self.master_secret, "key expansion", &seed, key_block.as_mut_slice())?;
        let (client_mac_key, remain) = key_block.split_at(aead.mac_key_len());
        let (server_mac_key, remain) = remain.split_at(aead.mac_key_len());
        let (client_key, remain) = remain.split_at(aead.key_len());
        let (server_key, remain) = remain.split_at(aead.key_len());
        let (client_iv, remain) = remain.split_at(aead.fix_iv_len());
        let (server_iv, explicit) = remain.split_at(aead.fix_iv_len());
        let hasher = self.cipher_suite.mac_hash().ok_or(HashError::HasherNone)?;
        match server {
            true => {
                self.write.set_key(server_key, server_mac_key, aead, hasher)?;
                self.write.set_iv(Iv::new(server_iv, vec![0; 8]));
                self.read.set_key(client_key, client_mac_key, aead, hasher)?;
                self.read.set_iv(Iv::new(client_iv, vec![]));
            }
            false => {
                self.write.set_key(client_key, client_mac_key, aead, hasher)?;
                self.write.set_iv(Iv::new(client_iv, explicit.to_vec()));
                self.read.set_key(server_key, server_mac_key, aead, hasher)?;
                self.read.set_iv(Iv::new(server_iv, vec![]));
            }
        }

        Ok(())
    }

    pub fn gen_server_hello<'a>(&mut self, mut client_hello: ClientHello, certificate: &'a mut [Certificate], pri_key: &RsaKey, random: &'a [u8]) -> RlsResult<RecordLayer<'a>> {
        self.client_random = client_hello.client_random().as_ref().try_into()?;
        let mut record = RecordLayer {
            context_type: RecordType::HandShake,
            version: Version::TLS_1_2,
            len: 0,
            messages: vec![],
        };
        //server hello
        let mut server_hello = ServerHello::from_client_hello(client_hello)?;
        server_hello.set_random(random);
        self.set_by_server_hello(&server_hello)?;
        record.messages.push(Message::ServerHello(server_hello));
        //certificate
        let mut certificates = Certificates::default();
        for certificate in certificate.iter_mut() {
            certificates.add_certificate(certificate.as_der()?.as_slice());
        }
        record.messages.push(Message::Certificate(certificates));
        //server_key_exchange
        let mut server_key_exchange = ServerKeyExchange::default();
        self.shared_key = SharedKey::new(server_key_exchange.hellman_param().named_curve())?;
        server_key_exchange.hellman_param_mut().set_pub_key(self.shared_key.pub_key()?.as_ref());
        let sign_data = self.gen_key_sign_data(&server_key_exchange);
        let signer = AlgorithmSigner::new_sign(pri_key.pkey(), server_key_exchange.hellman_param().signature_algorithm())?;
        server_key_exchange.hellman_param_mut().set_signature(Bytes::new(signer.sign(&sign_data)?));
        self.exchange_pub_key = server_key_exchange.hellman_param().pub_key().clone();
        self.named_curve = *server_key_exchange.hellman_param().named_curve();
        record.messages.push(Message::ServerKeyExchange(server_key_exchange));
        //server_hello_done
        record.messages.push(Message::ServerHelloDone(ServerHelloDone::new()));
        Ok(record)
    }

    ///#### tls Record结构-5bytes(头部)
    /// * aes-gcm: payload(8byte的explicit+16payload+16byte的tag)
    /// * chacha20_poly1305: payload(16payload+16byte tag)
    pub fn make_finish_message(&mut self, buffer: &mut [u8], server: bool) -> RlsResult<usize> {
        let finish = self.make_verify_data(server)?;
        self.update_session(finish)?;
        self.make_message(RecordType::HandShake, buffer, &finish)
    }

    pub fn verify_finish(&mut self, data: &[u8], server: bool) -> RlsResult<()> {
        if !self.verify {
            self.update_session(data)?;
            return Ok(());
        }
        let out = self.make_verify_data(server)?;
        self.update_session(data)?;
        if data != out { return Err(RlsError::Currently("FinishVerifyFail".into())); }
        Ok(())
    }

    fn make_verify_data(&mut self, server: bool) -> RlsResult<[u8; 16]> {
        let mut finish = [0; 16];
        finish[0..4].copy_from_slice(&[0x14, 0x00, 0x0, 0xc]);
        let session_hash = self.cipher_suite.current_session_hash()?;
        self.prf.prf(&self.master_secret, if !server { "client finished" } else { "server finished" }, session_hash, &mut finish[4..16])?;
        Ok(finish)
    }

    pub fn make_message(&mut self, cty: RecordType, buffer: &mut [u8], payload: &[u8]) -> RlsResult<usize> {
        let aead = self.cipher_suite.aead().ok_or(RlsError::AeadNone)?;
        let buffer = RecordEncodeBuffer::new(cty, &self.version, buffer, payload, aead);
        self.write.encrypt(buffer)
    }

    pub fn read_message(&mut self, origin: &[u8], buffer: &mut [u8]) -> RlsResult<usize> {
        let aead = self.cipher_suite.aead().ok_or(RlsError::AeadNone)?;
        let buffer = RecordDecodeBuffer::from_buffer(origin, buffer, aead)?;
        self.read.decrypt(buffer)
    }

    pub fn alpn(&self) -> Option<&ALPN> {
        self.alpn.as_ref()
    }

    pub fn update_session(&mut self, data: impl AsRef<[u8]>) -> RlsResult<()> {
        if self.mtls() || self.cipher_suite.hasher().is_none() {
            self.session_bytes.extend_from_slice(data.as_ref());
        }
        if self.cipher_suite.hasher().is_some() {
            self.cipher_suite.update(data)?;
        }
        Ok(())
    }

    pub fn cipher_suite(&self) -> &CipherSuite { &self.cipher_suite }

    pub fn mtls(&self) -> bool { self.mtls_hash.as_u16() != 0 }
    pub fn handle_mtls_client<W: WriteExt>(&mut self, writer: &mut W, key: &RsaKey) -> RlsResult<usize> {
        let mut cert_verify = CertificateVerify::default();
        cert_verify.set_hash(self.mtls_hash.clone());
        let signer = AlgorithmSigner::new_sign(key.pkey(), &self.mtls_hash)?;
        let sign = signer.sign(mem::take(&mut self.session_bytes))?;
        cert_verify.set_sign(&sign);
        let mut record = RecordLayer::handshake();
        record.messages.push(Message::CertificateVerify(cert_verify));
        record.write_to(writer, 1)
    }
}