#[cfg(feature = "quic")]
mod quic;

use super::bytes::Bytes;
use super::record::{RecordLayer, RecordType};
use super::suite::iv::Iv;
use super::suite::CipherSuite;
use super::suite::TlsCipher;
use super::version::Version;
use crate::boring::{certificate, AlgorithmSigner};
use crate::buffer::{Buf, CipherDecodeBuffer, CipherEncodeBuffer};
use crate::error::{HandShakeError, RlsResult};
use crate::key::{DerivedKey, KeyType, SecretKey, TlsSession};
use crate::message::{CompressedCertificate, EncryptedExtension, HandshakeType};
use crate::*;
#[cfg(feature = "quic")]
pub use quic::QUICConnection;
use std::collections::HashMap;
use std::mem;
use std::path::PathBuf;

pub struct Connection {
    pub(crate) recv_cipher: TlsCipher,
    pub(crate) send_cipher: TlsCipher,
    named_curve: NamedCurve,
    exchange_pub_key: Bytes,
    alpn: Option<ALPN>,
    cipher_suite: &'static CipherSuite,
    session_bytes: Vec<u8>,
    pub(crate) derived: DerivedKey,
    certificates: Vec<Certificate>,
    secret_keys: HashMap<NamedCurve, SecretKey>,
    secret_key: Option<SecretKey>,
    verify: bool,
    root_stores: &'static CertStore,
    sig_alg: SignatureAlgorithm,
    mtls_hash: SignatureAlgorithm,
    mtls_enable: bool,
    version: Version,
    server: bool,
    hasher: Hasher,
}
impl Default for Connection {
    fn default() -> Self {
        Connection::new([0; 32], [0; 32], TlsSession::default(), None, false)
    }
}

impl Connection {
    const HRR_MAGIC: [u8; 32] = [207, 33, 173, 116, 229, 154, 97, 17, 190, 29, 140, 2, 30, 101, 184, 145, 194, 162, 17, 22, 122, 187, 140, 94, 7, 158, 9, 226, 200, 168, 51, 156];

    pub fn new(client_random: [u8; 32], server_random: [u8; 32], session: TlsSession, key_log: Option<PathBuf>, quic: bool) -> Connection {
        Connection {
            recv_cipher: TlsCipher::none(),
            send_cipher: TlsCipher::none(),
            named_curve: NamedCurve::X25519.into(),
            exchange_pub_key: Bytes::none(),
            alpn: None,
            cipher_suite: &CipherSuite::UNKNOWN,
            session_bytes: Vec::with_capacity(4096),
            derived: DerivedKey::new(client_random, server_random, session, key_log, quic),
            certificates: vec![],
            verify: false,
            root_stores: &certificate::ROOT_STORES,
            mtls_hash: SignatureAlgorithm::new(0),
            mtls_enable: false,
            version: Version::TLS_1_2,
            secret_keys: HashMap::new(),
            secret_key: None,
            server: false,
            hasher: Hasher::default(),
            sig_alg: SignatureAlgorithm::new(0),
        }
    }

    pub fn new_client(session: TlsSession, key_log: Option<PathBuf>, quic: bool) -> Connection {
        Connection::new(rand::random(), [0; 32], session, key_log, quic)
    }

    pub fn client_random(&self) -> &[u8] {
        self.derived.client_random()
    }

    pub fn with_verify(mut self, verify: bool) -> Connection {
        self.verify = verify;
        self
    }

    pub fn disable_verify(mut self) -> Connection {
        self.verify = false;
        self
    }

    pub fn with_mtls(mut self, mtls: bool) -> Connection {
        self.mtls_enable = mtls;
        self
    }

    pub fn hello_retry(&mut self, client_hello: &[u8]) -> RlsResult<()> {
        let cl = u32::from_be_bytes([0, self.session_bytes[1], self.session_bytes[2], self.session_bytes[3]]) as usize + 4;
        self.hasher.update(&self.session_bytes[..cl])?;
        let session_hash = self.hasher.current_hash()?;
        self.session_bytes[0] = HandshakeType::MessageHash as u8;
        self.session_bytes[1] = 0;
        self.session_bytes[2] = 0;
        self.session_bytes[3] = session_hash.len() as u8;
        self.session_bytes[4..session_hash.len() + 4].copy_from_slice(session_hash);
        let len = self.session_bytes.len();
        self.session_bytes.copy_within(cl..len, session_hash.len() + 4);
        unsafe { self.session_bytes.set_len(session_hash.len() + 4 + len - cl); }
        self.hasher = Hasher::default();
        self.update_session(client_hello)
    }

    pub fn set_by_server_hello(&mut self, server_hello: &ServerHello, version: Version) -> RlsResult<bool> {
        self.alpn = server_hello.alpn();
        self.derived.session_mut().set_session_id(server_hello.session_id.as_ref());
        self.cipher_suite = server_hello.cipher_suite;
        self.hasher.init(self.cipher_suite.hash())?;
        if let Some(version) = server_hello.supported_version() {
            self.version = *version;
        } else { self.version = version; }
        if server_hello.random().as_ref() == Self::HRR_MAGIC { return Ok(true); }
        self.hasher.update(&self.session_bytes)?;
        #[cfg(feature = "log")]
        info!("[ParsedServerHello] Version: {:?} | CipherSuite: {} | Hasher: {:?} | AEAD: {:?}",
            self.version, self.cipher_suite.spec(), self.cipher_suite.hash(), self.cipher_suite.aead());
        self.derived.init(KeyType::Handshake, self.cipher_suite);
        self.derived.set_server_random(server_hello.random.as_ref().try_into()?);
        self.derived.set_ems(server_hello.use_ems());
        if Version::TLS_1_3 == self.version {
            let key_entry = server_hello.key_share_extend().ok_or(RlsError::MissingKeyEntry)?.key_entry();
            self.named_curve = *key_entry.name_curve();
            let mut secret_key = self.secret_keys.remove(key_entry.name_curve()).ok_or("secret not inited")?;
            let share_secret = secret_key.diffie_hellman(key_entry.exchange_key().as_ref())?;
            self.derived.make_handshake_traffic_secret(share_secret, self.hasher.current_hash()?)?;
            #[cfg(feature = "log")]
            info!("[ParsedServerHello] KeyShare={:?}; pubkey={}",key_entry.name_curve(), key_entry.exchange_key().len());
            self.derived_key_cipher(KeyType::Handshake)?;
        }
        Ok(false)
    }

    pub(crate) fn derived_key_cipher(&mut self, typ: KeyType) -> RlsResult<()> {
        #[cfg(feature = "log")]
        trace!("[DerivedCipher] type={:?}; cipher={:?}; mac={:?}; veriosn={:?}",
            typ,self.cipher_suite.cipher(),self.cipher_suite.mac_hash(),self.version);
        let key = self.derived.make_cipher_key(&self.version, typ)?;
        let sk = key.send_key(typ, self.server);
        let smk = key.send_mac_key(self.server);
        self.send_cipher.set_key(sk, smk, self.cipher_suite)?;
        self.send_cipher.set_iv(Iv::new(key.send_iv(typ, self.server), key.explicit()));
        let rk = key.recv_key(typ, self.server);
        let rmk = key.recv_mac_key(self.server);
        self.recv_cipher.set_key(rk, rmk, self.cipher_suite)?;
        self.recv_cipher.set_iv(Iv::new(key.recv_iv(typ, self.server), vec![]));
        Ok(())
    }

    pub fn set_by_encrypted_extension(&mut self, encrypted: &EncryptedExtension) {
        self.alpn = encrypted.alpn().cloned();
    }

    pub fn set_by_certificate(&mut self, certificate: Certificates, ext_cas: &[Certificate], sni: &str) -> RlsResult<()> {
        for certificate in certificate.certificates() {
            self.certificates.push(Certificate::from_der(certificate.as_ref())?);
        }
        if !self.verify { return Ok(()); };
        if self.version == Version::TLCP {
            self.certificates[0].verify_sni(sni)?;
            return Ok(());
        }
        self.root_stores.verify_cert(&mut self.certificates, ext_cas, sni)
    }

    pub fn set_by_compressed_certificate(&mut self, cc: CompressedCertificate<'_>, ext_cas: &[Certificate], sni: &str) -> RlsResult<()> {
        #[cfg(feature = "log")]
        debug!("[ParsedCompCert] method={}; size={}",cc.algorithm(), cc.compressed_data().len());
        match cc.algorithm() {
            CompressionMethod::BROTLI => {
                let data = coder::br_decompress(cc.compressed_data())?;
                let mut reader = Reader::from_slice(&data);
                let certs = Certificates::from_reader(&self.version, &mut reader, true)?;
                self.set_by_certificate(certs, ext_cas, sni)?;
                Ok(())
            }
            _ => panic!("unsupported compression method"),
        }
    }

    fn gen_key_sign_data(&mut self, server_key: &ServerKeyExchange, key: &mut Sm2Key) -> RlsResult<Vec<u8>> {
        match self.version {
            Version::TLCP => {
                let mut sign_data = Vec::with_capacity(1024);
                sign_data.extend_from_slice(self.derived.client_random());
                sign_data.extend_from_slice(self.derived.server_random());
                for certificate in self.certificates.iter_mut() {
                    let (pubkey, key_usage) = certificate.sm2_pub_key()?;
                    if key_usage & 0x80 == 0x80 && key.is_null() {
                        *key = Sm2Key::from_pub_key(pubkey.as_slice())?;
                    } else if key_usage & 0x20 == 0x20 {
                        let len = certificate.as_der()?.as_slice().len() as u32;
                        sign_data.extend_from_slice(&len.to_be_bytes()[1..]);
                        sign_data.extend_from_slice(certificate.as_der()?.as_slice());
                    }
                    if !key.is_null() && sign_data.len() > 64 { break; }
                }
                Ok(sign_data)
            }
            _ => {
                let mut sign_data = Vec::with_capacity(512);
                sign_data.extend_from_slice(self.derived.client_random());
                sign_data.extend_from_slice(self.derived.server_random());
                sign_data.push(*server_key.hellman_param().curve_type() as u8);
                sign_data.extend(server_key.hellman_param().named_curve().as_u16().to_be_bytes());
                sign_data.push(server_key.hellman_param().pub_key().len() as u8);
                sign_data.extend(server_key.hellman_param().pub_key().as_ref());
                Ok(sign_data)
            }
        }
    }

    pub fn verify_cert(&mut self, verify: CertificateVerify<'_>, server: bool) -> RlsResult<()> {
        #[cfg(feature = "log")]
        info!("[CertVerify] verify={}; server={}; algorithm={}", self.verify, server, verify.hash().spec());
        if !self.verify { return Ok(()); }
        let mut sign_data = Vec::with_capacity(256);
        sign_data.extend([0x20; 64]);
        match server {
            true => sign_data.extend_from_slice(b"TLS 1.3, server CertificateVerify"),
            false => sign_data.extend_from_slice(b"TLS 1.3, client CertificateVerify")
        }
        sign_data.push(0);
        sign_data.extend_from_slice(self.hasher.current_hash()?);
        let cert = self.certificates.first_mut().ok_or("missing cert")?;
        let signer = AlgorithmSigner::new_verify(cert.pub_key()?, verify.hash())?;
        signer.verify(sign_data, verify.sign().as_ref())?;
        Ok(())
    }

    pub fn set_by_cert_req(&mut self, req: CertificateRequest, cert: Option<&mut Certificate>) -> RlsResult<()> {
        if let Some(cert) = cert {
            for hash in req.into_hashes() {
                match (hash.as_u16(), cert.cert_type()?) {
                    (SignatureAlgorithm::RSA_PSS_RSAE_SHA256, CertType::RSA) => self.mtls_hash = hash,
                    (SignatureAlgorithm::RSA_PSS_RSAE_SHA384, CertType::RSA) => self.mtls_hash = hash,
                    (SignatureAlgorithm::RSA_PSS_RSAE_SHA512, CertType::RSA) => self.mtls_hash = hash,
                    (SignatureAlgorithm::ECDSA_SECP256R1_SHA256, CertType::ECDSA) => self.mtls_hash = hash,
                    (SignatureAlgorithm::ECDSA_SECP384R1_SHA384, CertType::ECDSA) => self.mtls_hash = hash,
                    (SignatureAlgorithm::ECDSA_SECP521R1_SHA512, CertType::ECDSA) => self.mtls_hash = hash,
                    (SignatureAlgorithm::RSA_PKCS1_SHA1, CertType::RSA) => self.mtls_hash = hash,
                    (SignatureAlgorithm::RSA_PKCS1_SHA256, CertType::RSA) => self.mtls_hash = hash,
                    (SignatureAlgorithm::RSA_PKCS1_SHA384, CertType::RSA) => self.mtls_hash = hash,
                    (SignatureAlgorithm::RSA_PKCS1_SHA512, CertType::RSA) => self.mtls_hash = hash,
                    _ => continue,
                }
                break;
            }
        } else { self.mtls_hash = SignatureAlgorithm::RSA_PKCS1_SHA1.into() }
        Ok(())
    }

    pub fn set_by_server_exchange_key(&mut self, server_key: ServerKeyExchange) -> RlsResult<()> {
        self.sig_alg = *server_key.hellman_param().signature_algorithm();
        self.named_curve = *server_key.hellman_param().named_curve();
        #[cfg(feature = "log")]
        info!("[ExchangeKey] algorithm={}; curve={:?}; verify={}", self.sig_alg.spec(), self.named_curve, self.verify);
        match (self.verify, self.version) {
            (true, Version::TLCP) => {
                let mut key = Sm2Key::none();
                let sign_data = self.gen_key_sign_data(&server_key, &mut key)?;
                key.verify_asn1(sign_data, server_key.hellman_param().signature().as_ref())?;
            }
            (true, _) => {
                let sign_data = self.gen_key_sign_data(&server_key, &mut Sm2Key::none())?;
                let signature = AlgorithmSigner::new_verify(self.certificates[0].pub_key()?, self.sig_alg)?;
                signature.verify(sign_data, server_key.hellman_param().signature().as_ref())?;
            }
            (_, _) => {}
        }
        self.exchange_pub_key = Bytes::new(server_key.hellman_param().pub_key().to_vec());
        self.secret_key = Some(SecretKey::new(&self.named_curve)?);
        self.secret_keys.clear();
        self.secret_keys.shrink_to_fit();
        Ok(())
    }

    pub fn set_by_session_ticket(&mut self, ticket: SessionTicket) {
        self.derived.session_mut().set_ticket(ticket.tls_ticket().ticket().to_vec());
    }

    pub fn set_by_client_exchange_key(&mut self, client_key: ClientKeyExchange) {
        self.exchange_pub_key = Bytes::new(client_key.hellman_param().pub_key().to_vec());
    }

    pub fn pub_share_key(&mut self) -> RlsResult<Buf<'_>> {
        match self.secret_key {
            Some(SecretKey::PreMasterSecret(ref bs)) => {
                debug_assert_eq!(self.version, Version::TLCP);
                let cert = self.certificates.iter_mut().find_map(|cert| {
                    let cert = cert.sm2_pub_key().ok().filter(|x| x.1 & 0x20 == 0x20);
                    cert.map(|x| x.0)
                }).ok_or(HandShakeError::MissingPubkey)?;
                let key = Sm2Key::from_pub_key(cert.as_slice())?;
                let pubkey = key.encrypt_premaster(bs.as_ref())?;
                Ok(Buf::Vec(pubkey))
            }
            Some(ref key) => key.pub_key(),
            None => {
                debug_assert_eq!(self.version, Version::TLS_1_2);
                let key = SecretKey::new_pre_master_secret(&self.version)?;
                let rsa = RsaCipher::new(self.certificates[0].pub_key()?)?;
                let pub_key = Buf::Vec(rsa.encrypt(key.pub_key()?.as_ref())?);
                self.secret_key = Some(key);
                Ok(pub_key)
            }
        }
    }

    pub fn make_cipher(&mut self, recover: bool) -> RlsResult<()> {
        if matches!(self.version, Version::TLS_1_2|Version::TLCP) && !recover {
            let secret_key = self.secret_key.as_mut().ok_or("Invalid secret key")?;
            let share_secret = secret_key.diffie_hellman(self.exchange_pub_key.as_ref())?;
            self.derived.make_master(Version::TLS_1_2, share_secret, self.hasher.current_hash()?)?;
        }
        self.derived_key_cipher(KeyType::Application)?;
        Ok(())
    }

    pub fn gen_server_hello<'a>(&mut self, _record_version: Version, client_hello: ClientHello<'a>, certificate: &'a mut [Certificate], pri_key: &RsaKey, random: &'a [u8], alpn: ALPN) -> RlsResult<RecordLayer<'a>> {
        self.derived.set_client_random(client_hello.client_random().as_ref().try_into()?);
        let mut record = RecordLayer {
            content_type: RecordType::HandShake,
            version: Version::TLS_1_2,
            len: 0,
            messages: vec![],
        };
        //server hello
        let mut server_hello = ServerHello::from_client_hello(client_hello, alpn)?;
        server_hello.set_random(random);
        self.set_by_server_hello(&server_hello, Version::TLS_1_2)?;
        record.messages.push(Message::new_parsed(MessageParsed::ServerHello(server_hello)));
        //certificate
        let mut certificates = Certificates::default();
        for certificate in certificate.iter_mut() {
            certificates.add_certificate(certificate.as_der()?.as_slice());
        }
        record.messages.push(Message::new_parsed(MessageParsed::Certificate(certificates)));
        //server_key_exchange
        let mut server_key_exchange = ServerKeyExchange::default();
        let key = SecretKey::new(server_key_exchange.hellman_param().named_curve())?;
        server_key_exchange.hellman_param_mut().set_pub_key(Buf::Vec(key.pub_key()?.to_vec()));
        self.secret_key = Some(key);
        let sign_data = self.gen_key_sign_data(&server_key_exchange, &mut Sm2Key::none())?;
        let signer = AlgorithmSigner::new_sign(pri_key.pkey(), server_key_exchange.hellman_param().signature_algorithm())?;
        server_key_exchange.hellman_param_mut().set_signature(Buf::Vec(signer.sign(&sign_data)?));
        self.exchange_pub_key = Bytes::new(server_key_exchange.hellman_param().pub_key().to_vec());
        self.named_curve = *server_key_exchange.hellman_param().named_curve();
        record.messages.push(Message::new_parsed(MessageParsed::ServerKeyExchange(server_key_exchange)));
        //server_hello_done
        record.messages.push(Message::new_parsed(MessageParsed::ServerHelloDone(ServerHelloDone::new())));
        self.server = true;
        Ok(record)
    }

    ///#### tls Record结构-5bytes(头部)
    /// * aes-gcm: payload(8byte的explicit+16payload+16byte的tag)
    /// * chacha20_poly1305: payload(16payload+16byte tag)
    pub fn make_finish_message(&mut self, buffer: &mut [u8], server: bool) -> RlsResult<usize> {
        let session_hash = self.hasher.current_hash()?;
        let finish = self.derived.make_finish(self.version, server, session_hash)?;
        if self.version == Version::TLS_1_3 { self.derived.make_application_traffic_secret(session_hash)?; }
        self.update_session(&finish)?;
        if self.derived.quic {
            buffer[..finish.len()].copy_from_slice(finish.as_slice());
            Ok(finish.len())
        } else {
            self.make_message(RecordType::HandShake, buffer, &finish)
        }
    }

    pub fn verify_finish(&mut self, data: &[u8], server: bool) -> RlsResult<()> {
        if self.verify {
            let session_hash = self.hasher.current_hash()?;
            let out = self.derived.make_finish(self.version, server, session_hash)?;
            if data != out { return Err(HandShakeError::VerifyFinishedFail.into()); }
        }
        self.update_session(data)?;
        Ok(())
    }


    pub fn make_message(&mut self, cty: RecordType, buffer: &mut [u8], payload: &[u8]) -> RlsResult<usize> {
        if buffer.len() < 5 + payload.len() {
            return Err(BufferError::CapacityTooSmall {
                needed: 5 + payload.len(),
                current: buffer.len(),
                file: file!(),
                line: line!(),
            }.into());
        }
        let buffer = CipherEncodeBuffer::new_tls(cty, buffer, payload, self.cipher_suite);
        self.send_cipher.encrypt(None, buffer)
    }

    pub fn read_message(&mut self, origin: &[u8], buffer: &mut [u8]) -> RlsResult<usize> {
        let buffer = CipherDecodeBuffer::from_buffer(origin, buffer, self.cipher_suite)?;
        self.recv_cipher.decrypt(None, buffer)
    }

    pub fn alpn(&self) -> Option<&ALPN> {
        self.alpn.as_ref()
    }

    pub fn update_session(&mut self, data: impl AsRef<[u8]>) -> RlsResult<()> {
        // println!("update session: {} {:x?}", data.as_ref().len(), data.as_ref());
        if self.mtls_enable || !self.hasher.inited() {
            self.session_bytes.extend_from_slice(data.as_ref());
        }
        if self.hasher.inited() {
            self.hasher.update(data)?;
        }
        Ok(())
    }

    pub fn session_bytes(&self) -> &[u8] { &self.session_bytes }
    pub fn cipher_suite(&self) -> &'static CipherSuite { self.cipher_suite }
    pub fn session(&self) -> &TlsSession { self.derived.session() }
    pub fn server(&self) -> bool { self.server }
    pub fn handle_mtls_client<W: WriteExt>(&mut self, writer: &mut W, key: &RsaKey) -> RlsResult<()> {
        let mut cert_verify = CertificateVerify::default();
        cert_verify.set_hash(self.mtls_hash.as_u16().into());
        let signer = AlgorithmSigner::new_sign(key.pkey(), &self.mtls_hash)?;
        let sign = signer.sign(mem::take(&mut self.session_bytes))?;
        cert_verify.set_sign(&sign);
        let mut record = RecordLayer::handshake(self.version);
        record.messages.push(Message::new_parsed(MessageParsed::CertificateVerify(cert_verify)));
        record.write_to(writer, KeyExchangeAlg::NULL)
    }

    pub fn set_secret_keys(&mut self, keys: HashMap<NamedCurve, SecretKey>) {
        self.secret_keys = keys;
    }

    pub fn secret_key(&self) -> &Option<SecretKey> {
        &self.secret_key
    }

    pub fn named_curve(&self) -> &NamedCurve { &self.named_curve }

    pub fn version(&self) -> &Version { &self.version }

    pub fn sig_alg(&self) -> &SignatureAlgorithm { &self.sig_alg }
}