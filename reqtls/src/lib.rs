//!## reqtls - a TLS and cryptographic foundation library designed based on BoringSSL
//!
//! `reqtls` is a high-performance TLS and cryptographic foundation library designed for the `reqrio` ecosystem, offering comprehensive capabilities for encryption, signing, certificate handling, and encoding.
//! It focuses on security, scalability, and cross-platform support, making it suitable for building HTTPS clients, proxy services, certificate issuance systems, and custom secure communication protocols.
//! ## Design Objectives
//!
//! * Lightweight Implementation: Only implements the TLS protocol and essential encryption components to avoid excessive dependencies and bloat
//! * High controllability: Developers can directly access the TLS record layer and handshake process
//! * Suitable for protocol development: Easy to use for network proxies, debugging tools, or protocol experiments
//!
//! ## TLS Record Layer (TLS1.2)
//!
//! `reqtls` currently implements the core functionality of TLS 1.2 Record Layer, which is used to provide encrypted communication capabilities over TCP connections. This implementation is mainly aimed at
//! Protocol research, network tools, and custom TLS client/proxy development.
//!
//! Future versions are planned to gradually support TLS 1.3.
//!
//! #### Supported password algorithms
//!
//! * TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
//! * TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
//! * TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
//! * TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
//! * TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
//! * TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
//! * TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
//! *
//! * TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
//! * TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
//! * TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
//! * TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
//! * TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
//! * TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
//! * TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
//! *
//! * TLS_RSA_WITH_AES_128_GCM_SHA256
//! * TLS_RSA_WITH_AES_256_GCM_SHA384
//! * TLS_RSA_WITH_AES_128_CBC_SHA256
//! * TLS_RSA_WITH_AES_256_CBC_SHA256
//! * TLS_RSA_WITH_AES_128_CBC_SHA
//! * TLS_RSA_WITH_AES_256_CBC_SHA
//!
//! #### Signature algorithm
//!
//! * RSA_PSS_RSAE_SHA256
//! * RSA_PSS_RSAE_SHA384
//! * RSA_PSS_RSAE_SHA512
//! * ECDSA_SECP256R1_SHA256
//! * ECDSA_SECP384R1_SHA384
//! * ECDSA_SECP521R1_SHA512
//! * RSA_PKCS1_SHA1
//! * RSA_PKCS1_SHA256
//! * RSA_PKCS1_SHA384
//! * RSA_PKCS1_SHA512
//!
//! ### Password Curve
//!
//! * secp256r1
//! * secp385r1
//! * secp521r1
//! * x25519
//!
//! ### Basic usage
//!
//! Developers can directly manipulate TCP data and encrypt/decrypt messages through Connection
//!
//! #### Example：
//!
//! * Communication key generation (after Client Exchange Key)
//!
//! ```text
//! Connection::make_cipher(bool)
//! ```
//!
//! * Build record message
//!
//! ```text
//! Connection::make_message(RecordType, out, int)
//! ```
//!
//! * Read record message
//!
//! ```text
//! Connection::read_message(int,out)
//! ```
//!
//! For specific details, please refer to
//!
//! * [async_stream](https://github.com/xllgl2017/reqrio/blob/master/reqrio/src/stream/async_stream.rs)
//! * [sync_stream](https://github.com/xllgl2017/reqrio/blob/master/reqrio/src/stream/sync_stream.rs)
//!
//! ## Certificate related support
//!
//! During the TLS handshake process, the server typically sends an X.509 Certificate Chain to the client to prove the server's identity and provide public key information to establish a secure connection.
//!
//! Currently, `reqtls` is able to parse and extract certificate data from TLS handshakes to support key exchange and handshake processes. Some common root certificates are built-in in `reqtls`, so `reqtls` defaults to not trusting system root certificates:
//!
//! ### Certificate reading/writing
//!
//! ```no_run
//! use std::fs;
//! use reqtls::*;
//!
//! fn dd() {
//!     //Read certificate chain
//!     let mut certificates = Certificate::from_pem_file("path/to/pem/cert").unwrap();
//!     //Read certificate private key
//!     let certificate_key = RsaKey::from_pri_pem_file("path/to/pem/key").unwrap();
//!     //Certificate writing
//!     fs::write("1.der", certificates[0].as_der().as_slice()).unwrap();
//! }
//! ```
//!
//! ### Certificate Issuance Example
//!
//! ```rust
//! use std::fs;
//! use reqtls::*;
//!
//! fn dd() {
//!     let mut ca_signer = CertSigner::root_siger(2048).unwrap();
//!     ca_signer.set_expire(10).unwrap();
//!     //Country code, only two characters
//!     ca_signer.add_subject(DnType::Country, "XX").unwrap();
//!     ca_signer.add_subject(DnType::StateOrProvince, "XXX").unwrap();
//!     ca_signer.add_subject(DnType::Locality, "XXX").unwrap();
//!     ca_signer.add_subject(DnType::Organization, "XXX").unwrap();
//!     ca_signer.add_subject(DnType::OrganizationalUnit, "XXX").unwrap();
//!     ca_signer.add_subject(DnType::Common, "XXX").unwrap();
//!     //Certificate Purpose
//!     ca_signer.add_extension(CertExtend::KeyUsage(vec![KeyUsage::Critical, KeyUsage::KeyCertSign, KeyUsage::CrlSign])).unwrap();
//!     ca_signer.add_extension(CertExtend::KeyIdentifier(vec![KeyIdentifier::Hash])).unwrap();
//!     ca_signer.add_extension(CertExtend::BasicConstraints(vec![BasicConstraint::Critical, BasicConstraint::Ca(true)])).unwrap();
//!     ca_signer.sign_by_self().unwrap();
//!     fs::write("ca.der", ca_signer.cert_mut().as_der().as_slice()).unwrap();
//! }
//! ```
//!
//! ### Cryptography related support
//!
//! #### AES/DES/RC4/RSA supported
//!
//! * AES_128_CBC
//! * AES_192_CBC
//! * AES_256_CBC
//! * AES_128_ECB
//! * AES_192_ECB
//! * AES_256_ECB
//! * AES_128_CTR
//! * AES_192_CTR
//! * AES_256_CTR
//! * AES_128_GCM
//! * AES_192_GCM
//! * AES_256_GCM
//! * AES_128_OFB
//! * AES_192_OFB
//! * AES_256_OFB
//! * DES_CBC
//! * DES_ECB
//! * RC4
//! * RSA
//!
//! - Cipher usage example
//!
//! ```rust
//! use reqtls::*;
//!
//! fn dd() {
//!     let mut aes = Cipher::des_cbc();
//!     aes.set_secret_key("12345678", Some("12345678"));
//!     let encrypted = aes.encrypt("1234567812345678jhjfhhhhhhhhhhhhhhdhhhhhhhgfdsfdsefdutrythdyrfgytyth8").unwrap();
//!     println!("{:?}", encrypted);
//!     let b64 = base64::b64encode(encrypted).unwrap();
//!     println!("encrypted: {}", b64);
//!
//!     let de_bs = base64::b64decode(b64).unwrap();
//!     println!("decrypted: {:?}", de_bs);
//!     println!("{:?}", aes.decrypt(de_bs).unwrap());
//!
//!     //Convenient AES based 64 encryption
//!     let res = cipher::en_b64(CipherType::AES_128_CBC, "1234567812345678", Some("1234567812345678"), "dada");
//! }
//! ```
//!
//! - Rsa Encryption and Decryption Example
//!
//! ```rust
//! use reqtls::*;
//!
//! fn dd() {
//!     let key = RsaKey::gen_new_key(2048).unwrap();
//!     println!("{}", key.to_pri_pem().unwrap());
//!     println!("{}", key.to_pub_pem().unwrap());
//!     println!("{:?}", key.to_pri_der());
//!     println!("{:?}", key.to_pub_der());
//!     let nkey = RsaKey::from_pub_der(key.to_pub_der().as_slice()).unwrap();
//!     let rsa = RsaCipher::from_rsa_key(&nkey).unwrap();
//!     let encrypted = rsa.encrypt("adsdfds").unwrap();
//!     println!("{} {:?}", encrypted.len(), encrypted);
//!
//!     let nkey = RsaKey::from_pri_der(key.to_pri_der().as_slice()).unwrap();
//!     let rsa = RsaCipher::from_rsa_key(&nkey).unwrap();
//!     let decrypted = rsa.decrypt(encrypted.as_slice()).unwrap();
//!     println!("{} {:?}", decrypted.len(), decrypted);
//! }
//! ```
//!
//! #### Hash support
//!
//! * SHA1
//! * SHA224
//! * SHA256
//! * SHA384
//! * SHA512
//! * MD5
//! * HMAC
//!
//! - Usage example
//!
//! ```rust
//! use reqtls::*;
//!
//! fn dd() {
//!     let mut hasher = Hasher::new(HashType::MD5).unwrap();
//!     hasher.update("dfsdf").unwrap();
//!     let md5 = hasher.finalize().unwrap();
//!
//!     let md5 = hash::md5("dfsdf").unwrap();
//!     let md5_hex = hash::md5_hex("sdsdf").unwrap();
//!
//!     let mut hmac = Hmac::new("key", HashType::Sha256).unwrap();
//!     hmac.update("fs").unwrap();
//!     let bs = hmac.finalize().unwrap();
//! }
//! ```
//!
//! #### Encoding support
//!
//! * base64
//! * urlencoding
//! * hex
//!
//! #### Compression support
//!
//! * gzip
//! * deflate
//! * br
//! * zstd

mod extend;
mod message;
mod prf;
mod suite;
mod connection;
mod record;
mod version;
mod bytes;
mod error;
pub mod rand;
mod boring;
mod ffi;
pub mod coder;
mod alpn;
mod share_key;
mod url;

#[cfg(feature = "export")]
mod export;
mod buffer;

pub use alpn::ALPN;
pub use boring::{base64, certificate::BasicConstraint, certificate::CertExtend, certificate::CertSigner, certificate::CertStore, certificate::CertType, certificate::Certificate, certificate::DnType, certificate::KeyIdentifier,
                 certificate::KeyUsage, certificate::SubjectAltName, cipher, hash,
                 hmac, AlgorithmSigner, Cipher,
                 CipherType, Padding, RsaCipher,
                 RsaKey,
                 RsaPadding, SignatureAlgorithm};
pub use buffer::{WriteExt, BufferError};
pub use connection::Connection;
pub use error::{RlsError, HandShakeError};
pub use extend::{formats::EcPointFormat, group::GroupType, CompressionType, Extension, ExtensionType, SupportVersions};
pub use hash::{HashType, Hasher, Hmac};
pub use hex;
pub use message::certificate::Certificates;
pub use message::client_hello::ClientHello;
pub use message::key_exchange::ClientKeyExchange;
pub use message::key_exchange::ServerKeyExchange;
pub use message::server_hello::ServerHello;
pub use message::session_ticket::{SessionTicket, TlsSessionTicket};
pub use message::{Alert, CertificateRequest, CertificateVerify, Message};
pub use record::{RecordLayer, RecordType};
pub use suite::CipherSuite;
pub use url::{Addr, Param, Scheme, Uri, Url, UrlError};
pub use version::Version;
