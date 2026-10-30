## reqtls - a TLS and cryptographic foundation library designed based on [BoringSSL](https://github.com/google/boringssl)

`reqtls` is a high-performance TLS and cryptographic foundation library designed for the `reqrio` ecosystem, offering
comprehensive capabilities for encryption, signing, certificate handling, and encoding.
It focuses on security, scalability, and cross-platform support, making it suitable for building HTTPS clients, proxy
services, certificate issuance systems, and custom secure communication protocols.

## Design Objectives

* Lightweight Implementation: Only implements the TLS protocol and essential encryption components to avoid excessive
  dependencies and bloat
* High controllability: Developers can directly access the TLS record layer and handshake process
* Suitable for protocol development: Easy to use for network proxies, debugging tools, or protocol experiments

## TLS Record Layer (TLS1.2 and TLS1.3)

`reqtls` currently implements the core functionality of TLS 1.2 and TLS 1.3 Record Layer, which is used to provide
encrypted communication capabilities over TCP connections. This implementation is mainly aimed at Protocol research,
network tools, and custom TLS client/proxy development.

#### Supported password algorithms

* TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
* TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
* TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
* TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
* TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
* TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
* TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
*
* TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
* TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
* TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
* TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
* TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
* TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
* TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
*
* TLS_RSA_WITH_AES_128_GCM_SHA256
* TLS_RSA_WITH_AES_256_GCM_SHA384
* TLS_RSA_WITH_AES_128_CBC_SHA256
* TLS_RSA_WITH_AES_256_CBC_SHA256
* TLS_RSA_WITH_AES_128_CBC_SHA
* TLS_RSA_WITH_AES_256_CBC_SHA
*
* TLS_AES_128_GCM_SHA256
* TLS_AES_256_GCM_SHA384
* TLS_CHACHA20_POLY1305_SHA256
*
* ECC_SM4_CBC_SM3

#### Signature algorithm

* RSA_PSS_RSAE_SHA256
* RSA_PSS_RSAE_SHA384
* RSA_PSS_RSAE_SHA512
* ECDSA_SECP256R1_SHA256
* ECDSA_SECP384R1_SHA384
* ECDSA_SECP521R1_SHA512
* RSA_PKCS1_SHA1
* RSA_PKCS1_SHA256
* RSA_PKCS1_SHA384
* RSA_PKCS1_SHA512
* ECC_SM2_ASN1

### Password Curve

* SecP256r1
* SecP385r1
* SecP521r1
* X25519
* X25519MLKEM768
* SecP256r1MLKEM768

### Basic usage

Developers can directly manipulate TCP data and encrypt/decrypt messages through Connection

#### Example：

* Communication key generation (after Client Exchange Key)

```text
Connection::make_cipher(bool)
```

* Build record message

```text
Connection::make_message(RecordType, out, int)
```

* Read record message

```text
Connection::read_message(int,out)
```

For specific details, please refer to

* [async_stream](https://github.com/xllgl2017/reqrio/blob/master/reqrio/src/stream/aync/tls/mode)
* [sync_stream](https://github.com/xllgl2017/reqrio/blob/master/reqrio/src/stream/sync_stream.rs)

## Certificate related support

During the TLS handshake process, the server typically sends an X.509 Certificate Chain to the client to prove the
server's identity and provide public key information to establish a secure connection.

Currently, `reqtls` is able to parse and extract certificate data from TLS handshakes to support key exchange and
handshake processes. Some common root certificates are built-in in `reqtls`, so `reqtls` defaults to not trusting system
root certificates:

### Certificate reading/writing

```rust
use std::fs;

fn dd() {
    //Read certificate chain
    let certificates = Certificate::from_pem_file(pem)?;
    //Read certificate private key
    let certificate_key = RsaKey::from_pri_pem_file(key)?;
    //Certificate writing
    fs::write("1.der", certificates[0].as_der().as_slice()).unwrap();
}
```

### Certificate Issuance Example

```rust
fn dd() {
    let mut ca_signer = CertSigner::root_siger(2048).unwrap();
    ca_signer.set_expire(10).unwrap();
    //Country code, only two characters
    ca_signer.add_subject(DnType::Country, "XX").unwrap();
    ca_signer.add_subject(DnType::StateOrProvince, "XXX").unwrap();
    ca_signer.add_subject(DnType::Locality, "XXX").unwrap();
    ca_signer.add_subject(DnType::Organization, "XXX").unwrap();
    ca_signer.add_subject(DnType::OrganizationalUnit, "XXX").unwrap();
    ca_signer.add_subject(DnType::Common, "XXX").unwrap();
    //Certificate Purpose
    ca_signer.add_extension(CertExtend::KeyUsage(vec![KeyUsage::Critical, KeyUsage::KeyCertSign, KeyUsage::CrlSign])).unwrap();
    ca_signer.add_extension(CertExtend::KeyIdentifier(vec![KeyIdentifier::Hash])).unwrap();
    ca_signer.add_extension(CertExtend::BasicConstraints(vec![BasicConstraint::Critical, BasicConstraint::Ca(true)])).unwrap();
    ca_signer.sign_by_self().unwrap();
    fs::write("ca.der", ca_signer.cert.as_der().as_slice()).unwrap();
}
```

### Cryptography related support

#### AES/DES/RC4/RSA supported

* AES_128_CBC
* AES_192_CBC
* AES_256_CBC
* AES_128_ECB
* AES_192_ECB
* AES_256_ECB
* AES_128_CTR
* AES_192_CTR
* AES_256_CTR
* AES_128_GCM
* AES_192_GCM
* AES_256_GCM
* AES_128_OFB
* AES_192_OFB
* AES_256_OFB
* DES_CBC
* DES_ECB
* RC4
* RSA
* SM2
* SM4-ECB
* SM4-CBC
* SM4-OFB
* SM4-CFB
* SM4-CTR
* 3DES-CBC
* 3DES-ECB

- Cipher usage example

```rust
fn dd() {
    let mut aes = Cipher::des_cbc();
    aes.set_secret_key("12345678", Some("12345678"));
    let encrypted = aes.encrypt("1234567812345678jhjfhhhhhhhhhhhhhhdhhhhhhhgfdsfdsefdutrythdyrfgytyth8").unwrap();
    println!("{:?}", encrypted);
    let b64 = base64::b64encode(encrypted).unwrap();
    println!("encrypted: {}", b64);

    let de_bs = base64::b64decode(b64).unwrap();
    println!("decrypted: {:?}", de_bs);
    println!("{:?}", aes.decrypt(de_bs).unwrap());

    //Convenient AES based 64 encryption
    let res = cipher::en_b64(CipherType::AES_128_CBC, "1234567812345678", Some("1234567812345678"), "dada");
}
```

- Rsa Encryption and Decryption Example

```rust
fn dd() {
    let key = RsaKey::gen_new_key(2048).unwrap();
    println!("{}", key.to_pri_pem().unwrap());
    println!("{}", key.to_pub_pem().unwrap());
    println!("{:?}", key.to_pri_der());
    println!("{:?}", key.to_pub_der());
    let nkey = RsaKey::from_pub_der(key.to_pub_der()).unwrap();
    let rsa = RsaCipher::from_key(nkey).unwrap();
    let encrypted = rsa.encrypt("adsdfds", true).unwrap();
    println!("{} {:?}", encrypted.len(), encrypted);

    let nkey = RsaKey::from_pri_der(key.to_pri_der()).unwrap();
    let rsa = RsaCipher::from_key(nkey).unwrap();
    let decrypted = rsa.decrypt(encrypted.as_slice(), true).unwrap();
    println!("{} {:?}", decrypted.len(), decrypted);
}
```

#### Hash support

* SHA1
* SHA224
* SHA256
* SHA384
* SHA512
* MD5
* HMAC
* SM3

- Usage example

```rust
fn dd() {
    let mut hasher = Hasher::new(HashType::MD5).unwrap();
    hasher.update("dfsdf").unwrap();
    let md5 = hasher.finalize().unwrap();

    let md5 = hash::md5("dfsdf").unwrap();
    let md5_hex = hash::md5_hex("sdsdf").unwrap();

    let mut hmac = Hmac::new("key", HashType::Sha256).unwrap();
    hmac.update("fs").unwrap();
    let bs = hmac.finalize().unwrap();
}
```

#### Encoding support

* base64
* urlencoding
* hex

#### Compression support

* gzip
* deflate
* br
* zstd