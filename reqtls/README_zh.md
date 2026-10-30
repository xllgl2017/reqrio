## reqtls-基于BoringSSL设计的tls和密码学基础库

`reqtls`是为 `reqrio` 生态打造的高性能 TLS 与密码学基础库，提供完整的加密、签名、证书处理与编码能力。
它专注于安全性、可扩展性与跨平台支持，适用于构建 HTTPS 客户端、代理服务、证书签发系统以及自定义安全通信协议。

## 设计目标

* 轻量实现：仅实现 TLS 协议和必要加密组件，避免过度依赖过重
* 可控性强：开发者可以直接访问 TLS 记录层及握手流程
* 适合协议开发：方便用于网络代理、调试工具或协议实验

## TLS记录层（TLS1.2）

`reqtls` 当前实现了 TLS 1.2 记录层（Record Layer） 的核心功能，用于在 TCP 连接之上提供加密通信能力。该实现主要面向
协议研究、网络工具及自定义 TLS 客户端/代理开发。

未来版本计划逐步支持 TLS 1.3。

#### 已支持的密码算法

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

#### 签名算法

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

### 密码曲线

* SecP256r1
* SecP385r1
* SecP521r1
* X25519
* X25519MLKEM768
* SecP256r1MLKEM768

### 用法基础

`reqtls`开发者可以直接操作tcp数据，然后通过`Connection`对消息进行加解密

#### 示例：

* 通信密钥生成（在ClientExchangeKey后）

```text
Connection::make_cipher(bool)
```

* 构建record 消息

```text
Connection::make_message(RecordType, out, int)
```

* 读取record 消息

```text
Connection::read_message(int,out)
```

具体可以参考

* [async_stream](https://github.com/xllgl2017/reqrio/blob/master/reqrio/src/stream/aync/tls/mode)
* [sync_stream](https://github.com/xllgl2017/reqrio/blob/master/reqrio/src/stream/sync_stream.rs)

## 证书相关支持

在 TLS 握手过程中，服务器通常会向客户端发送 X.509 证书链（Certificate Chain），用于证明服务器身份，并提供公钥信息以建立安全连接。

`reqtls` 当前能够 解析和提取 TLS 握手中的证书数据，以支持密钥交换和握手流程。reqtls中内置了一些常见的根证书，因此reqtls默认是不信任系统根证书：

### 证书读取/写出

```rust
use std::fs;

fn dd() {
    //读取证书链
    let certificates = Certificate::from_pem_file(pem)?;
    //读取证书私钥
    let certificate_key = RsaKey::from_pri_pem_file(key)?;
    //证书写出
    fs::write("1.der", certificates[0].as_der().as_slice()).unwrap();
}
```

### 证书签发示例

```rust
fn dd() {
    let mut ca_signer = CertSigner::root_siger(2048).unwrap();
    ca_signer.set_expire(10).unwrap();
    //国家代码，仅两字符
    ca_signer.add_subject(DnType::Country, "XX").unwrap();
    ca_signer.add_subject(DnType::StateOrProvince, "XXX").unwrap();
    ca_signer.add_subject(DnType::Locality, "XXX").unwrap();
    ca_signer.add_subject(DnType::Organization, "XXX").unwrap();
    ca_signer.add_subject(DnType::OrganizationalUnit, "XXX").unwrap();
    ca_signer.add_subject(DnType::Common, "XXX").unwrap();
    //证书用途
    ca_signer.add_extension(CertExtend::KeyUsage(vec![KeyUsage::Critical, KeyUsage::KeyCertSign, KeyUsage::CrlSign])).unwrap();
    ca_signer.add_extension(CertExtend::KeyIdentifier(vec![KeyIdentifier::Hash])).unwrap();
    ca_signer.add_extension(CertExtend::BasicConstraints(vec![BasicConstraint::Critical, BasicConstraint::Ca(true)])).unwrap();
    ca_signer.sign_by_self().unwrap();
    fs::write("ca.der", ca_signer.cert.as_der().as_slice()).unwrap();
}
```

### 密码学相关支持

#### AES/DES/RC4/RSA支持

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


- Cipher使用示例

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

    //便捷aes-base64加密
    let res = cipher::en_b64(CipherType::AES_128_CBC, "1234567812345678", Some("1234567812345678"), "dada");
}
```

- RsaCipher 加解密示例

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

#### 哈希支持

* SHA1
* SHA224
* SHA256
* SHA384
* SHA512
* MD5
* HMAC
* SM3

- 使用示例

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

#### 编码支持

* base64
* urlencoding
* hex

#### 压缩支持

* gzip
* deflate
* br
* zstd