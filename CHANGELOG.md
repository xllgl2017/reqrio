# reqrio-v0.4.0

`v0.4.0` 将 reqrio 的传输能力扩展到 HTTP/3 和 QUIC，并补充了面向国密场景的 TLCP、SM2 支持。

## ✨ 新特性

### 🌊 HTTP/3 与 QUIC [#20](https://github.com/xllgl2017/reqrio/pull/20)

- 新增 QUIC 传输层，实现连接、握手、加密数据包、ACK、流控和流管理。
- 新增 HTTP/3 请求与响应处理，支持同步和异步请求流程。
- 新增 QPACK 编解码及静态表、动态表和索引管理。
- `ScReq` 支持通过 `quic` feature 发起 HTTP/3 请求。
- 新增 `H3Finger`，用于配置 HTTP/3 指纹。
- 新增对无序流、`HelloRetry`、`Retry` 数据包和 HTTP/3 响应头的处理。

> ⚠️ HTTP/3/QUIC 板块尚未问题，如需是用，请开启 `quic` feature：

```toml
reqrio = { version = "0.4.0", features = ["quic"] }
```

### 🔐 TLCP 与国密算法 [#23](https://github.com/xllgl2017/reqrio/issues/23) [#25](https://github.com/xllgl2017/reqrio/pull/25)

- 支持 TLCP 服务端证书校验。
- 新增 `Sm2Key`，支持 SM2 加密、解密、签名和验签。
- 支持 `ECC_SM4_CBC_SM3` 密码套件。
- 完善 SM2、证书和签名相关的底层接口与错误处理。

### 🧩 HTTPStream 与流式请求

- 统一 HTTP/1.1、HTTP/2 和 HTTP/3 的流处理结构`HTTPStream`。
- `HTTPStream` 支持异步和同步使用。
- 支持连续发送多个请求, 并且不需按顺序接收，如下：

```text
use reqrio::*;

let mut req = ScReq::new().connect("https://example.com")?;
let sid1 = req.send(Method::GET, "https://example.com/1", Body::none())?;
let sid2 = req.send(Method::GET, "https://example.com/2", Body::none())?;
let sid3 = req.send(Method::GET, "https://example.com/3", Body::none())?;
let sid4 = req.send(Method::GET, "https://example.com/4", Body::none())?;
let sid5 = req.send(Method::GET, "https://example.com/5", Body::none())?;
let sid6 = req.send(Method::GET, "https://example.com/6", Body::none())?;
let sid7 = req.send(Method::GET, "https://example.com/7", Body::none())?;

let resp1 = req.recv(sid1)?;
let resp7 = req.recv(sid7)?;
let resp2 = req.recv(sid2)?;
println!("{} {}", resp1.header().status(), resp7.header().status());
```
### 🎯 其他

- 增加 `QUERY` 请求方法 [RFC10008](https://www.rfc-editor.org/rfc/rfc10008.html)
- 支持 MacOS [#22](https://github.com/xllgl2017/reqrio/issues/22)
- 合并同步和异步接口，使用.wait()/.await

## 🛠️ 修复

- 修复h2响应体在缺少 `content-length` 时的问题
- 
- 修复`WebSocket`的`premessage-deflate`未解压问题 [#17](https://github.com/xllgl2017/reqrio/issues/17)
- 修复流式响应 [#18](https://github.com/xllgl2017/reqrio/issues/18)
- 修复响应不正确，在高网络延迟环境 [#24](https://github.com/xllgl2017/reqrio/issues/24)
- 修复h2在请求体为空的post时，的`content-length`无法设置问题

## Contact

- Telegram: https://t.me/+VVfbAeug-ohhZjU1
- QQ: 1083315546

---

**Full Changelog**: https://github.com/xllgl2017/reqrio/compare/v0.3.1...v0.4.0

# reqrio-v0.3.1

- Allow H2 to add `content-length` field
- Fix zstd stream decode
- Remove `Sec-WebSocket-Extensions` in`WebSocket`
- fix addHeader in java
- fix missing cookie in java
- Fix missing cookies in `setHeader` in Java
- Fix Buffer move
- Fix cookie parsing bug in response cookie.
- Improve doc from 0.3.0

# reqrio-v0.3.0

`v0.3.0` is a significant architectural upgrade, marking the evolution of reqrio
from a basic HTTP client into a controllable network stack with TLS/streaming
capabilities.

## ⚠️ Breaking Changes

The `ScReq` / `AcReq` request interfaces were refactored. Code written against
v0.2.0 needs to be updated.

```text
// Before (v0.2.0)
// let req = ScReq::new();
// req.set_url(url).unwrap();
// let resp=req.get().unwrap();

// After (v0.3.0)
let mut req = ScReq::new();
let resp = req.get(url, None)?;   // 2nd arg = optional headers/options (None to skip)
```

## ✨ New Features

### 🔧 New HTTP API ([#7](https://github.com/xllgl2017/reqrio/pull/7))

- Refactored the `ScReq` / `AcReq` request interfaces
- Simplified the fast-request API
- Enhanced support for method chaining
- Optimized code examples and documentation

```text
let mut req = ScReq::new();
let url = "https://www.baidu.com/";
let resp = req.get(url, None).unwrap();   // None = no extra headers/options
println!("{}", resp.header());
```

### 🌐 Built-in ECH (Encrypted ClientHello) lookup ([#11](https://github.com/xllgl2017/reqrio/pull/11))

- Supports querying ECH configuration for a domain
- Can construct ECH data from the query result
- Provides foundational capabilities for TLS fingerprint emulation and
  privacy-enhancing connections

### 🌊 Streaming response handling

#### 1. Lightweight streaming parser `Reader` ([#12](https://github.com/xllgl2017/reqrio/pull/12))

- Supported types:
    - `u8` / `u16` / `u24` / `u32`
    - `&[u8]` / `str`
- Useful for parsing protocols such as TLS, DNS, and HTTP.

#### 2. Stream decompression `StreamDecode` ([#15](https://github.com/xllgl2017/reqrio/pull/15))

- Supported formats:
    - chunked gzip / br / deflate / zstd
    - gzip / br / deflate / zstd

## 🎯 Fingerprint-level network behavior control

In v0.3.0 the `Fingerprint` architecture was refactored to support fine-grained
control over TLS and HTTP/2 behavior.

### 🔐 Custom TLS fingerprint

Customization is supported:

* Cipher Suites
* Supported Groups
* Signature Algorithms
* TLS Versions
* Extensions
* ...

```text
let finger = TlsFinger::Custom {
    suites: vec![
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.into(),
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.into(),
        CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256.into(),
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.into(),
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.into(),
        CipherSuite::TLS_AES_128_GCM_SHA256.into(),
        CipherSuite::TLS_AES_256_GCM_SHA384.into(),
        CipherSuite::TLS_CHACHA20_POLY1305_SHA256.into(),
    ],
    extensions: vec![
        ExtensionType::StatusRequest.into(),
        Extension::new(ExtensionType::SupportedGroup, ExtensionValue::Curves(vec![
            NamedCurve::X25519.into(),
            NamedCurve::SecP256r1.into(),
            NamedCurve::SecP384r1.into(),
            NamedCurve::SecP521r1.into(),
        ]))
    ]
}
```

👉 Use cases:

* Precise TLS fingerprinting, simulating browser TLS fingerprinting behavior
* Web crawler detection and countermeasures
* Protocol research

### ⚡ Custom HTTP/2 fingerprint

Supports custom HTTP/2 frame and priority parameters:

```text
let h2 = H2Finger {
    setting: vec![
        H2Setting::EnablePush(0),               // 0 = disable server push
        H2Setting::HeaderTableSize(4096),
        H2Setting::InitialWindowSize(8192),
        H2Setting::MaxHeaderListSize(242144),
    ],
    window_size: 2147418112,
    weight: 234,        // priority weight
    priority: true,     // enable priority
};
```

👉 Use cases:

- Constructing HTTP/2 fingerprints (Settings / Window / Priority)
- Simulating browser network behavior
- Fine-grained control over connection-scheduling strategies

## 🔐 TLS 1.3 support ([#9](https://github.com/xllgl2017/reqrio/pull/9))

- support for the TLS 1.3 handshake
- Integrates with custom TLS fingerprints
- Provides a foundation for browser-level TLS behavior emulation

## 📦 Other changes

### New cryptographic algorithms

- sm4-ecb / sm4-cbc / sm4-ofb / sm4-cfb / sm4-ctr
- aead-sm4-gcm
- sm3
- 3des-cbc / 3des-ecb

### Logging

- Improved logging — log output is now exposed to the language bindings.

## Contact

- Telegram: https://t.me/+VVfbAeug-ohhZjU1
- QQ: 1083315546

---

**Full Changelog**: https://github.com/xllgl2017/reqrio/compare/v0.2.0...v0.3.0

# reqrio-v0.2.0

`v0.2.0` focuses on improving the high-performance request streaming architecture and expanding the TLS capabilities of
reqtls.Several improvements were also added, including proxy authentication support, enhanced TLS algorithms, DNS
caching

## High speed low copy request stream

Starting from `v0.1.0`, reqrio introduces a high-speed request streaming architecture that minimizes memory allocations
and unnecessary data copies.

The new design removes most intermediate `String` and `Vec<u8>` allocations when building requests, significantly
improving
throughput and reducing memory pressure in high-concurrency scenarios.

* Data Flow

```text

        Data  ┌────────┐encode->bytes ┌──────────┐             ┌──────────┐
 User ───────►│        │─────────────►│          │             │          │
              │ ScReq  │              │  Request │ copy slice  │ fragment │ write ┌───────┐
              │ AcReq  │              │  borrow  │────────────►│  TLS     │──────►│  TCP  │
       Files  │(Engine)│ into_reader  │  buffer  │             │ Encrypt  │       └───────┘
 User ───────►│        │─────────────►│          │             │          │
              └────────┘              └──────────┘             └──────────┘
```

## `ReadExt` and `WriteExt`

Starting from `v0.2.0`, reqrio introduces two core I/O helpers: ReadExt and WriteExt. They are the foundation of the
high-speed request stream pipeline, enabling efficient construction of both HTTP request streams and TLS record streams
with minimal overhead.

```text
           Write                Read            
       Request Source         Tcp Socket     
             │                    │ Buffer           
             ▼                    ▼            
       RequestBuffer          TLS Record         
         (ReadExt)            (decrypt)
      Buffer │ copy          copy │ Buffer       
             ▼                    ▼            
         TLS Record             Buffer        
          (encrypt)           (H2Frame)      
             │                    │            
             ▼                    ▼            
          TCP Socket           Response      
```

## Certificate Issuer

Starting from `v0.2.0`, `reqtls` introduces a built-in certificate issuer, enabling the generation and signing of tls
certificates directly within the library.

This feature allows `reqtls` to act as a lightweight certificate authority (CA) capable of issuing:

* Root certificates

* Server certificates

* Client certificates

## mTLS Client

Starting from v0.2.0, `reqtls` adds support for mutual TLS (mTLS) on the client side.

With mTLS enabled, the client not only verifies the server certificate, but also presents its own certificate and
private key during the TLS handshake. This allows servers to authenticate the client identity, providing stronger
security than standard TLS.

Client mTLS can be enabled by configuring a client certificate and private key through `ClientConfig`.

* Example

```
 use reqrio::*;
 
 let mut req=ScReq::new();
 let certs=Certificate::from_pem_file("path/to/cert").unwrap();
 let key=RsaKey::from_pri_pem_file("path/to/cert/key").unwrap();
 req.set_mtls(certs,key);
```

## New Export

| No. | Function              | Params                                                   | Res    | Note                     |
|:---:|:----------------------|:---------------------------------------------------------|:-------|:-------------------------|
|  1  | Cipher_new            | CipherType                                               | void * |
|  2  | Cipher_set_secret_key | void *, const uint8_t *, size_t, const uint8_t *, size_t | int    |
|  3  | Cipher_encrypt        | void *, const uint8_t *, size_t, uint8_t **, size_t      | int    |
|  4  | Cipher_decrypt        | void *, const uint8_t *, size_t, uint8_t **, size_t      | int    |
|  5  | Cipher_free           | void *                                                   | -      | Destroy Cipher * pointer |
|  6  | Hasher_new            | HashType                                                 | void * |
|  7  | Hasher_update         | void *, const uint8_t *, size_t                          | int    |
|  8  | Hasher_finalize       | void *, uint8_t **, size_t                               | int    |
|  9  | Hasher_free           | void *                                                   | -      |
| 10  | Hmac_new              | uint8_t **, size_t, HashType                             | void * |
| 11  | Hmac_update           | void *, const uint8_t *, size_t                          | int    |
| 12  | Hmac_finalize         | void *, uint8_t **, size_t                               | int    |
| 13  | Hmac_free             | void *                                                   | -      |
| 14  | Base64_new            | -                                                        | void * |
| 15  | Base64_encode         | void *, const uint8_t *, size_t                          | char * |
| 16  | Base64_decode         | void *, const uint8_t *, size_t, uint8_t **, size_t      | int    |
| 17  | Base64_free           | void *                                                   | -      |
| 18  | url_encode            | const char *                                             | char * |
| 19  | url_decode            | const char *                                             | char * |
| 20  | hex_encode            | const unt8_t, size_t                                     | char * |
| 21  | hex_decode            | const char *, uint8_t **, size_t                         | int    |

## Other Update

### reqrio

- set_verify - verify server certificate information
- Add ` patch ` method
- set_auto_direct - does it automatically jump to 3xx state
- proxy: `socks5` and `http_plain` support username and password verification
- hpack—coding：Supports streaming hpack encoding and decoding

### reqtls

- Export `Cipher`, `Hmac`, `Base64`, `Hasher`, url_en(de)code, hex_en(de)code, and other C-ABI formats.

- Support `TLS_AES_CBC/128/256/SHA/SHA256/SHA384 algorithms`.

- Add `RecordEncodeBuffer` and `RecordDecodeBuffer`.

- Add DNS caching with a 30-minute cache time.

## Contact

* Tg: https://t.me/+VVfbAeug-ohhZjU1
* QQ: 1083315546

# reqrio-v0.1.0

### reqrio is an HTTP request library designed for fast, simple, and convenient HTTP request usage.

* Features: Low copy, high concurrency, low overhead

* Supports TLS fingerprinting, which can be configured via hexadecimal, Ja3, or Ja4 TLS handshake settings (*
  *subscription only**).

* Ensures **request header order** (see [Request Header Order Table](#request-header-order-table)), consistent with
  browsers.

* Uses **BoringSSL** to implement TLS, consistent with browsers like Chrome and Edge.

**Note:** std and cls cannot exist simultaneously, while sync and async can exist simultaneously.

### Request Header Order Table

| No. | HTTP/2.0                    | HTTP/1.1                  |
|:----|:----------------------------|:--------------------------|
| 1   | cache-control               | Host                      |
| 2   | sec-ch-ua                   | Connection                |
| 3   | sec-ch-ua-mobile            | Content-Length            |
| 4   | sec-ch-ua-full-version      | Authorization             |
| 5   | sec-ch-ua-arch              | Content-Type              |
| 6   | sec-ch-ua-platform          | Cache-Control             |
| 7   | sec-ch-ua-platform-version  | sec-ch-ua                 |
| 8   | sec-ch-ua-model             | sec-ch-ua-mobile          |
| 9   | sec-ch-ua-bitness           | sec-ch-ua-platform        |
| 10  | sec-ch-ua-full-version-list | Upgrade-Insecure-Requests |
| 11  | upgrade-insecure-requests   | User-Agent                |
| 12  | user-agent                  | Accept                    |
| 13  | accept                      | Sec-Fetch-Site            |
| 14  | origin                      | Sec-Fetch-Mode            |
| 15  | sec-fetch-site              | Sec-Fetch-User            |
| 16  | sec-fetch-mode              | Sec-Fetch-Dest            |
| 17  | sec-fetch-user              | Sec-Fetch-Storage-Access  |
| 18  | sec-fetch-dest              | Referer                   |
| 19  | sec-fetch-storage-access    | Accept-Encoding           |
| 20  | referer                     | Accept-Language           |
| 21  | accept-encoding             | Cookie                    |
| 22  | accept-language             | Origin                    |
| 23  | cookie                      |                           |
| 24  | priority                    |                           |
|     | //unknown                   |                           |
| 25  | content-encoding            |                           |
| 26  | content-type                |                           |
| 27  | authorization               |                           |
| 28  | content-type                |                           |

### reqrio export function

Reqrio has C export functions that can be called in different languages

| No. | Function                     | Params                                        | Res    |               Note                |
|:---:|:-----------------------------|:----------------------------------------------|:-------|:---------------------------------:|
|  1  | ScReq_new                    | -                                             | void * |
|  2  | ScReq_set_header_json        | void *, const char *                          | int    |
|  3  | ScReq_add_header             | void *, const char *, const char *            | int    |
|  4  | ScReq_set_alpn               | void *, const char *                          | int    |
|  5  | ScReq_set_random_fingerprint | void *                                        | int    |                                   |
|  6  | ScReq_set_fingerprint        | void *, const char *                          | int    |                                   |
|  7  | ScReq_set_ja3                | void *, const char *                          | int    |                                   |
|  8  | ScReq_set_ja4                | void *, const char *                          | int    |                                   |
|  9  | ScReq_set_proxy              | void *, const char *                          | int    |       http:// or socks5://        |
| 10  | ScReq_set_url                | void *, const char *                          | int    |  Called before setting the body   |
| 11  | ScReq_add_param              | void *, const char *, const char *            | int    |
| 12  | ScReq_set_data               | void *, const char *                          | int    |
| 13  | ScReq_set_json               | void *, const char *                          | int    |
| 14  | ScReq_set_bytes              | void *, const char *, uint32_t                | int    |
| 15  | ScReq_set_text               | void *, const char *                          | int    |
| 16  | ScReq_set_timeout            | void *, const char *                          | int    |   Tiemout structure to JSON str   |
| 17  | ScReq_set_cookie             | void *, const char *                          | int    |
| 18  | ScReq_add_cookie             | void *, const char *, const char *            | int    |
| 19  | ScReq_set_callback           | void *, extern "C" fn(const char *, uint32_t) | int    |
| 20  | ScReq_reconnect              | void *                                        | int    |
| 21  | ScReq_stream_io              | void *, Method                                | char * |       Return to hexadecimal       |
| 22  | ScReq_drop                   | void *                                        | -      |   Destroy the new_tttp instance   |
| 23  | char_free                    | char *                                        | -      |      Destroy char * pointer       |
| 24  | ws_build                     | -                                             | void * |
| 25  | ws_add_header                | void *, const char *, const char *            | int    |
| 26  | ws_set_proxy                 | void *, const char *                          | int    | The value is http:// or socks5:// |
| 27  | ws_set_url                   | void *, const char *                          | int    |
| 28  | ws_set_uri                   | void *, const char *                          | int    |
| 29  | ws_open                      | void *                                        | void * |
| 30  | ws_open_raw                  | const char *, const char *                    | void * |
| 31  | ws_read                      | void *                                        | char * |          Return as JSON           |
| 32  | ws_write                     | void *, int, bool, const char *               | int    |          opcode,mask,msg          |
| 33  | ws_close                     | void *                                        | -      |        Destroy WS instance        |

* When the function returns -1, the function is unavailable
* The instance needs to be manually released, otherwise it may cause memory leakage

# reqtls-v0.1.0

### reqtls is a lightweight TLS library and encryption/decryption library.

&nbsp;&nbsp;&nbsp;&nbsp;reqtls is built on boringssl and maintains consistency with browser behavior.

### Encryption/decryption support：

* aes_ecb_128
* aes_ecb_192
* aes_ecb_256
* aes_cbc_128
* aes_cbc_192
* aes_cbc_256
* aes_crt_128
* aes_crt_192
* aes_crt_256
* aes_gcm_192
* aes_gcm_256
* aes_gcm_128
* aes_ofb_192
* aes_ofb_256
* aes_ofb_128
* des_ecb
* des_cbc
* rsa

### TLS supports TLS 1.2.

* aes-gcm-128
* aes-gcm-256
* chacha20_poly1305
* x25519
* secp256r1
* secp384r1
* secp521r1

### CipherSuite

* TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
* TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
*
* TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
* TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
* TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256

* TLS_RSA_WITH_AES_128_GCM_SHA256
* TLS_RSA_WITH_AES_256_GCM_SHA384

### AlgorithmSignature

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

### Hash support

* sha1
* sha224
* sha256
* sha385
* sha512
* hmac

### Encoding support

* base64
* urlencoding
* hex

### Compression Support

* gzip
* deflate
* br
* zstd