# reqrio export function

* char **一般是错误，传入一个nullptr。函数调用后应检查其是否为nullptr，若不为nullptr应获取对应的错误，并使用char_free对其进行内存释放
* 返回char *, 与char **基本一致

## ScReq

请求类及其方法

| No. | Function              | Params                                    | Res        |
|:---:|:----------------------|:------------------------------------------|:-----------|
|  1  | ScReq_new             | bool                                      | ScReq *    |
|  2  | ScReq_set_header_json | ScReq *, const char *                     | char *     |
|  3  | ScReq_add_header      | ScReq *, const char *, const char *, bool | char *     |
|  4  | ScReq_remove_header   | ScReq *, const char *                     | char *     |
|  5  | ScReq_set_alpn        | ScReq *, const char *                     | char *     |
|  6  | ScReq_set_verify      | ScReq *, bool                             | char *     |
|  7  | ScReq_set_redirect    | ScReq *, bool                             | char *     |
|  8  | ScReq_set_key_log     | ScReq *, const char *                     | char *     |
|  9  | ScReq_set_version     | ScReq *, Version                          | char *     |
| 10  | ScReq_set_fingerprint | ScReq *, Fingerprint *                    | char *     |
| 11  | ScReq_set_proxy       | ScReq *, const char *                     | char *     |
| 12  | ScReq_set_timeout     | ScReq *, const char *                     | char *     |
| 13  | ScReq_set_cookie      | ScReq *, const char *                     | char *     |
| 14  | ScReq_add_cookie      | ScReq *, const char *, const char *       | char *     |
| 15  | ScReq_send            | ScReq *, Method, Url *, Body *, char **   | uint64_t   |
| 16  | ScReq_recv            | ScReq *, uint64_t, bool, char **          | Response * |
| 17  | ScReq_do_http         | ScReq *, Method, Url *, Body *, char **   | Response * |
| 18  | ScReq_recv_stream     | ScReq *, uint64_t, size_t *, char **      | uint8_t *  |
| 19  | ScReq_reconnect       | ScReq *                                   | char *     |
| 20  | ScReq_connect         | ScReq *, const char *, const char *       | char *     |
| 21  | ScReq_close_stream    | ScReq *                                   | char *     |
| 22  | ScReq_drop            | ScReq *                                   | -          |

日志（仅在开启 `log` feature 时导出）

| No. | Function           | Params       | Res |
|:---:|:-------------------|:-------------|:----|
|  1  | init_log           | LevelFilter  | -   |
|  2  | set_max_log_level  | LevelFilter  | -   |

函数签名

```rust
extern "system" {
    fn ScReq_new(ignore_hdr_sort: bool) -> *mut ScReq;
    fn ScReq_set_header_json(req: *mut ScReq, header: *const c_char) -> *mut c_char;
    fn ScReq_add_header(req: *mut ScReq, key: *const c_char, value: *const c_char, reversed: bool) -> *mut c_char;
    fn ScReq_remove_header(req: *mut ScReq, key: *const c_char) -> *mut c_char;
    fn ScReq_set_alpn(req: *mut ScReq, alpn: *const c_char) -> *mut c_char;
    fn ScReq_set_verify(req: *mut ScReq, verify: bool) -> *mut c_char;
    fn ScReq_set_redirect(req: *mut ScReq, redirect: bool) -> *mut c_char;
    fn ScReq_set_key_log(req: *mut ScReq, key_log: *const c_char) -> *mut c_char;
    fn ScReq_set_version(req: *mut ScReq, version: Version) -> *mut c_char;
    //转移了fingerprint的所有权
    fn ScReq_set_fingerprint(req: *mut ScReq, fingerprint: *mut Fingerprint) -> *mut c_char;
    fn ScReq_set_proxy(req: *mut ScReq, addr: *const c_char) -> *mut c_char;
    //timeout 为 JSON，如 {"connect":3000,"read":3000,"write":3000}（毫秒）
    fn ScReq_set_timeout(req: *mut ScReq, timeout: *const c_char) -> *mut c_char;
    fn ScReq_set_cookie(req: *mut ScReq, cookie: *const c_char) -> *mut c_char;
    fn ScReq_add_cookie(req: *mut ScReq, name: *const c_char, value: *const c_char) -> *mut c_char;
    //转移了url和body的所有权；返回 sid，失败返回 0 并写入 err
    fn ScReq_send(req: *mut ScReq, method: Method, url: *mut Url, body: *mut Body<'static>, err: *mut *mut c_char) -> u64;
    //stream=false: 返回新的 Response，需 Response_drop
    //stream=true : 返回内部 StreamMessage 的引用（与 Response 前部布局一致，不可 Response_drop），
    //              随后用 ScReq_recv_stream 逐块读取 body
    fn ScReq_recv(req: *mut ScReq, sid: u64, stream: bool, err: *mut *mut c_char) -> *mut Response;
    //一次完成发送与接收，返回新的 Response，需 Response_drop
    fn ScReq_do_http(req: *mut ScReq, method: Method, url: *mut Url, body: *mut Body<'static>, err: *mut *mut c_char) -> *mut Response;
    //读取下一个流式分块，返回的指针在下一次调用前有效；返回空指针表示流结束
    fn ScReq_recv_stream(req: *mut ScReq, sid: u64, len: *mut usize, err: *mut *mut c_char) -> *const u8;
    fn ScReq_reconnect(req: *mut ScReq) -> *mut c_char;
    fn ScReq_connect(req: *mut ScReq, url: *const c_char, sni: *const c_char) -> *mut c_char;
    fn ScReq_close_stream(req: *mut ScReq) -> *mut c_char;
    fn ScReq_drop(req: *mut ScReq);
    fn char_free(ptr: *mut c_char);
}
```

### 请求方法类型

```c
enum Method {
    GET = 0,
    POST = 1,
    PUT = 2,
    HEAD = 3,
    DELETE = 4,
    OPTIONS = 5,
    TRACE = 6,
    CONNECT = 7,
    PATCH = 8,
    QUERY = 9,
}
```

### LevelFilter

```c
/* 与 log crate 的 LevelFilter 一致 */
enum LevelFilter {
    Off = 0,
    Error = 1,
    Warn = 2,
    Info = 3,
    Debug = 4,
    Trace = 5,
}
```

## Url

请求的地址

| No. | Function         | Params                            | Res    |
|:---:|:-----------------|:----------------------------------|:-------|
|  1  | Url_new          | const char *, char **             | Url *  |
|  2  | Url_add_param    | Url *, const char *, const char * | char * |
|  3  | Url_remove_param | Url *, const char *               | char * |
|  4  | Url_set_sni      | Url *, const char *               | char * |
|  5  | Url_drop         | Url *                             | -      |

函数签名

```rust
extern "system" {
    fn Url_new(base_url: *const c_char, err: *mut *mut c_char) -> *mut Url;
    fn Url_add_param(url: *mut Url, name: *const c_char, value: *const c_char) -> *mut c_char;
    fn Url_remove_param(url: *mut Url, name: *const c_char) -> *mut c_char;
    fn Url_set_sni(url: *mut Url, sni: *const c_char) -> *mut c_char;
    fn Url_drop(url: *mut Url);
}
```

## Response

请求的响应体

| No. | Function             | Params                                  | Res       |
|:---:|:---------------------|:----------------------------------------|:----------|
|  1  | Response_status_code | const Response *, char **               | uint16_t  |
|  2  | Response_sid         | const Response *, char **               | uint64_t  |
|  3  | Response_bytes       | const Response *, size_t *, char **     | uint8_t * |
|  4  | Response_header_keys | const Response *, char **               | char *    |
|  5  | Response_get_header  | const Response *, const char *, char ** | char *    |
|  6  | Response_cookies     | const Response *, char **               | char *    |
|  7  | Response_drop        | Response *                              | -         |

说明：`Response_bytes` 返回的指针在 Response 释放前有效；`Response_header_keys` 返回以 `,,,,` 分隔的头名；`Response_cookies` 返回 JSON 数组。

函数签名

```rust
extern "system" {
    fn Response_status_code(resp: *const Response, err: *mut *mut c_char) -> u16;
    fn Response_sid(resp: *const Response, err: *mut *mut c_char) -> u64;
    fn Response_bytes(resp: *const Response, len: &mut usize, err: *mut *mut c_char) -> *const u8;
    fn Response_header_keys(resp: *const Response, err: *mut *mut c_char) -> *mut c_char;
    fn Response_get_header(resp: *const Response, name: *const c_char, err: *mut *mut c_char) -> *mut c_char;
    fn Response_cookies(resp: *const Response, err: *mut *mut c_char) -> *mut c_char;
    fn Response_drop(resp: *mut Response);
}
```

### TLS参数

> 说明：`Version`、`ExtensionType`、`NamedCurve`、`CompressionMethod`、`EcPointFormat`、`SignatureAlgorithm`、`CipherSuite` 在 Rust 侧均为 `#[repr(C)]` 单字段新类型（内部字段为 u8/u16），C 侧直接按对应的整型传值即可。

#### CipherSuite

```c
// CipherSuite 为 #[repr(C)] 结构体，首字段 value 为 u16，C 侧按 u16 传值
enum CipherSuite {
    // ecdhe-ecdhe
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xc02b,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xc02c,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0xc023,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = 0xc024,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0xc009,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0xc00a,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca9,

    // ecdhe-rsa
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xc02f,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xc030,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0xc027,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 0xc028,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xc013,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xc014,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca8,

    // dhe-rsa
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = 0x009e,
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = 0x009f,
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = 0x0067,
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = 0x006b,
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA = 0x0033,
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA = 0x0039,
    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xccaa,

    // rsa
    TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009c,
    TLS_RSA_WITH_AES_256_GCM_SHA384 = 0x009d,
    TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003c,
    TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x003d,
    TLS_RSA_WITH_AES_128_CBC_SHA = 0x002f,
    TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035,

    // psk
    TLS_PSK_AES_128_GCM_SHA256 = 0x00a8,
    TLS_PSK_AES_256_GCM_SHA384 = 0x00a9,

    // tls1.3
    TLS_AES_128_GCM_SHA256 = 0x1301,
    TLS_AES_256_GCM_SHA384 = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,

    // TLCP
    TLS_SM4_GCM_SM3 = 0x00c6,
    ECC_SM4_CBC_SM3 = 0xe013,

    TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00ff,
};
```

#### ExtensionType

```c
// ExtensionType(u16)
enum ExtensionType {
    ServerName = 0x0,
    StatusRequest = 0x5,
    SupportedGroup = 0xa,
    EcPointFormats = 0xb,
    SignatureAlgorithms = 0xd,
    ApplicationLayerProtocolNegotiation = 0x10,
    SignedCertificateTimestamp = 0x12,
    Padding = 0x15,
    EncryptTheMac = 0x16,
    ExtendMasterSecret = 0x17,
    SessionTicket = 0x23,
    CompressionCertificate = 0x1b,
    SupportedVersions = 0x2b,
    PskKeyExchangeMode = 0x2d,
    PostHandshakeAuth = 0x31,
    KeyShare = 0x33,
    RenegotiationInfo = 0xff01,
    EncryptedClientHello = 0xfe0d,
    ApplicationSetting = 0x44cd,
    PreSharedKey = 0x29,
    ApplicationSettingOld = 0x4469,
    QuicTrpParameters = 0x0039,
    TrustAnchors = 0xca34
};
```

#### NamedCurve（SupportedGroup / KeyShare）

```c
// NamedCurve(u16)
enum NamedCurve {
    X25519 = 0x1d,
    X448 = 0x1e,
    X25519MLKEM768 = 0x11ec,
    SecP256r1MLKEM768 = 0x11eb,
    SecP384r1MLKEM1024 = 0x11ed,
    SecP256r1 = 0x0017,
    SecP384r1 = 0x0018,
    SecP521r1 = 0x0019,
    FFDHE2048 = 0x0100,
    FFDHE3072 = 0x0101,
    FFDHE4096 = 0x0102,
    FFDHE6144 = 0x0103,
    FFDHE8192 = 0x0104,
};

```

#### Version

```c
// Version(u16)
enum Version {
    TLS_1_0 = 0x301,
    TLS_1_1 = 0x302,
    TLS_1_2 = 0x303,
    TLS_1_3 = 0x304,
    TLCP = 0x101
};
```

#### CompressionMethod

```c
// CompressionMethod(u16)
enum CompressionMethod {
    NULL = 0,
    DEFLATE = 1,
    BROTLI = 2,
    GZIP = 0xFFFF,
    ZSTD = 0xFFFE
};
```

#### EcPointFormat

```c
// EcPointFormat(u8)
enum EcPointFormat {
    UNCOMPRESSED = 0,
    ANSI_X962_PRIME = 1,
    ANSI_X962_CHAR2 = 2
};
```

#### SignatureAlgorithm

```c
// SignatureAlgorithm(u16)
enum SignatureAlgorithm {
    RSA_PKCS1_SHA1 = 0x0201,
    RSA_PKCS1_SHA256 = 0x0401,
    RSA_PKCS1_SHA384 = 0x0501,
    RSA_PKCS1_SHA512 = 0x0601,
    RSA_PSS_RSAE_SHA256 = 0x0804,
    RSA_PSS_RSAE_SHA384 = 0x0805,
    RSA_PSS_RSAE_SHA512 = 0x0806,
    RSA_PSS_PSS_SHA256 = 0x0809,
    RSA_PSS_PSS_SHA384 = 0x080a,
    RSA_PSS_PSS_SHA512 = 0x080b,
    ED25519 = 0x0807,
    ED448 = 0x0808,
    ECDSA_SHA1 = 0x0203,
    ECDSA_SECP256R1_SHA256 = 0x0403,
    ECDSA_SECP384R1_SHA384 = 0x0503,
    ECDSA_SECP521R1_SHA512 = 0x0603,
    SHA1_DSA = 0x0202,
    SHA224_RSA = 0x0301,
    SHA224_DSA = 0x0302,
    SHA224_ECDSA = 0x0303,
    SHA256_DSA = 0x0402,
    SHA384_DSA = 0x0502,
    SHA512_DSA = 0x0602,
    SM2SIG_SM3 = 0x0708,
    SM2_ASN1 = 0xFFFF,
};
```

## Fingerprint

Session指纹，包含TLS指纹和HTTP/2指纹

| No. | Function                       | Params                                              | Res           |
|:---:|:-------------------------------|:----------------------------------------------------|:--------------|
|  1  | Fingerprint_new                | u16, u16, const char *                              | Fingerprint * |
|  2  | Fingerprint_from_builtin       | const char *, bool, const char *, char **           | Fingerprint * |
|  3  | Fingerprint_from_idx           | size_t, const char *, const char *, bool, char **   | Fingerprint * |
|  4  | Fingerprint_add_cipher_suite   | Fingerprint *, u16                                  | -             |
|  5  | Fingerprint_add_ext            | Fingerprint *, u16                                  | -             |
|  6  | Fingerprint_add_ext_alpn       | Fingerprint *, u16, const char *                    | -             |
|  7  | Fingerprint_add_ext_version    | Fingerprint *, u16, u16                             | -             |
|  8  | Fingerprint_add_ext_curve      | Fingerprint *, u16, u16                             | -             |
|  9  | Fingerprint_add_ext_compress   | Fingerprint *, u16, u16                             | -             |
| 10  | Fingerprint_add_ext_psk_mode   | Fingerprint *, u16, u8                              | -             |
| 11  | Fingerprint_add_ext_padding    | Fingerprint *, u16, size_t                          | -             |
| 12  | Fingerprint_add_ext_bytes      | Fingerprint *, u16, const uint8_t *, size_t         | -             |
| 13  | Fingerprint_add_ext_algorithm  | Fingerprint *, u16, u16                             | -             |
| 14  | Fingerprint_add_ext_ec_point   | Fingerprint *, u16, u8                              | -             |
| 15  | Fingerprint_clear_h2_frame     | Fingerprint *                                       | -             |
| 16  | Fingerprint_add_h2_setting     | Fingerprint *, u16, u32                             | -             |
| 17  | Fingerprint_add_h2_frame       | Fingerprint *, u8, const uint8_t *, size_t          | -             |
| 18  | Fingerprint_clean_h3_frame     | Fingerprint *                                       | -             |
| 19  | Fingerprint_add_h3_setting     | Fingerprint *, u64, u64                             | -             |
| 20  | Fingerprint_add_h3_frame       | Fingerprint *, u64, const uint8_t *, size_t         | -             |
| 21  | Fingerprint_set_h2_window_size | Fingerprint *, u32                                  | -             |
| 22  | Fingerprint_set_h2_priority    | Fingerprint *, bool, u8                             | -             |
| 23  | Fingerprint_drop               | Fingerprint *                                       | -             |
| 24  | Fingerprint_from_ja3           | const char *, const char *, char **                 | Fingerprint * |
| 25  | Fingerprint_from_ja4           | const char *, const char *, char **                 | Fingerprint * |
| 26  | Fingerprint_from_client_hello  | const uint8_t *, size_t, const char *token, char ** | Fingerprint * |
| 27  | Fingerprint_random             | const char *, char **                               | Fingerprint * |
| 28  | Fingerprint_custom             | const char *, const char *token, char **            | Fingerprint * |


```c
enum H2FrameType {
    Data = 0x0, 
    Headers = 0x1, 
    Priority = 0x2,
    RstStream = 0x3, 
    Settings = 0x4,
    PushPromise = 0x5, 
    Ping = 0x6, 
    Goaway = 0x7, 
    WindowUpdate = 0x8, 
    Continuation = 0x9,
};

enum H3FrameType {
    Data = 0x0, 
    Header = 0x1, 
    Setting = 0x4, 
    PriorityUpdate = 0xf0700,
};
```

函数签名

```rust
extern "system" {
    fn Fingerprint_new(record_version: Version, message_version: Version, token: *const c_char) -> *mut Fingerprint;
    fn Fingerprint_from_builtin(name: *const c_char, sec_full: bool, token: *const c_char, err: *mut *mut c_char) -> *mut Fingerprint;
    fn Fingerprint_from_idx(idx: usize, auth: *const c_char, path: *const c_char, sec_full: bool, err: *mut *mut c_char) -> *mut Fingerprint;
    fn Fingerprint_add_cipher_suite(fingerprint: *mut Fingerprint, suite: u16);
    fn Fingerprint_add_ext(fingerprint: *mut Fingerprint, ext_typ: ExtensionType);
    fn Fingerprint_add_ext_alpn(fingerprint: *mut Fingerprint, ext_typ: u16, alpn: *const c_char);
    fn Fingerprint_add_ext_version(fingerprint: *mut Fingerprint, ext_typ: ExtensionType, version: u16);
    fn Fingerprint_add_ext_curve(fingerprint: *mut Fingerprint, ext_typ: ExtensionType, curve: NamedCurve);
    fn Fingerprint_add_ext_compress(fingerprint: *mut Fingerprint, ext_typ: ExtensionType, method: CompressionMethod);
    fn Fingerprint_add_ext_psk_mode(fingerprint: *mut Fingerprint, ext_typ: ExtensionType, mode: PskMode);
    fn Fingerprint_add_ext_padding(fingerprint: *mut Fingerprint, ext_typ: ExtensionType, padding: usize);
    fn Fingerprint_add_ext_bytes(fingerprint: *mut Fingerprint, ext_typ: ExtensionType, bs: *const u8, len: usize);
    fn Fingerprint_add_ext_algorithm(fingerprint: *mut Fingerprint, ext_typ: ExtensionType, algorithm: SignatureAlgorithm);
    fn Fingerprint_add_ext_ec_point(fingerprint: *mut Fingerprint, ext_typ: ExtensionType, ec_point: u8);
    fn Fingerprint_clear_h2_frame(fingerprint: *mut Fingerprint);
    fn Fingerprint_add_h2_setting(fingerprint: *mut Fingerprint, flag: u16, value: u32);
    fn Fingerprint_add_h2_frame(fingerprint: *mut Fingerprint, typ: H2FrameType, data: *const u8, data_len: usize);
    fn Fingerprint_clean_h3_frame(fingerprint: *mut Fingerprint);
    fn Fingerprint_add_h3_setting(fingerprint: *mut Fingerprint, flag: u64, value: u64);
    fn Fingerprint_add_h3_frame(fingerprint: *mut Fingerprint, typ: H3FrameType, data: *const u8, data_len: usize);
    fn Fingerprint_set_h2_window_size(fingerprint: *mut Fingerprint, size: u32);
    fn Fingerprint_set_h2_priority(fingerprint: *mut Fingerprint, priority: bool, weight: u8);
    fn Fingerprint_drop(fingerprint: *mut Fingerprint);
    fn Fingerprint_from_ja3(ja3: *const c_char, token: *const c_char, err: *mut *mut c_char) -> *mut Fingerprint;
    fn Fingerprint_from_ja4(ja4: *const c_char, token: *const c_char, err: *mut *mut c_char) -> *mut Fingerprint;
    fn Fingerprint_from_client_hello(client_hello: *const u8, len: usize, token: *const c_char, err: *mut *mut c_char) -> *mut Fingerprint;
    fn Fingerprint_random(token: *const c_char, err: *mut *mut c_char) -> *mut Fingerprint;
    fn Fingerprint_custom(custom: *const c_char, token: *const c_char, err: *mut *mut c_char) -> *mut Fingerprint;
}
```

## Body

请求体

| No. | Function          | Params                                            | Res        |
|:---:|:------------------|:--------------------------------------------------|:-----------|
|  1  | Body_new          | const uint8_t *, size_t, const char *, char **    | Body *     |
|  2  | Body_none         | -                                                 | Body *     |
|  3  | Body_new_files    | HttpFile *, const char *, char **                 | Body *     |
|  4  | HttpFile_new      | -                                                 | HttpFile * |
|  5  | HttpFile_add_form | HttpFile *, FileForm *                            | char *     |
|  6  | FileForm_new      | const char *, const char *, const char *, char ** | FileForm * |
|  7  | HttpFile_drop     | HttpFile *                                        | -          |
|  8  | Body_drop         | Body *                                            | -          |

函数签名

```rust
extern "system" {
    fn Body_new(data: *const u8, len: usize, ty: *const c_char, err: *mut *mut c_char) -> *mut Body<'static>;
    fn Body_none() -> *mut Body<'static>;
    //转移了file的所有权
    fn Body_new_files(file: *mut HttpFile, data: *const c_char, err: *mut *mut c_char) -> *mut Body<'static>;
    fn HttpFile_new() -> *mut HttpFile;
    //转移了form的所有权
    fn HttpFile_add_form(file: *mut HttpFile, form: *mut FileForm) -> *mut c_char;
    fn FileForm_new(path: *const c_char, field_name: *const c_char, filetype: *const c_char, err: *mut *mut c_char) -> *mut FileForm;
    fn HttpFile_drop(form: *mut HttpFile);
    fn Body_drop(body: *mut Body);
}
```

## Cipher

加密/解密

#### CipherType

```c
enum CipherType {
    AES_128_CBC = 0,
    AES_192_CBC = 1,
    AES_256_CBC = 2,
    AES_128_ECB = 3,
    AES_192_ECB = 4,
    AES_256_ECB = 5,
    AES_128_CTR = 6,
    AES_192_CTR = 7,
    AES_256_CTR = 8,
    AES_128_GCM = 9,
    AES_192_GCM = 10,
    AES_256_GCM = 11,
    AES_128_OFB = 12,
    AES_192_OFB = 13,
    AES_256_OFB = 14,
    DES_CBC = 15,
    DES_ECB = 16,
    RC4 = 17,
    SM4_ECB = 18,
    SM4_CBC = 19,
    SM4_CTR = 20,
    SM4_CTR_32 = 21,
    SM4_OFB = 22,
    SM4_CFB = 23,
    DES_DED3_CBC = 24,
    DES_DED3_ECB = 25,
    CHACHA20_POLY1305 = 26,
    SM4_GCM = 27,
}
```

| No. | Function              | Params                                                   | Res      |
|:---:|:----------------------|:---------------------------------------------------------|:---------|
|  1  | Cipher_new            | CipherType                                               | Cipher * |
|  2  | Cipher_set_secret_key | Cipher *, const uint8_t *, usize, const uint8_t *, usize | i32      |
|  3  | Cipher_encrypt        | Cipher *, const uint8_t *, usize, uint8_t **, size_t *   | i32      |
|  4  | Cipher_decrypt        | Cipher *, const uint8_t *, usize, uint8_t **, size_t *   | i32      |
|  5  | Cipher_free           | Cipher *                                                 | -        |

函数签名

```rust
extern "C" {
    fn Cipher_new(ct: CipherType) -> *mut Cipher;
    fn Cipher_set_secret_key(cipher: *mut Cipher, key: *const u8, key_len: usize, iv: *const u8, iv_len: usize) -> i32;
    fn Cipher_encrypt(cipher: *mut Cipher, ct: *const u8, ct_len: usize, out: *mut *mut u8, out_len: &mut usize) -> i32;
    fn Cipher_decrypt(cipher: *mut Cipher, ct: *const u8, ct_len: usize, out: *mut *mut u8, out_len: &mut usize) -> i32;
    fn Cipher_free(cipher: *mut Cipher);
}
```

## Hasher

哈希/HMAC

#### HashType

```c
enum HashType {
    MD5 = 0,
    Sha1 = 1,
    Sha224 = 2,
    Sha256 = 3,
    Sha384 = 4,
    Sha512 = 5,
    Sm3 = 6,
}
```

| No. | Function        | Params                           | Res      |
|:---:|:----------------|:---------------------------------|:---------|
|  1  | Hasher_new      | HashType                         | Hasher * |
|  2  | Hasher_update   | Hasher *, const uint8_t *, usize | i32      |
|  3  | Hasher_finalize | Hasher *, uint8_t **, size_t *   | i32      |
|  4  | Hasher_drop     | Hasher *                         | -        |
|  5  | Hmac_new        | const uint8_t *, usize, HashType | Hmac *   |
|  6  | Hmac_update     | Hmac *, const uint8_t *, usize   | i32      |
|  7  | Hmac_finalize   | Hmac *, uint8_t **, size_t *     | i32      |
|  8  | Hmac_free       | Hmac *                           | -        |

说明：`Hasher_finalize` 与 `Hmac_finalize` 会消耗传入的对象（内部已释放），失败时请使用 `Hasher_drop` / `Hmac_free`。

函数签名

```rust
extern "C" {
    fn Hasher_new(ht: HashType) -> *mut Hasher;
    fn Hasher_update(hasher: *mut Hasher, data: *const u8, len: usize) -> i32;
    fn Hasher_finalize(hasher: *mut Hasher, out: *mut *mut u8, out_len: &mut usize) -> i32;
    fn Hasher_drop(hasher: *mut Hasher);
    fn Hmac_new(key: *const u8, len: usize, ht: HashType) -> *mut Hmac;
    fn Hmac_update(hmac: *mut Hmac, data: *const u8, len: usize) -> i32;
    fn Hmac_finalize(hmac: *mut Hmac, out: *mut *mut u8, out_len: &mut usize) -> i32;
    fn Hmac_free(hmac: *mut Hmac);
}
```

## Coder

编码工具

| No. | Function      | Params                                                 | Res      |
|:---:|:--------------|:-------------------------------------------------------|:---------|
|  1  | u8_free       | uint8_t *, usize                                       | -        |
|  2  | url_encode    | const char *                                           | char *   |
|  3  | url_decode    | const char *                                           | char *   |
|  4  | hex_encode    | const uint8_t *, usize                                 | char *   |
|  5  | hex_decode    | const char *, uint8_t **, size_t *                     | i32      |
|  6  | Base64_new    | -                                                      | Base64 * |
|  7  | Base64_encode | Base64 *, const uint8_t *, usize                       | char *   |
|  8  | Base64_decode | Base64 *, const uint8_t *, usize, uint8_t **, size_t * | i32      |
|  9  | Base64_free   | Base64 *                                               | -        |

函数签名

```rust
extern "C" {
    fn u8_free(ptr: *mut u8, len: usize);
    fn url_encode(url: *const c_char) -> *mut c_char;
    fn url_decode(url: *const c_char) -> *mut c_char;
    fn hex_encode(data: *const u8, data_len: usize) -> *mut c_char;
    fn hex_decode(data: *const c_char, out: *mut *mut u8, len: &mut usize) -> i32;
    fn Base64_new() -> *mut Base64;
    fn Base64_encode(base64: *mut Base64, data: *const u8, len: usize) -> *mut c_char;
    fn Base64_decode(base64: *mut Base64, data: *const u8, len: usize, out: *mut *mut u8, out_len: &mut usize) -> i32;
    fn Base64_free(base64: *mut Base64);
}
```

## WebSocket(暂不处理)

WebSocket连接

| No. | Function      | Params                              | Res          |
|:---:|:--------------|:------------------------------------|:-------------|
|  1  | ws_open       | const char *, const char *          | WebSocket *  |
|  2  | ws_open_raw   | const char *, const char *          | WebSocket *  |
|  3  | ws_read       | WebSocket *                         | char *       |
|  4  | ws_write      | WebSocket *, i32, const char *      | i32          |
|  5  | ws_close      | WebSocket *                         | -            |


函数签名

```rust
extern "system" {
    fn ws_open(url: *const c_char, hdr: *const c_char) -> *mut WebSocket;
    fn ws_open_raw(url: *const c_char, context: *const c_char) -> *mut WebSocket;
    fn ws_read(websocket: *mut WebSocket) -> *mut c_char;
    fn ws_write(websocket: *mut WebSocket, op_code: i32, payload: *const c_char) -> i32;
    fn ws_close(websocket: *mut WebSocket);
}
```

