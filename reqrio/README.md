# 📦 reqrio — Lightweight, high-performance, fingerprint-oriented HTTP request library

`reqrio` is an HTTP request library designed for protocol research, TLS fingerprint control, high-concurrency data
collection, and complex network environment simulation. It supports HTTP/1.1 and HTTP/2, and uses `reqtls` to provide
programmable TLS handshake construction for browser-level network behavior simulation.

Unlike HTTP clients that prioritize ease of use, `reqrio` focuses on:

- browser-level TLS fingerprint consistency
- controllable header order
- HTTP/2 behavior control
- low-copy high-concurrency performance
- multi-language FFI binding support

> ⚡ Ideal for protocol research | anti-scraping | fingerprint control | high-concurrency systems

---

## ✨ Key Features

| Category                    | Capability                                                               |
|-----------------------------|--------------------------------------------------------------------------|
| **Protocol Support**        | HTTP/1.1, HTTP/2, HTTP/3.0                                               |
| **TLS Support**             | TLS 1.2 / TLS 1.3, TLCP,QUIC                                             |
| **TLS Fingerprinting**      | JA3, JA4, ClientHello, randomized TLS fingerprints                       |
| **Request Modes**           | synchronous & asynchronous                                               |
| **Header Control**          | ordered headers, browser-like header sequencing                          |
| **Streaming**               | low-copy data pipeline, large file upload and streaming response support |
| **Proxy Support**           | HTTP proxy, SOCKS5 proxy                                                 |
| **Cookie Management**       | automatic inheritance and session persistence                            |
| **Compression**             | Gzip, Deflate, Brotli, Zstd                                              |
| **Multi-language Bindings** | Rust, Python, Java, Node.js, Go, Qt/C++                                  |

---

## 🌊 Low-Copy Architecture

`reqrio` adopts a low-copy design to minimize memory overhead while simulating complex network behaviors.

- Sending: form-data, JSON, text, and other input data are converted to bytes first. A copy only occurs once during TLS
  encryption, while other stages borrow the data.
- File upload: files are read through `into_reader`, avoiding loading the entire file into memory.
- Receiving: TLS-decrypted data is written directly into an internal buffer and then parsed by the engine layer.

```text
┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ Write ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐
│        Form  ┌─────────┐           ┌───────────────┐           ┌─────────────┐           ┌──────┐ │
│ User ───────►│  Req    │  Body     │ RequestBuf    │  Buffer   │             │ Encrypted │      │ │
│        Json  │ Engine  ├─ Cow<T> ──┤ Header + Body │──────────►│  TlsStream  │──────────►│ TCP  │ │
│        Files │ (Sync)  │ Lifetime  │    Readers    │           │   Encrypt   │           │ Send │ │
│ User ───────►│ (Async) │           │ (borrowed)    │           │             │           │      │ │
│              └─────────┘           └───────────────┘           └─────────────┘           └──────┘ │    
└ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘
┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─  Read ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─  ─ ─ ─ ─ ┐
│                 ┌──────────┐            ┌────────┐                 │
│ ┌───────┐ read  │   TLS    │ decrypt to │ ScReq  │  return         │
│ │  TCP  │──────►│ Fragment │───────────►│ AcReq  │─────────► User  │
│ └───────┘       │ Decrypt  │            │(Engine)│ Response        │
│                 └──────────┘            └────────┘                 │
└ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─┘

```

---

## 🔐 TLS and Fingerprinting

`reqrio`'s TLS capabilities are provided by `reqtls`. `reqtls` is not a system TLS wrapper; it is a programmable TLS
handshake constructor designed for browser-level ClientHello and TLS behavior building.

### Supported Capabilities

- TLS 1.2 / TLS 1.3
- controllable ClientHello construction
- JA3 / JA4 fingerprinting
- custom TLS fingerprints
- randomized TLS fingerprints
- ALPN, SNI, cipher suite order, and session resume control

> ⚠️ Some advanced fingerprint features are currently offered as subscription/advanced features.

### TLS fingerprint examples

```rust
use reqrio::*;

let fingerprint = Fingerprint::from_builtin("chrome-152") ?;
let mut req = ScReq::new().with_fingerprint(fingerprint).with_alpn(ALPN::HTTP20);
```

You can also build a custom fingerprint from a ClientHello payload:

```rust
use reqrio::*;

let client_hello = hex::decode("...") ?;
let mut req = ScReq::new().with_fingerprint(Fingerprint::from_client_hello(client_hello, "<token>") ? );
```

---

## 🚀 Quick Start

### Initialize a Session

```rust
use reqrio::*;

fn main() {
    let headers = json::object! {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0",
        "sec-ch-ua": r#""Microsoft Edge";v="143", "Chromium";v="143", "Not A(Brand";v="24""#,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": r#""Windows""#
    };

    let mut req = ScReq::new()
        .with_alpn(ALPN::HTTP20)
        .with_header_json(headers).unwrap()
        .with_timeout(Timeout::new_same(3000, 3));
}
```

### GET Request Example

```rust
use reqrio::*;

fn main() {
    let mut req = ScReq::new();
    let mut res = req.get("https://www.baidu.com", None).unwrap();
    let header = res.header();
    let body = res.decode_body().unwrap();
    let json = res.json().unwrap();
}
```

### Form POST

```rust
use reqrio::*;

fn main() {
    let mut req = ScReq::new();
    let url = "https://www.baidu.com/api";
    let data = json::object! {
        "field1": "value1",
        "field2": "value2"
    };
    let resp = req.post(url, data.form()).unwrap();
}
```

### JSON POST

```rust
use reqrio::*;

fn main() {
    let mut req = ScReq::new();
    let url = "https://www.baidu.com/api";
    let data = json::object! {
        "field1": "value1",
        "field2": "value2"
    };
    let resp = req.post(url, data).unwrap();
}
```

### POST with a `Serialize` struct

> Requires the `serde` feature

```rust
use reqrio::*;
use serde::Serialize;

fn main() {
    #[derive(Serialize)]
    struct Data {
        field1: String,
        field2: bool,
    }

    let mut req = ScReq::new();
    let url = "https://www.baidu.com/api";
    let resp = req.post(url, Body::json(&Data { field1: "value".to_string(), field2: false }).unwrap()).unwrap();
}
```

---

## 🔌 WebSocket Support

```rust
use reqrio::*;

fn main() {
    let mut ws = WebSocket::open_sync("wss://echo.websocket.org").unwrap();
    ws.write_frame(WsFrame::new_text(true, "Hello")).unwrap();
    let frame = ws.read_frame().unwrap();
    println!("Received: {:?}", frame);
}
```

The async variant is also available as `WebSocket::open_async(url)`.

---

## 📄 License

This project is open source under the Apache 2.0 License.

---

## 🤝 Contributing

Contributions are welcome. Feel free to open issues and submit pull requests.

---

## 📬 Contact

- **Telegram**: https://t.me/+VVfbAeug-ohhZjU1
- **QQ**: 1083315546
