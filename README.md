# 📦 reqrio

### Browser-grade TLS Fingerprinting & High Performance HTTP Client

[![Github](https://github.com/xllgl2017/reqrio/actions/workflows/main.yml/badge.svg)](https://github.com/xllgl2017/reqrio/actions/workflows/main.yml)
[![Apache](https://img.shields.io/badge/license-Apache2.0-blue.svg?logo=apache)](https://github.com/xllgl2017/reqrio/blob/main/LICENSE-APACHE)
[![Crates](https://img.shields.io/crates/v/reqrio.svg?logo=rust&label=rust)](https://crates.io/crates/reqrio)
[![PyPI](https://img.shields.io/pypi/v/reqrio.svg?logo=pypi)](https://pypi.org/project/reqrio/)
[![Npm](https://img.shields.io/npm/v/reqrio.svg?logo=npm)](https://www.npmjs.org/package/reqrio)
[![Maven](https://img.shields.io/maven-central/v/io.github.xllgl2017/reqrio?logo=apachemaven&label=maven)](https://search.maven.org/artifact/io.github.xllgl2017/reqrio)
[![Go](https://img.shields.io/crates/v/reqrio.svg?logo=go&label=go)](https://pkg.go.dev/github.com/xllgl2017/reqrio/reqrio-go)

[![Rustdocs](https://docs.rs/reqrio/badge.svg)](https://docs.rs/reqrio)
[![Javadocs](https://javadoc.io/badge/io.github.xllgl2017/reqrio/latest.svg)](https://javadoc.io/doc/io.github.xllgl2017/reqrio/latest)
---

🌐 **Official Website**: [reqrio](https://ms.xllgl.top/)

💡 **Application Cases**: [TLS Forward](https://tlsfoward.com/) — Advanced packet capture tool built on reqrio
## Overview

&nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;`reqrio` is an HTTP request library designed for **protocol research, TLS
fingerprinting control, high-concurrency data collection, and complex network environment simulation**. It is primarily
used in scenarios requiring precise control over network behavior, such as protocol research, fingerprint analysis,
high-concurrency data collection, and request construction in complex anti-scraping environments.

&nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;`reqrio` provides browser-level TLS fingerprinting capabilities, including JA3,
JA4, and custom ClientHello functionality.

&nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;It also supports synchronous and asynchronous interfaces, multi-language binding,
streaming upload and download, and a low-memory design.

&nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;`reqrio` is an HTTP client request library written in Rust and bound to multiple
languages via ffi. It supports HTTP/1.1, HTTP/2.0, and HTTP/3 over QUIC when the `quic` feature is enabled;
TLS supports TLS 1.2 and TLS 1.3.

## reqrio focuses on another type of issue:

- Is the TLS ClientHello consistent with the browser?

- Is the header order controllable?

- Is HTTP/2 behavior controllable?

- Can the fingerprint be reproduced?

- Is memory sufficient for high-concurrency scenarios? Is low-performance sufficient?

- Does it support both synchronous and asynchronous requests?

## 🔐 TLS Stack and Fingerprint System

`reqrio`'s TLS capabilities are supported by **reqtls**, which is the core module of the entire project.

### 🧩 `reqtls` — TLS core engine

`reqtls` Responsible for building and controlling the behavior of TLS handshake:

- TLS 1.2 / TLS 1.3 handshake construction
- Fully orchestratable ClientHello generation
- Cipher suites order and policy control
- TLS extensions management
- ALPN / SNI control
- Session Ticket / Resumption support
- JA3 / JA4 fingerprint generation foundation

> ⚠️ reqtls is not a system TLS wrapper, but rather an orchestratable TLS handshake constructor.

---

## ✅ Capability Comparison (HTTP Client Libraries)

| Abilities/Characteristics      | reqrio     | reqwest | requests (py) | uTLS (Go)                | curl-ffi (py) | blockreq |
|--------------------------------|------------|---------|---------------|--------------------------|---------------|----------|
| HTTP req                       | ✅          | ✅       | ✅             | ⚠️（Requires combination） | ✅             | ✅        |
| HTTPS / TLS                    | ✅          | ✅       | ✅             | ⚠️                       | ✅             | ⚠️       |
| Cookie auto management         | ✅          | ✅       | ✅             | ❌                        | ⚠️            | ⚠️       |
| Agent support                  | ✅          | ✅       | ✅             | ⚠️                       | ✅             | ⚠️       |
| Redirection control            | ✅          | ✅       | ✅             | ❌                        | ⚠️            | ⚠️       |
| Header Custom                  | ✅          | ✅       | ✅             | ❌                        | ⚠️            | ⚠️       |
| Header Sequence Control        | ✅          | ❌       | ❌             | ❌                        | ⚠️            | ⚠️       |
| Connection reuse (Keep-Alive)  | ✅          | ✅       | ⚠️（limited）   | ⚠️                       | ⚠️            | ⚠️       |
| HTTP/2 support                 | ✅          | ✅       | ❌             | ⚠️                       | ⚠️            | ⚠️       |
| HTTP/3 / QUIC                  | ⚠️（requires `quic` feature） | ⚠️      | ❌             | ❌                        | ⚠️            | ❌        |
| Streaming requests/responses   | ✅          | ✅       | ⚠️（weak）      | ⚠️                       | ⚠️            | ⚠️       |
| Ultra-low latency optimization | ✅          | ❌       | ❌             | ❌                        | ⚠️            | ⚠️       |
| High concurrency support       | ✅          | ⚠️      | ❌             | ⚠️                       | ⚠️            | ⚠️       |

---

## 🔐 TLS / fingerprint capability

| Abilities/Characteristics             | reqrio | reqwest | requests (py) | uTLS (Go)          | curl-ffi (py)          | blockreq |
|---------------------------------------|--------|---------|---------------|--------------------|------------------------|----------|
| JA3                                   | ✅      | ❌       | ❌             | ⚠️（simulation）     | ⚠️（Depends on libcurl） | ⚠️       |
| JA4                                   | ✅      | ❌       | ❌             | ❌                  | ❌                      | ⚠️       |
| ClientHello                           | ✅      | ❌       | ❌             | ⚠️（templatization） | ❌                      | ⚠️       |
| Random TLS                            | ✅      | ❌       | ❌             | ❌                  | ❌                      | ⚠️       |
| Custom TLS fingerprint                | ✅      | ❌       | ❌             | ⚠️                 | ❌                      | ⚠️       |
| Browser-level TLS                     | ✅      | ❌       | ❌             | ⚠️（Chrome profile） | ❌                      | ⚠️       |
| Fine-grained control of TLS 1.2 / 1.3 | ✅      | ⚠️      | ❌             | ⚠️                 | ⚠️                     | ⚠️       |
| Session Ticket Control                | ✅      | ❌       | ❌             | ❌                  | ❌                      | ⚠️       |
| TLS session recovery                  | ✅      | ⚠️      | ⚠️            | ⚠️                 | ⚠️                     | ⚠️       |

---

## 🧠 Scalability (Advanced Features)

| Abilities/Characteristics       | reqrio | reqwest | requests (py) | uTLS (Go) | curl-ffi (py) | blockreq |
|---------------------------------|--------|---------|---------------|-----------|---------------|----------|
| fingerprint consistency control | ✅      | ❌       | ❌             | ⚠️        | ⚠️            | ⚠️       |
| Switching  TLS                  | ✅      | ❌       | ❌             | ⚠️        | ⚠️            | ⚠️       |
| Browser behavior simulation     | ✅      | ❌       | ❌             | ⚠️        | ⚠️            | ⚠️       |
| HTTP Header Spoofing Strategies | ✅      | ❌       | ❌             | ⚠️        | ⚠️            | ⚠️       |
| UA / ClientHello integration    | ✅      | ❌       | ❌             | ⚠️        | ⚠️            | ⚠️       |
| Anti-detection strategy support | ✅      | ❌       | ❌             | ⚠️        | ⚠️            | ⚠️       |
| Low-level socket control        | ✅      | ❌       | ❌             | ⚠️        | ⚠️            | ⚠️       |

---

### 🔐 TLS fingerprinting capability

| Capabilities / Features               | Support Status             |
|---------------------------------------|----------------------------|
| JA3 Fingerprint                       | ✅                          |
| JA4 Fingerprint                       | ✅                          |
| Controllable ClientHello              | ✅                          |
| TLS Fingerprint Randomization         | ✅                          |
| Custom TLS Fingerprint                | ✅                          |
| Browser-Level TLS Behavior Simulation | ⚠️(Planning)               |
| TLS 1.2 / 1.3 Control                 | ⚠️(Fingerprint Dependency) |
| Session Ticket Recovery               | ⚠️(TLS 1.2)                |

---

### 🌊 Low copy

`reqrio` It is a low-copy request sending engine used to efficiently send user data or file data to TCP after encryption
via TLS.`reqrio`.User-input form-data, JSON, bytes, and text data are converted to bytes for storage. A copy is only
performed once during the TLS encryption phase; data is borrowed in other phases. File uploads are read using
`into_reader` to reduce memory overhead.

```text

        Form  ┌────────┐encode->bytes ┌──────────┐             ┌──────────┐
 User ───────►│        │─────────────►│          │             │          │
        Json  │ ScReq  │  into_bytes  │  Request │ copy slice  │ fragment │ write ┌───────┐
              │ AcReq  │              │  borrow  │────────────►│  TLS     │──────►│  TCP  │
       Files  │(Engine)│ into_reader  │  reader  │             │ Encrypt  │       └───────┘
 User ───────►│        │─────────────►│          │             │          │
              └────────┘              └──────────┘             └──────────┘
```

## 🧱 Architecture Design

reqrio adopts a layered network stack design:

```text
┌────────────────────────────┐
│ HTTP Layer                 │
│ req / res / cookie / etc   │
└────────────┬───────────────┘
             │
┌────────────▼───────────────┐
│ Request Engine Layer       │
│ header ordering / stream   │
└────────────┬───────────────┘
             │
┌────────────▼───────────────┐
│ TLS Layer (reqtls)         │
│ handshake / cipher / ALPN  │
│ ClientHello builder        │
└────────────┬───────────────┘
             │
┌────────────▼───────────────┐
│ Transport Layer            │
│ TCP / proxy / socket       │
└────────────────────────────┘
```

## Multilingual binding

| Language | Type   | Status | Doc                                                                                                  |
|----------|--------|--------|------------------------------------------------------------------------------------------------------|
| Rust     | Native | ✅      | [docs.rs](https://docs.rs/reqrio/latest/reqrio/)                                                     |
| Python   | FFI    | ✅      | [pypi](https://pypi.org/project/reqrio/)                                                             |
| Java     | JNI    | ✅      | [Maven](https://javadoc.io/doc/io.github.xllgl2017/reqrio/latest/org/xllgl2017/package-summary.html) |
| Node.js  | FFI    | ✅      | [Node.js](https://www.npmjs.com/package/reqrio)                                                      |
| Go       | CGO    | ✅      |                                                                                                      |
| Qt/C++   | FFI    | ✅      |                                                                                                      |

## Roadmap

### v0.4

- [x] TLS 1.3 Fingerprint / ClientHello control
- [x] HTTP/3 support when the `quic` feature is enabled
- [x] QUIC transport support when the `quic` feature is enabled

---

### v1.0

- [ ] API Stable

- [ ] Documentation Site

- [ ] Long Term Support Version

## 🚀 Quick Satrt

## License

This project is an open-source project under the Apache 2.0 license.

## Contribute

You are welcome to submit issues and pull requests.

## Contact information

* Tg：https://t.me/+VVfbAeug-ohhZjU1
* QQ：1083315546