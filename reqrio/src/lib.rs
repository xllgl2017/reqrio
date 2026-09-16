//!# reqrio - High-Performance HTTP Request Engine
//!
//! A modern Rust HTTP request library optimized for low latency, high concurrency, and minimal memory overhead.
//! Designed to mimic browser behavior for advanced web automation, API integration, and reverse proxy development.
//!
//! ## Why reqrio?
//!
//! - **Undetectable Client Simulation**: Authentic TLS fingerprinting and browser-identical request headers for bypassing bot detection
//! - **Enterprise-Grade Performance**: Handle thousands of concurrent requests with minimal overhead using async/sync dual-mode
//! - **Production-Ready TLS**: BoringSSL-based implementation with certificate management, mTLS support, and session resumption
//! - **Efficient Memory Usage**: Intelligent use of Rust's lifetime system and `Cow` to eliminate unnecessary copies
//!
//! ## Core Features
//!
//! - **Efficient Reference-Based Architecture**: Leverages Rust's ownership model with `Cow` and lifetime borrowing to minimize allocations
//! - **Dual Concurrency Models**: Sync (`ScReq`) and Async (`AcReq`) engines for flexible deployment
//! - **Browser-Compatible TLS**: Implemented with BoringSSL for feature parity with Chrome, Firefox, and Edge
//! - **Advanced TLS Fingerprinting** (subscription): Customize via hexadecimal, Ja3, or Ja4 standards for maximum authenticity
//! - **Strict Header Ordering**: Enforces HTTP/2.0 and HTTP/1.1 header sequences consistent with real browser requests
//! - **Complete Protocol Support**: HTTP/1.1, HTTP/2.0, and full-duplex WebSocket with connection pooling
//!
//! ## Architecture: Efficient Data Pipeline
//!
//! `reqrio` uses a layered architecture that optimizes memory usage through intelligent borrowing and streaming:
//!```text
//! ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ Write ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐
//! │        Form  ┌─────────┐           ┌───────────────┐           ┌─────────────┐           ┌──────┐ │
//! │ User ───────►│  Req    │  Body     │ RequestBuf    │  Buffer   │             │ Encrypted │      │ │
//! │        Json  │ Engine  ├─ Cow<T> ──┤ Header + Body │──────────►│  TlsStream  │──────────►│ TCP  │ │
//! │        Files │ (Sync)  │ Lifetime  │    Readers    │           │   Encrypt   │           │ Send │ │
//! │ User ───────►│ (Async) │           │ (borrowed)    │           │             │           │      │ │
//! │              └─────────┘           └───────────────┘           └─────────────┘           └──────┘ │
//! └ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘
//! ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─  Read ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─  ─ ─ ─ ─ ┐
//! │                 ┌──────────┐            ┌────────┐                 │
//! │ ┌───────┐ read  │   TLS    │ decrypt to │ ScReq  │  return         │
//! │ │  TCP  │──────►│ Fragment │───────────►│ AcReq  │─────────► User  │
//! │ └───────┘       │ Decrypt  │            │(Engine)│ Response        │
//! │                 └──────────┘            └────────┘                 │
//! └ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─┘
//!
//! ```
//! **Key Design Principles:**
//! - **Lifetime-Based Borrowing**: Data is borrowed via lifetime parameters during header and body processing, avoiding unnecessary copies
//! - **Copy-on-Write (Cow)**: Form data and JSON payloads use `Cow<T>` to support both borrowed and owned data without overhead
//! - **Streaming Body Readers**: Support for HTTP/1.1 and HTTP/2.0 with separate body readers for efficient chunking
//! - **Single Data Copy at Encryption**: Data flows into TLS encryption layer where it is copied once for cryptographic operations
//! - **Zero-Copy for Files**: Large file uploads are read on-demand through `BodyReader` interface, avoiding full buffering
//!
//!
//! ## Quick Start Guide
//!
//! ### Simple GET Request
//! The simplest way to send a GET request:
//!
//! ```rust
//! # use reqrio::*;
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut res = reqrio::get("https://api.example.com/users", None)?;
//! println!("{}", res.as_text()?);
//! # Ok(())
//! # }
//! ```
//!
//! ### GET Request with Query Parameters
//! Add query parameters using the `.params()` method:
//! ```rust
//! # use reqrio::*;
//! # fn ff() {
//! let params = json::object! {
//!     "p1": 1,
//!     "p2": "??34//11<<><"
//! };
//!
//! // Send GET request with query parameters
//! let mut res = reqrio::get("https://www.baidu.com".params(params), None).unwrap();
//!
//! // Access response headers
//! let header = res.header();
//!
//! // Parse as JSON
//! let json = res.json().unwrap();
//! # }
//! ```
//!
//! ### POST with Form Data
//! ```rust
//! # use reqrio::*;
//! # fn ff() {
//! let url = "https://www.baidu.com/api";
//! let data = json::object! {
//!     "field1": "value1",
//!     "field2": "value2"
//! };
//!
//! let resp = reqrio::post(url, data.form()).unwrap();
//! # }
//! ```
//!
//! ### POST with JSON Data
//! ```rust
//! # use reqrio::*;
//! # fn ff() {
//! let url = "https://www.baidu.com/api";
//! let data = json::object! {
//!     "field1": "value1",
//!     "field2": "value2"
//! };
//!
//! let resp = reqrio::post(url, data).unwrap();
//! # }
//! ```
//!
//! ### POST with Serializable Struct
//! ```rust
//! # use reqrio::*;
//! # use serde::Serialize;
//! # fn ff() {
//! #[derive(Serialize)]
//! struct Data {
//!     field1: String,
//!     field2: bool,
//! }
//!
//! let url = "https://www.baidu.com/api";
//! let resp = reqrio::post(
//!     url,
//!     Body::json(&Data {
//!         field1: "value".to_string(),
//!         field2: false,
//!     }).unwrap()
//! ).unwrap();
//! # }
//! ```
//!
//! ### Advanced: Custom Session with Fingerprinting
//! For authentic browser emulation, configure a session with custom headers and TLS settings:
//!
//! ```rust
//! # use reqrio::*;
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let headers = json::object! {
//!     "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
//!     "Accept-Encoding": "gzip, deflate, br, zstd",
//!     "Accept-Language": "en-US,en;q=0.9",
//!     "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"
//! };
//!
//! let mut session = ScReq::new()
//!     .with_alpn(ALPN::HTTP20)                    // Use HTTP/2.0 for modern sites
//!     .with_header_json(headers)?                 // Set browser-compatible headers
//!     .with_timeout(Timeout::new_same(5000, 3)); // 5s timeout with 3 retries
//!
//! // Configure TLS fingerprint (if subscription available)
//! // session.set_fingerprint(Fingerprint::chrome_120());
//!
//! // Make requests with persistent session state
//! let resp = session.post("https://api.example.com/data", json::object! {"key": "value"})?;
//! # Ok(())
//! # }
//! ```
//!
//! ### WebSocket Connection (Sync)
//! Real-time communication with WebSocket protocol:
//! ```rust
//! # use reqrio::*;
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let url = "wss://stream.example.com/events";
//!
//! let mut ws = WebSocket::open_sync(url)?;
//!
//! // Read frames in a loop
//! loop {
//!     let frame = ws.read_frame().wait()?;
//!     match frame.frame_type().op_code() {
//!         WsOpcode::TEXT => {
//!             let text = String::from_utf8(frame.payload().as_bytes().to_vec())?;
//!             println!("Received: {}", text);
//!         }
//!         WsOpcode::BINARY => println!("Binary data received"),
//!         WsOpcode::PING => {
//!             ws.send_pong(frame.payload().as_bytes()).wait()?;
//!         }
//!         WsOpcode::CLOSE => break,
//!         _ => {}
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Performance Characteristics
//!
//! - **Request Latency**: ~1-5ms per request (varies by network/server)
//! - **Concurrent Throughput**: 10K+ requests/sec on standard hardware
//! - **Memory Efficiency**: ~50-100KB per idle connection
//! - **Zero Allocation**: Header processing uses stack when possible
//!
//! ## Use Cases
//!
//! - **Web Scraping**: Authentic browser behavior bypass advanced detection
//! - **API Testing**: Precise control over HTTP semantics and TLS configuration
//! - **Real-Time Systems**: WebSocket support for live data streaming
//! - **Reverse Proxies**: Direct TLS record layer access for protocol development
//! - **Performance Tools**: Connection pooling and efficient concurrent requests
//!
//! ## Thread Safety & Concurrency
//!
//! - `ScReq` (Sync): Single-threaded, `Send + Sync` for thread pools
//! - `AcReq` (Async): Tokio-based, designed for `async/await` workloads
//! - Connection pooling and session reuse recommended for production
//!
//! ## Feature Flags
//!
//! - `aync`: Enable async runtime with Tokio support (required for `AcReq`)
//! - `export`: Enable C FFI bindings for cross-language integration
//! - `serde`: Enable serde serialization/deserialization support
//! - `log`: Enable internal debug logging (requires Rust nightly)
//!
//! ## Security Considerations
//!
//! - **Certificate Verification**: Enabled by default; disable only for testing with `verify(false)`
//! - **TLS Session Caching**: Automatic session resumption for performance; explicitly managed
//! - **Memory Safety**: Rust type system prevents buffer overflows and use-after-free bugs
//! - **Constant-Time Operations**: Critical cryptographic operations use constant-time implementations
//!
//! ## Advanced Topics
//!
//! ### Custom TLS Configuration
//! For advanced TLS scenarios like mTLS or custom certificate chains:
//!
//! ```rust,no_run
//! # use reqrio::*;
//! let mut req = ScReq::new();
//!
//! // Load client certificate and key
//! let certs = Certificate::from_pem_file("client.pem")?;
//! let key = RsaKey::from_pri_pem_file("client.key")?;
//!
//! // Add custom CA certificates
//! let ca_certs = Certificate::from_pem_file("ca-bundle.pem")?;
//!
//! // Set them in the request engine
//! // req.with_certs(certs).with_key(key).with_ca_certs(ca_certs);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ### Proxy Configuration
//! Route requests through HTTP/SOCKS proxies:
//!
//! ```rust,no_run
//! # use reqrio::*;
//! // let proxy = Proxy::http("http://proxy.example.com:8080")?;
//! // let mut req = ScReq::new().with_proxy(proxy);
//! ```
//!
//! ## Ecosystem Integration
//!
//! - **reqtls**: Underlying TLS and cryptographic engine
//! - **reqrio-json**: Built-in JSON utilities
//! - **pack**: HTTP/2 header compression support
//!
//! For more examples and advanced usage, visit the [GitHub repository](https://github.com/xllgl2017/reqrio)

#[cfg(feature = "aync")]
mod acq;
pub mod pack;
mod error;
#[cfg(feature = "export")]
mod export;
mod ext;
mod packet;
mod scq;
mod stream;
mod body;
mod fingerprint;
mod reader;
mod request;
mod cookie;
mod time;
#[cfg(feature = "log")]
mod logger;

pub type ReqCallback = Box<dyn FnMut(&[u8]) -> HlsResult<()> + Send + Sync>;
pub const HTTP_GAP: &[u8; 4] = b"\r\n\r\n";
pub const CHUNK_END: [u8; 7] = [13, 10, 48, 13, 10, 13, 10];

use crate::error::HlsResult;
#[cfg(feature = "aync")]
pub use acq::AcReq;
pub use body::{Body, FileForm, HttpFile, BodyData, BodyExt};
pub use error::HlsError;
pub use ext::{ReqExt, ReqStreamExt, UrlExt};
pub use fingerprint::{Fingerprint, H2Finger};
pub use packet::{
    Application, ContentType, Cookie, Font, FrameFlag, FrameType, H2Frame, H2Setting, Header,
    HeaderKey, HeaderValue, HttpStatus, Method, Response, Text, WsFrame, WsOpcode,
};
pub use reqrio_json as json;
pub use reqtls::*;
pub use scq::ScReq;
pub use stream::{Proxy, ProxyStream, ConnParam, WebSocket, TlsStream};
#[cfg(feature = "quic")]
pub use stream::{QUICStream, HTTP3StreamS};
pub use time::{Time, TimeError, Timeout};
#[cfg(feature = "tokio")]
pub use tokio;
#[cfg(feature = "log")]
pub use logger::Logger;
use crate::ext::ReqUrl;

pub fn get<'a>(url: impl Into<ReqUrl<'a>>, body: impl Into<Body<'a>>) -> HlsResult<Response> {
    ScReq::new().get(url, body)
}

pub fn post<'a>(url: impl Into<ReqUrl<'a>>, body: impl Into<Body<'a>>) -> HlsResult<Response> {
    ScReq::new().post(url, body)
}

pub fn put<'a>(url: impl Into<ReqUrl<'a>>, body: impl Into<Body<'a>>) -> HlsResult<Response> {
    ScReq::new().put(url, body)
}
