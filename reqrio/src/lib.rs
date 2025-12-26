//! #### reqrio是http请求库，目标是可以使用rust快速、简单、便捷使用http请求
//! ```rust
//! use reqrio::ScReq;
//! let req=ScReq::new_with_url("").unwrap();
//! ```
//! * reqrio支持tls指纹，可以通过tls握手的十六进制或ja3设置,仅cls_sync和cls_async支持,例如:
//! ```rust
//! use reqrio::{Fingerprint, ScReq, ALPN};
//! let fingerprint=Fingerprint::default().unwrap();
//! fingerprint.set_ja3("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,13-11-65037-17613-45-18-16-5-43-10-0-27-23-35-51-65281,4588-29-23-24,0");
//! let req=ScReq::new()
//!     //默认使用http/1.1
//!     .with_alpn(ALPN::Http20)
//!     .with_fingerprint(fingerprint)
//!     .with_url("https://www.baidu.com").unwrap();
//! let header=json::object! {
//!     "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0"
//! }
//! //默认没有任何请求头，需要自己设置
//! req.set_headers_json(header);
//! let res=req.get().unwrap();
//! //获取响应头
//! let header=res.header();
//! //获取响应体,这里的body已经解编码
//! let body=res.decode_body().unwrap();
//! //尝试解码到json
//! let json=res.to_json().unwrap();
//! ```
//!
//!
//!
//!
//!
//!
//!
//!
//!
//!
#[cfg(aync)]
pub use acq::AcReq;
pub use alpn::ALPN;
pub use buffer::Buffer;
pub use ext::{ReqExt, ReqGenExt};
pub use json;
pub use packet::{
    Application, Body, ContentType, Cookie, Font, Frame, FrameFlag, FrameType, Header, HeaderValue,
    HttpStatus, Method, Response, Text,
};
#[cfg(use_cls)]
pub use reqtls::Fingerprint;
#[cfg(sync)]
pub use scq::ScReq;
pub use stream::Proxy;
#[cfg(feature = "tokio")]
pub use tokio;
pub use url::{Addr, Protocol, Uri, Url};

#[cfg(aync)]
mod acq;
mod alpn;
mod buffer;
pub mod coder;
mod error;
#[cfg(feature = "export")]
mod export;
mod ext;
mod file;
mod packet;
#[cfg(sync)]
mod scq;
mod stream;
mod timeout;
mod url;
