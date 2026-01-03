//! #### reqrio是http请求库，目标是可以快速、简单、便捷使用http请求
//!
//! * reqrio支持tls指纹，可以通过tls握手的十六进制或ja3设置,仅cls_sync和cls_async支持(**仅订阅**),
//! * reqrio默认对请求头的顺序会默认和浏览器一致(会对请求头进行重排序)
//!
//! #### reqrio默认不开启http请求，仅作为http数据数据流解析库导出，请求需要打开features
//! * std_sync: 标准的tls库([rustls](https://github.com/rustls/rustls)，同步请求
//! * std_async: 标准的tls库([tokio-rustls](https://github.com/rustls/tokio-rustls))，异步请求
//! * cls_sync: 自研tls库(**算法不完善，不校验服务端证书，请勿用于生产模式**)[reqtls](https://github.com/xllgl2017/reqrio/tree/master/reqtls), 同步请求
//! * cls_async: 自研tls库(**算法不完善，不校验服务端证书，请勿用于生产模式**)[reqtls](https://github.com/xllgl2017/reqrio/tree/master/reqtls), 异步请求
//!
//! **注意**: std和cls不可以同时存在，sync和async可以同时存在
//!
//! ### 使用示例(feaures=cls_sync)
//! * 快速请求
//! ```rust
//! use reqrio::ScReq;
//! let req=ScReq::new_with_url("https://www.baidu.com").unwrap();
//! ```
//! * 详细用法:
//! ```rust
//! use reqrio::{Fingerprint, ScReq, ALPN};
//! let fingerprint=Fingerprint::default().unwrap();
//! fingerprint.set_ja3("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,13-11-65037-17613-45-18-16-5-43-10-0-27-23-35-51-65281,4588-29-23-24,0");
//! let req=ScReq::new()
//!     //默认使用http/1.1
//!     .with_alpn(ALPN::Http20)
//!     .with_fingerprint(fingerprint)
//!     .with_url("https://www.baidu.com").unwrap();
//! let headers = json::object! {
//!     "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
//!     "Accept-Encoding": "gzip, deflate, br, zstd",
//!     "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
//!     "Cache-Control": "no-cache",
//!     "Connection": "keep-alive",
//!     "Cookie": "__guid=15015764.1071255116101212729.1764940193317.2156; env_webp=1; _S=pvc5q7leemba50e4kn4qis4b95; QiHooGUID=4C8051464B2D97668E3B21198B9CA207.1766289287750; count=1; so-like-red=2; webp=1; so_huid=114r0SZFiQcJKtA38GZgwZg%2Fdit1cjUGuRcsIL2jTn4%2FE%3D; __huid=114r0SZFiQcJKtA38GZgwZg%2Fdit1cjUGuRcsIL2jTn4%2FE%3D; gtHuid=1",
//!     "Host": "m.so.com",
//!     "Pragma": "no-cache",
//!     "Sec-Fetch-Dest": "document",
//!     "Sec-Fetch-Mode": "navigate",
//!     "Sec-Fetch-Site": "none",
//!     "Sec-Fetch-User": "?1",
//!     "Upgrade-Insecure-Requests": 1,
//!     "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0",
//!     "sec-ch-ua": r#""Microsoft Edge";v="143", "Chromium";v="143", "Not A(Brand";v="24""#,
//!     "sec-ch-ua-mobile": "?0",
//!     "sec-ch-ua-platform": r#""Windows""#
//! };
//! //默认没有任何请求头，需要自己设置
//! req.set_headers_json(header);
//! let mut len = Rc::new(RefCell::new(0));
//! //这里设置回调函数
//! req.set_callback(move|bs|{
//!     *len.borrow_mut() += bs.len();
//!     println!("{}",bs.len());
//! })
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

#[cfg(aync)]
pub use acq::AcReq;
pub use alpn::ALPN;
pub use buffer::Buffer;
#[cfg(anys)]
pub use ext::{ReqExt, ReqGenExt};
pub use json;
pub use packet::{
    Application, Body, ContentType, Cookie, Font, Frame, FrameFlag, FrameType, Header, HeaderValue,
    HttpStatus, Method, Response, Text, HeaderKey,
};
#[cfg(use_cls)]
pub use reqtls::Fingerprint;
#[cfg(sync)]
pub use scq::ScReq;
pub use stream::Proxy;
#[cfg(feature = "cls_async")]
pub use stream::{TlsStream, TlsConnector};
#[cfg(feature = "tokio")]
pub use tokio;
pub use url::{Addr, Protocol, Uri, Url};
pub use error::HlsError;
#[cfg(anys)]
use crate::error::HlsResult;
pub use timeout::Timeout;

#[cfg(anys)]
pub type ReqCallback = Box<dyn FnMut(&[u8]) -> HlsResult<()>>;


#[cfg(aync)]
mod acq;
mod alpn;
mod buffer;
pub mod coder;
mod error;
#[cfg(feature = "export")]
mod export;
#[cfg(anys)]
mod ext;
#[cfg(anys)]
mod file;
mod packet;
#[cfg(sync)]
mod scq;
mod stream;
mod timeout;
mod url;
#[cfg(anys)]
mod body;
