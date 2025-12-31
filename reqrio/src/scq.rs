use crate::alpn::ALPN;
use crate::body::BodyType;
use crate::buffer::Buffer;
use crate::coder::{HPackCoding, HackDecode};
use crate::error::HlsResult;
use crate::ext::{ReqExt, ReqGenExt, ReqPriExt};
use crate::packet::*;
use crate::stream::{ConnParam, Proxy, Stream};
use crate::timeout::Timeout;
use crate::url::Url;
use json::JsonValue;
#[cfg(feature = "cls_sync")]
use reqtls::Fingerprint;
use std::mem;
use crate::ReqCallback;

pub struct ScReq {
    header: Header,
    url: Url,
    hack_coder: HPackCoding,
    stream: Stream,
    body: BodyType,
    callback: Option<ReqCallback>,
    timeout: Timeout,
    stream_id: u32,
    alpn: ALPN,
    proxy: Proxy,
    #[cfg(feature = "cls_sync")]
    fingerprint: Fingerprint,
}

impl ScReq {
    pub fn new() -> ScReq {
        ScReq {
            header: Header::new_req_h1(),
            url: Url::new(),
            hack_coder: HPackCoding::new(),
            stream: Stream::unconnection(),
            body: BodyType::Text("".to_string()),
            callback: None,
            timeout: Timeout::new(),
            stream_id: 0,
            alpn: ALPN::Http11,
            proxy: Proxy::Null,
            #[cfg(feature = "cls_sync")]
            fingerprint: Fingerprint::default(),
        }
    }

    pub fn get(&mut self) -> HlsResult<Response> {
        self.header.set_method(Method::GET);
        self.stream_io()
    }

    pub fn post(&mut self) -> HlsResult<Response> {
        self.header.set_method(Method::POST);
        self.stream_io()
    }

    pub fn put(&mut self) -> HlsResult<Response> {
        self.header.set_method(Method::PUT);
        self.stream_io()
    }

    pub fn options(&mut self) -> HlsResult<Response> {
        self.header.set_method(Method::OPTIONS);
        self.stream_io()
    }

    pub fn delete(&mut self) -> HlsResult<Response> {
        self.header.set_method(Method::DELETE);
        self.stream_io()
    }

    pub fn head(&mut self) -> HlsResult<Response> {
        self.header.set_method(Method::HEAD);
        self.stream_io()
    }

    pub fn trach(&mut self) -> HlsResult<Response> {
        self.header.set_method(Method::TRACH);
        self.stream_io()
    }

    pub fn h1_io(&mut self, context: Vec<u8>) -> HlsResult<Response> {
        self.stream.sync_write(context.as_slice())?;
        let mut response = Response::new();
        let mut buffer = Buffer::with_capacity(16413);
        let mut read_len = 0;
        loop {
            buffer.reset();
            self.stream.sync_read(&mut buffer)?;
            if self.handle_h1_res(&buffer, &mut response, &mut read_len)? { break; }
        }
        Ok(response)
    }

    fn handle_io(&mut self) -> HlsResult<Response> {
        let response = match self.stream.alpn() {
            ALPN::Http20 => {
                let headers = self.gen_h2_header()?;
                let body = self.gen_h2_body()?;
                self.h2c_io(headers, body)
            }
            _ => {
                let context = self.gen_h1()?;
                self.h1_io(context)
            }
        }?;
        self.update_cookie(&response);
        self.callback = None;
        if let ALPN::Http20 = self.alpn { self.stream_id += 2; }
        Ok(response)
    }

    pub fn stream_io(&mut self) -> HlsResult<Response> {
        for i in 0..self.timeout.handle_times() {
            let res = self.handle_io();
            match res {
                Ok(res) => return Ok(res),
                Err(e) => if i != self.timeout.handle_times() - 1 {
                    println!("[ScReq] write/recv error, error: {}, handle: {}/{}", e.to_string(), i + 2, self.timeout.handle_times());
                    continue;
                }
            }
        }
        Err("stream io error".into())
    }

    pub fn with_proxy(mut self, proxy: Proxy) -> Self {
        self.proxy = proxy;
        self
    }

    ///默认使用http2.0去连接，实际使用协议需要和服务器协商
    pub fn with_alpn(mut self, alpn: ALPN) -> Self {
        self.alpn = alpn;
        self
    }

    pub fn re_conn(&mut self) -> HlsResult<()> {
        self.hack_coder = HPackCoding::new();
        self.stream_id = 0;
        for i in 0..self.timeout.connect_times() {
            let param = ConnParam {
                url: &self.url,
                proxy: &self.proxy,
                timeout: &self.timeout,
                #[cfg(feature = "cls_sync")]
                fingerprint: &mut self.fingerprint,
                alpn: &self.alpn,
            };
            match self.stream.sync_connect(param) {
                Ok(_) => {
                    // println!("{}", self.stream.alpn().alpn_str());
                    self.header.init_by_alpn(self.stream.alpn());
                    if self.stream.alpn() == &ALPN::Http20 { self.handle_h2_setting()?; }
                    return Ok(());
                }
                Err(e) => if i != self.timeout.connect_times() - 1 {
                    println!("[ScReq] continue with error-{}, handle: {}/{}", e.to_string(), i + 2, self.timeout.handle_times());
                    continue;
                }
            }
        }
        Err("[ScReq] connection error".into())
    }

    pub fn with_url(mut self, url: &str) -> HlsResult<Self> {
        self.set_url(url)?;
        Ok(self)
    }

    #[cfg(feature = "cls_sync")]
    pub fn with_fingerprint(mut self, fingerprint: Fingerprint) -> Self {
        self.fingerprint = fingerprint;
        self
    }

    #[cfg(feature = "cls_sync")]
    pub fn set_fingerprint(&mut self, fingerprint: Fingerprint) {
        self.fingerprint = fingerprint;
    }

    pub fn new_with_url(url: impl AsRef<str>) -> HlsResult<ScReq> {
        let mut res = Self::new();
        res.set_url(url)?;
        Ok(res)
    }

    pub fn set_url(&mut self, url: impl AsRef<str>) -> HlsResult<()> {
        let body = mem::replace(&mut self.body, BodyType::Text("".to_string()));
        drop(body);
        let old_host = self.url.addr().host().to_string();
        self.url = Url::try_from(url.as_ref())?;
        if self.url.addr().host() != old_host {
            let host = self.url.addr().to_string().replace(":80", "").replace(":443", "");
            self.header.set_host(host)?;
            self.re_conn()?;
        }
        Ok(())
    }

    pub fn send_check(&mut self, method: Method) -> HlsResult<Response> {
        self.header.set_method(method);
        let response = self.stream_io()?;
        self.check_status(&response)?;
        Ok(response)
    }

    pub fn send_check_json(&mut self, method: Method, k: impl AsRef<str>, v: impl ToString, e: Vec<impl AsRef<str>>) -> HlsResult<JsonValue> {
        let response = self.send_check(method)?;
        self.check_res(response, k, v, e)
    }
}

impl ScReq {
    pub fn handle_h2_setting(&mut self) -> HlsResult<()> {
        let mut handshake = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".as_bytes().to_vec();
        let setting_frame = Frame::default_setting();
        handshake.extend(setting_frame.to_bytes());
        let update_frame = Frame::window_update();
        handshake.extend(update_frame.to_bytes());
        self.stream.sync_write(&handshake)?;
        self.stream_id += 1;
        Ok(())
    }

    pub fn h2c_io(&mut self, headers: Vec<HeaderKey>, body: Vec<u8>) -> HlsResult<Response> {
        let hdr_bs = self.hack_coder.encode(headers)?;
        let header_frame = Frame::new_header(hdr_bs, body.len(), self.stream_id);
        self.stream.sync_write(header_frame.to_bytes().as_slice())?;
        for body_frame in Frame::new_body(body, self.stream_id) {
            self.stream.sync_write(body_frame.to_bytes().as_slice())?;
        }
        let mut response = Response::new();
        let mut buffer = Buffer::with_capacity(0xFFFF);
        loop {
            self.stream.sync_read(&mut buffer)?;
            while let Ok(frame) = Frame::from_bytes(&mut buffer) {
                if frame.frame_type() == &FrameType::Settings && frame.flags().contains(&FrameFlag::ACK) {
                    let mut end_frame = Frame::none_frame();
                    end_frame.set_frame_type(FrameType::Settings);
                    end_frame.set_flags(vec![FrameFlag::EndStream]);
                    self.stream.sync_write(end_frame.to_bytes().as_ref())?;
                    continue;
                }
                if self.handle_h2_res(frame, &mut response)? { return Ok(response); };
            }
        }
    }
}

impl ReqGenExt for ScReq {}

impl ReqPriExt for ScReq {
    fn callback(&mut self) -> &mut Option<ReqCallback> {
        &mut self.callback
    }

    fn hack_decoder(&mut self) -> &mut HackDecode {
        self.hack_coder.decoder()
    }
}

impl ReqExt for ScReq {
    fn body_type(&self) -> &BodyType {
        &self.body
    }

    fn body_type_mut(&mut self) -> &mut BodyType {
        &mut self.body
    }

    fn header_mut(&mut self) -> &mut Header {
        &mut self.header
    }

    fn header(&self) -> &Header {
        &self.header
    }

    fn set_timeout(&mut self, timeout: Timeout) {
        self.timeout = timeout;
    }

    fn timeout(&self) -> &Timeout {
        &self.timeout
    }

    fn url(&self) -> &Url {
        &self.url
    }

    fn url_mut(&mut self) -> &mut Url {
        &mut self.url
    }

    fn set_proxy(&mut self, proxy: Proxy) {
        self.proxy = proxy;
    }

    fn set_alpn(&mut self, alpn: ALPN) {
        self.alpn = alpn;
    }

    fn set_callback(&mut self, callback: impl FnMut(&[u8]) -> HlsResult<()> + 'static) {
        self.callback = Some(Box::new(callback));
    }

    #[cfg(use_cls)]
    fn set_fingerprint(&mut self, fingerprint: Fingerprint) {
        self.fingerprint = fingerprint;
    }
}

impl Drop for ScReq {
    fn drop(&mut self) {
        let _ = self.stream.sync_shutdown();
    }
}

#[cfg(feature = "export")]
unsafe impl Send for ScReq {}