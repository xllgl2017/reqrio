use crate::alpn::ALPN;
use crate::coder::HPackCoding;
use crate::error::HlsResult;
use crate::ext::{ReqExt, ReqGenExt, ReqPriExt};
use crate::file::HttpFile;
use crate::packet::*;
use crate::stream::{ConnParam, Proxy, Stream};
use crate::timeout::Timeout;
#[cfg(feature = "cls_sync")]
use reqtls::Fingerprint;
use crate::url::Url;
use crate::buffer::Buffer;
use json::JsonValue;

pub struct ScReq {
    header: Header,
    url: Url,
    hack_coder: HPackCoding,
    stream: Stream,
    files: Vec<HttpFile>,
    timeout: Timeout,
    raw_bytes: Vec<u8>,
    stream_id: u32,
    data: JsonValue,
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
            files: vec![],
            timeout: Timeout::new(),
            raw_bytes: vec![],
            stream_id: 0,
            data: JsonValue::String("".to_string()),
            alpn: ALPN::Http11,
            proxy: Proxy::Null,
            #[cfg(feature = "cls_sync")]
            fingerprint: Fingerprint::default().unwrap(),
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
        loop {
            let rbs = self.stream.sync_read()?;
            if response.extend(&Buffer::new_bytes(rbs))? { break; }
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
        self.raw_bytes.clear();
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
                    println!("{}", self.stream.alpn().alpn_str());
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
        self.data = JsonValue::Null;
        self.files.clear();
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
        loop {
            let rbs = self.stream.sync_read()?;
            self.raw_bytes.extend(rbs);
            while let Ok(frame) = Frame::from_bytes(&self.raw_bytes) {
                if frame.frame_type() == &FrameType::Settings && frame.flags().contains(&FrameFlag::ACK) {
                    let mut end_frame = Frame::none_frame();
                    end_frame.set_frame_type(FrameType::Settings);
                    end_frame.set_flags(vec![FrameFlag::EndStream]);
                    self.stream.sync_write(end_frame.to_bytes().as_ref())?;
                    self.raw_bytes = self.raw_bytes[frame.len() + 9..].to_vec();
                    continue;
                }
                if frame.frame_type() == &FrameType::Goaway { return Err("Connection reset by peer".into()); }
                self.raw_bytes = self.raw_bytes[frame.len() + 9..].to_vec();
                if response.extend_frame(frame, &mut self.hack_coder)? { return Ok(response); }
            }
        }
    }
}

impl ReqGenExt for ScReq {}

impl ReqPriExt for ScReq {}

impl ReqExt for ScReq {
    fn data(&self) -> &JsonValue {
        &self.data
    }

    fn file_bytes(&mut self) -> &mut Vec<HttpFile> {
        &mut self.files
    }

    fn set_data(&mut self, data: JsonValue) {
        self.data = data;
        self.header.set_content_type(ContentType::Application(Application::XWwwFormUrlencoded));
    }

    fn set_text(&mut self, text: String) {
        self.data = JsonValue::String(text);
        self.header.set_content_type(ContentType::Text(Text::Plain));
    }

    fn set_files(&mut self, files: Vec<HttpFile>) {
        self.files = files;
        self.header.set_content_type(ContentType::File("".to_string()))
    }

    fn add_file(&mut self, file: HttpFile) {
        self.files.push(file);
        self.header.set_content_type(ContentType::File("".to_string()))
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