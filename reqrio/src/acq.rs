use std::mem;
use crate::alpn::ALPN;
use crate::coder::HPackCoding;
use crate::error::HlsResult;
use crate::ext::ReqExt;
use crate::ext::{ReqGenExt, ReqPriExt};
use crate::packet::{Frame, FrameFlag, FrameType, Header, HeaderKey, Method, Response};
use crate::stream::{ConnParam, Proxy, Stream};
use crate::timeout::Timeout;
use crate::url::Url;
use crate::Buffer;
use json::JsonValue;
#[cfg(use_cls)]
use reqtls::Fingerprint;
use crate::body::BodyType;

pub struct AcReq {
    header: Header,
    url: Url,
    hack_coder: HPackCoding,
    stream: Stream,
    timeout: Timeout,
    raw_bytes: Vec<u8>,
    stream_id: u32,
    body: BodyType,
    alpn: ALPN,
    proxy: Proxy,
    #[cfg(use_cls)]
    fingerprint: Fingerprint,
}

impl AcReq {
    pub fn new() -> AcReq {
        AcReq {
            header: Header::new_req_h1(),
            url: Url::new(),
            hack_coder: HPackCoding::new(),
            stream: Stream::unconnection(),
            timeout: Timeout::new(),
            raw_bytes: vec![],
            stream_id: 0,
            alpn: ALPN::Http11,
            proxy: Proxy::Null,
            #[cfg(use_cls)]
            fingerprint: Fingerprint::default(),
            body: BodyType::Text("".to_string()),
        }
    }

    pub async fn get(&mut self) -> HlsResult<Response> {
        self.header.set_method(Method::GET);
        self.stream_io().await
    }

    pub async fn post(&mut self) -> HlsResult<Response> {
        self.header.set_method(Method::POST);
        self.stream_io().await
    }

    pub async fn put(&mut self) -> HlsResult<Response> {
        self.header.set_method(Method::PUT);
        self.stream_io().await
    }

    pub async fn options(&mut self) -> HlsResult<Response> {
        self.header.set_method(Method::OPTIONS);
        self.stream_io().await
    }

    pub async fn delete(&mut self) -> HlsResult<Response> {
        self.header.set_method(Method::DELETE);
        self.stream_io().await
    }

    pub async fn head(&mut self) -> HlsResult<Response> {
        self.header.set_method(Method::HEAD);
        self.stream_io().await
    }

    pub async fn trach(&mut self) -> HlsResult<Response> {
        self.header.set_method(Method::TRACH);
        self.stream_io().await
    }

    pub async fn h1_io(&mut self, context: Vec<u8>) -> HlsResult<Response> {
        self.stream.async_write(context.as_slice()).await?;
        let mut response = Response::new();
        let mut buffer = Buffer::with_capacity(16413);
        loop {
            buffer.reset();
            self.stream.async_read(&mut buffer).await?;
            if response.extend(&buffer)? { break; }
        }
        Ok(response)
    }

    async fn handle_io(&mut self) -> HlsResult<Response> {
        let response = match self.stream.alpn() {
            ALPN::Http20 => {
                let headers = self.gen_h2_header()?;
                let body = self.gen_h2_body()?;
                self.h2c_io(headers, body).await
            }
            _ => {
                let context = self.gen_h1()?;
                self.h1_io(context).await
            }
        }?;
        self.update_cookie(&response);
        if let ALPN::Http20 = self.stream.alpn() { self.stream_id += 2; }
        Ok(response)
    }

    pub async fn stream_io(&mut self) -> HlsResult<Response> {
        for i in 0..self.timeout.handle_times() {
            let res = tokio::time::timeout(self.timeout.handle(), self.handle_io()).await;
            match &res {
                Ok(res) => if let Err(e) = res && i != self.timeout.handle_times() - 1 {
                    if e.to_string().to_lowercase().contains("close") {
                        self.re_conn().await?;
                    }
                    println!("[AcReq] write/recv with error-{}, handle: {}/{}", e.to_string(), i + 2, self.timeout.handle_times());
                    continue;
                }
                Err(_) => if i != self.timeout.handle_times() - 1 {
                    println!("[AcReq] write/recv timeout, timeout: {:?}, handle: {}/{}", self.timeout.handle(), i + 2, self.timeout.handle_times());
                    continue;
                }
            }
            return match res {
                Ok(res) => res,
                Err(_) => Err(format!("handle timeout, handle:{}; timeout: {:?}", self.timeout.handle_times(), self.timeout.handle()).into())
            };
        }
        Err("stream io error".into())
    }

    pub async fn re_conn(&mut self) -> HlsResult<()> {
        self.hack_coder = HPackCoding::new();
        self.stream_id = 0;
        self.raw_bytes.clear();
        for i in 0..self.timeout.connect_times() {
            let param = ConnParam {
                url: &self.url,
                proxy: &self.proxy,
                timeout: &self.timeout,
                #[cfg(use_cls)]
                fingerprint: &mut self.fingerprint,
                alpn: &self.alpn,
            };
            let res = tokio::time::timeout(self.timeout.connect(), self.stream.async_connect(param)).await;
            match &res {
                Ok(res) => if let Err(e) = res && i != self.timeout.handle_times() - 1 {
                    println!("[AcReq] connect with error-{}, handle: {}/{}", e.to_string(), i + 2, self.timeout.handle_times());
                    continue;
                }
                Err(e) => if i != self.timeout.handle_times() - 1 {
                    println!("[AcReq] connect error, error: {:?}, handle: {}/{}", e.to_string(), i + 2, self.timeout.handle_times());
                    continue;
                }
            }
            return match res {
                Ok(res) => match res {
                    Ok(_) => {
                        self.header.init_by_alpn(self.stream.alpn());
                        if self.stream.alpn() == &ALPN::Http20 { self.handle_h2_setting().await?; }
                        Ok(())
                    }
                    Err(e) => Err(e.into()),
                },
                Err(_) => Err(format!("connect timeout, handle:{}; timeout: {:?}", self.timeout.handle_times(), self.timeout.handle()).into())
            };
        }
        Err("[AcReq] connection error".into())
    }

    pub async fn with_url(mut self, url: impl AsRef<str>) -> HlsResult<Self> {
        self.set_url(url).await?;
        Ok(self)
    }

    pub async fn new_with_url(url: impl AsRef<str>) -> HlsResult<AcReq> {
        let mut res = Self::new();
        res.set_url(url).await?;
        Ok(res)
    }

    pub async fn set_url(&mut self, url: impl AsRef<str>) -> HlsResult<()> {
        let body = mem::replace(&mut self.body, BodyType::Text("".to_string()));
        drop(body);
        let old_host = self.url.addr().host().to_string();
        self.url = Url::try_from(url.as_ref())?;
        if self.url.addr().host() != old_host {
            let host = self.url.addr().to_string().replace(":80", "").replace(":443", "");
            self.header.set_host(host)?;
            self.re_conn().await?;
        }
        Ok(())
    }

    pub async fn send_check(&mut self, method: Method) -> HlsResult<Response> {
        self.header.set_method(method);
        let response = self.stream_io().await?;
        self.check_status(&response)?;
        Ok(response)
    }

    pub async fn send_check_json(&mut self, method: Method, k: impl AsRef<str>, v: impl ToString, e: Vec<impl AsRef<str>>) -> HlsResult<JsonValue> {
        let response = self.send_check(method).await?;
        self.check_res(response, k, v, e)
    }
}

impl AcReq {
    pub async fn handle_h2_setting(&mut self) -> HlsResult<()> {
        let mut handshake = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".as_bytes().to_vec();
        let setting_frame = Frame::default_setting();
        handshake.extend(setting_frame.to_bytes());
        let update_frame = Frame::window_update();
        handshake.extend(update_frame.to_bytes());
        self.stream.async_write(&handshake).await?;
        self.stream_id += 1;
        Ok(())
    }

    pub async fn h2c_io(&mut self, headers: Vec<HeaderKey>, body: Vec<u8>) -> HlsResult<Response> {
        let hdr_bs = self.hack_coder.encode(headers)?;
        let header_frame = Frame::new_header(hdr_bs, body.len(), self.stream_id);
        self.stream.async_write(header_frame.to_bytes().as_slice()).await?;
        for body_frame in Frame::new_body(body, self.stream_id) {
            self.stream.async_write(body_frame.to_bytes().as_slice()).await?;
        }
        let mut response = Response::new();
        let mut buffer = Buffer::with_capacity(16413);
        loop {
            buffer.reset();
            self.stream.async_read(&mut buffer).await?;
            self.raw_bytes.extend_from_slice(buffer.filled());
            while let Ok(frame) = Frame::from_bytes(&self.raw_bytes) {
                if frame.frame_type() == &FrameType::Settings && frame.flags().contains(&FrameFlag::ACK) {
                    let mut end_frame = Frame::none_frame();
                    end_frame.set_frame_type(FrameType::Settings);
                    end_frame.set_flags(vec![FrameFlag::EndStream]);
                    self.stream.async_write(end_frame.to_bytes().as_ref()).await?;
                    self.raw_bytes = self.raw_bytes[frame.len() + 9..].to_vec();
                    continue;
                }
                if frame.frame_type() == &FrameType::Goaway { return Err("Connection reset by peer".into()); }
                self.raw_bytes = self.raw_bytes[frame.len() + 9..].to_vec();
                if response.extend_frame(frame, self.hack_coder.decoder())? { return Ok(response); }
            }
        }
    }
}

impl ReqGenExt for AcReq {}

impl ReqPriExt for AcReq {}

impl ReqExt for AcReq {
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

    #[cfg(use_cls)]
    fn set_fingerprint(&mut self, fingerprint: Fingerprint) {
        self.fingerprint = fingerprint;
    }
}