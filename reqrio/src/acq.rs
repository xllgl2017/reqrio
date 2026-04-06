use crate::body::{Body, H2FrameRBuf};
use crate::error::HlsResult;
use crate::ext::{ReqExt, ReqParam};
use crate::ext::{ReqGenExt, ReqPriExt};
use crate::hpack::HPackCoding;
use crate::json::JsonValue;
use crate::packet::{FrameFlag, FrameType, H2Frame, HeaderParam};
use crate::reader::{ReadExt, Reader};
use crate::request::RequestBuffer;
use crate::stream::{ConnParam, Proxy, Stream};
use crate::*;
use std::mem;

pub struct AcReq {
    header: Header,
    scheme: Scheme,
    addr: Addr,
    stream: Stream,
    timeout: Timeout,
    callback: Option<ReqCallback>,
    stream_id: u32,
    proxy: Proxy,
    fingerprint: Fingerprint,
    verify: bool,
    auto_redirect: bool,
    buffer: Buffer,
    hpack_coder: HPackCoding,
    certs: Vec<Certificate>,
    key: RsaKey,
    ca_certs: Vec<Certificate>,
    alpn: ALPN,
}

impl Default for AcReq {
    fn default() -> Self {
        AcReq {
            header: Header::new_req_h1(),
            scheme: Scheme::Http,
            addr: Addr::default(),
            stream: Stream::NonConnection,
            timeout: Timeout::default(),
            callback: None,
            stream_id: 0,
            proxy: Proxy::Null,
            fingerprint: Fingerprint::default(),
            verify: true,
            auto_redirect: true,
            buffer: Buffer::with_capacity(32826),
            hpack_coder: HPackCoding::new(4096),
            certs: vec![],
            key: RsaKey::none(),
            ca_certs: vec![],
            alpn: ALPN::Http11,
        }
    }
}

impl AcReq {
    pub fn new() -> AcReq {
        AcReq::default()
    }

    pub async fn get(&mut self, url: impl TryInto<Url>, body: impl Into<Body<'_>>) -> HlsResult<Response> {
        self.header.set_method(Method::GET);
        self.stream_io(url, body.into()).await
    }

    pub async fn post(&mut self, url: impl TryInto<Url>, body: impl Into<Body<'_>>) -> HlsResult<Response> {
        self.header.set_method(Method::POST);
        self.stream_io(url, body.into()).await
    }

    pub async fn put(&mut self, url: impl TryInto<Url>, body: impl Into<Body<'_>>) -> HlsResult<Response> {
        self.header.set_method(Method::PUT);
        self.stream_io(url, body.into()).await
    }

    pub async fn options(&mut self, url: impl TryInto<Url>, body: impl Into<Body<'_>>) -> HlsResult<Response> {
        self.header.set_method(Method::OPTIONS);
        self.stream_io(url, body.into()).await
    }

    pub async fn delete(&mut self, url: impl TryInto<Url>, body: impl Into<Body<'_>>) -> HlsResult<Response> {
        self.header.set_method(Method::DELETE);
        self.stream_io(url, body.into()).await
    }

    pub async fn head(&mut self, url: impl TryInto<Url>, body: impl Into<Body<'_>>) -> HlsResult<Response> {
        self.header.set_method(Method::HEAD);
        self.stream_io(url, body.into()).await
    }

    pub async fn trace(&mut self, url: impl TryInto<Url>, body: impl Into<Body<'_>>) -> HlsResult<Response> {
        self.header.set_method(Method::TRACE);
        self.stream_io(url, body.into()).await
    }

    pub async fn patch(&mut self, url: impl TryInto<Url>, body: impl Into<Body<'_>>) -> HlsResult<Response> {
        self.header.set_method(Method::PATCH);
        self.stream_io(url, body.into()).await
    }

    pub async fn h1_io(&mut self) -> HlsResult<Response> {
        let mut response = Response::new();
        let mut read_len = 0;
        loop {
            self.stream.async_read(&mut self.buffer).await?;
            if self.handle_h1_res(&mut response, &mut read_len)? { break; }
        }
        Ok(response)
    }

    pub(crate) async fn handle_io(&mut self, body: &Body<'_>) -> HlsResult<Response> {
        let mut request = RequestBuffer::new(&mut self.header, body, HeaderParam {
            addr: &self.addr,
            scheme: &self.scheme,
            encoder: self.hpack_coder.encoder(),
            stream_identifier: &self.stream_id,
            body_len: 0,
        })?;
        self.buffer.reset();
        loop {
            let mut render = Reader::new(self.buffer.unfilled_mut());
            let len = request.read(&mut render)?;
            if len == 0 { break; }
            self.stream.async_write(render.filled()).await?;
        }
        let response = match self.header.alpn() {
            ALPN::Http20 => self.h2c_io().await,
            _ => self.h1_io().await
        }?;
        self.update_cookie(&response);
        self.callback = None;
        if let ALPN::Http20 = self.header.alpn() { self.stream_id += 2; }
        Ok(response)
    }

    pub async fn stream_io(&mut self, url: impl TryInto<Url>, body: Body<'_>) -> HlsResult<Response> {
        self.set_url(url).await?;
        for i in 0..self.timeout.handle_times() {
            let res = tokio::time::timeout(self.timeout.handle(), self.handle_io(&body)).await;
            self.buffer.reset();
            match res {
                Ok(res) => match res {
                    Ok(res) => {
                        let code = res.header().status().code();
                        return if self.auto_redirect && (300..400).contains(&code) {
                            let location = res.header().location().ok_or("missing location")?;
                            let url = if location.starts_with("http") {
                                Url::try_from(location)?
                            } else {
                                Url::from_inner(self.scheme.clone(), self.addr.clone(), Uri::try_from(location)?)
                            };
                            self.header.set_method(Method::GET);
                            Box::pin(self.stream_io(url, Body::none())).await
                        } else {
                            Ok(res)
                        };
                    }
                    Err(e) => {
                        if i != self.timeout.handle_times() - 1 {
                            if e.to_string().to_lowercase().contains("close") || e.to_string().contains("中止了") || e.to_string().contains("关闭") {
                                self.re_conn().await?;
                            }
                            println!("[AcReq] write/recv with error-{}, handle: {}/{}", e, i + 2, self.timeout.handle_times());
                            continue;
                        } else { return Err(e); }
                    }
                }

                Err(_) => if i != self.timeout.handle_times() - 1 {
                    println!("[AcReq] write/recv timeout, timeout: {:?}, handle: {}/{}", self.timeout.handle(), i + 2, self.timeout.handle_times());
                    continue;
                } else { return Err("time out".into()); }
            }
        }
        Err("stream io error".into())
    }

    pub async fn re_conn(&mut self) -> HlsResult<()> {
        self.buffer.reset();
        for i in 0..self.timeout.connect_times() {
            let param = ConnParam {
                scheme: &self.scheme,
                addr: &self.addr,
                proxy: &self.proxy,
                timeout: &self.timeout,
                fingerprint: &mut self.fingerprint,
                alpn: &self.alpn,
                verify: self.verify,
                cert: &mut self.certs,
                key: &mut self.key,
                ca_cert: &self.ca_certs,
            };
            let res = tokio::time::timeout(self.timeout.connect(), self.stream.async_conn(param)).await;
            match &res {
                Ok(res) => if let Err(e) = res && i != self.timeout.handle_times() - 1 {
                    println!("[AcReq] connect with error-{}, handle: {}/{}", e, i + 2, self.timeout.handle_times());
                    continue;
                }
                Err(e) => if i != self.timeout.handle_times() - 1 {
                    println!("[AcReq] connect error, error: {:?}, handle: {}/{}", e.to_string(), i + 2, self.timeout.handle_times());
                    continue;
                }
            }
            return match res {
                Ok(res) => match res {
                    Ok(alpn) => {
                        self.header.init_by_alpn(alpn);
                        if self.header.alpn() == &ALPN::Http20 { self.handle_h2_setting().await?; }
                        Ok(())
                    }
                    Err(e) => Err(e),
                },
                Err(_) => Err(format!("connect timeout, handle:{}; timeout: {:?}", self.timeout.handle_times(), self.timeout.connect()).into())
            };
        }
        Err("[AcReq] connection error".into())
    }

    pub(crate) async fn set_url(&mut self, url: impl TryInto<Url>) -> HlsResult<()> {
        let (scheme, addr, uri) = url.try_into().or(Err(RlsError::Url(UrlError::ParseUrlError)))?.into_inner();
        let old_addr = mem::replace(&mut self.addr, addr);
        let old_scheme = mem::replace(&mut self.scheme, scheme);
        self.header.set_uri(uri);
        if self.addr.host() != old_addr.host() || self.scheme != old_scheme {
            self.re_conn().await?;
        }
        Ok(())
    }

    pub async fn send_check(&mut self, method: Method, url: impl TryInto<Url>, body: impl Into<Body<'_>>) -> HlsResult<Response> {
        self.header.set_method(method);
        let response = self.stream_io(url, body.into()).await?;
        self.check_status(&response)?;
        Ok(response)
    }

    pub async fn send_check_json(&mut self, method: Method, url: impl TryInto<Url>, body: impl Into<Body<'_>>,
                                 k: impl AsRef<str>, v: impl ToString, e: Vec<impl AsRef<str>>) -> HlsResult<JsonValue> {
        let response = self.send_check(method, url, body).await?;
        self.check_res(response, k, v, e)
    }
}

impl AcReq {
    pub async fn handle_h2_setting(&mut self) -> HlsResult<()> {
        self.stream_id = 0;
        self.buffer.write_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")?;
        self.buffer.write_slice(self.fingerprint.h2_setting())?;
        self.hpack_coder = HPackCoding::new(65535);
        self.buffer.write_slice(self.fingerprint.h2_window_update())?;
        self.stream.async_write(self.buffer.filled()).await?;
        self.buffer.reset();
        self.stream_id += 1;
        Ok(())
    }

    pub async fn h2c_io(&mut self) -> HlsResult<Response> {
        let mut response = Response::new();
        loop {
            self.stream.async_read(&mut self.buffer).await?;
            while let Ok((frame_type, frame_flag, frame_len)) = H2FrameRBuf::buffer_enough(&self.buffer) {
                if frame_type == FrameType::Settings && frame_flag.end_stream() {
                    let mut end_frame = H2Frame::none_frame();
                    end_frame.set_frame_type(FrameType::Settings);
                    end_frame.set_flag(FrameFlag::EndStream);
                    self.stream.async_write(end_frame.to_bytes().as_ref()).await?;
                    self.buffer.move_to(frame_len..self.buffer.len(), 0);
                    continue;
                }
                if self.handle_h2_res(frame_type, &mut response)? { return Ok(response); }
            }
        }
    }
}

impl ReqGenExt for AcReq {
    fn stream_mut(&mut self) -> &mut Stream {
        &mut self.stream
    }
}

impl ReqPriExt for AcReq {
    fn into_stream(self) -> Stream {
        self.stream
    }

    fn req_param(&mut self) -> ReqParam<'_> {
        ReqParam {
            header: &mut self.header,
            buffer: &mut self.buffer,
            hpack_coder: &mut self.hpack_coder,
            callback: &mut self.callback,
            addr: &self.addr,
            sid: &self.stream_id,
            scheme: &self.scheme,

        }
    }
}

impl ReqExt for AcReq {
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

    fn timeout_mut(&mut self) -> &mut Timeout {
        &mut self.timeout
    }

    fn set_proxy(&mut self, proxy: Proxy) {
        self.proxy = proxy;
    }

    fn set_verify(&mut self, verify: bool) {
        self.verify = verify;
    }

    fn set_auto_redirect(&mut self, auto_redirect: bool) {
        self.auto_redirect = auto_redirect;
    }

    fn set_alpn(&mut self, alpn: ALPN) {
        self.alpn = alpn;
    }

    fn set_mtls(&mut self, certs: Vec<Certificate>, key: RsaKey, ca: Option<Vec<Certificate>>) {
        self.certs = certs;
        self.key = key;
        self.ca_certs = ca.unwrap_or(vec![]);
    }

    fn set_callback(&mut self, callback: impl FnMut(&[u8]) -> HlsResult<()> + 'static) {
        self.callback = Some(Box::new(callback));
    }

    fn set_fingerprint(&mut self, fingerprint: Fingerprint) {
        self.fingerprint = fingerprint;
    }
}

unsafe impl Send for AcReq {}

unsafe impl Sync for AcReq {}