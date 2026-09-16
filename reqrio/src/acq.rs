use crate::body::Body;
use crate::error::HlsResult;
use crate::ext::ReqPriExt;
use crate::ext::{ReqExt, ReqUrl};
use crate::json::JsonValue;
use crate::packet::HeaderParam;
use crate::stream::{ConnParam, HTTPStream, Proxy, Stream};
use crate::*;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

pub struct AcReq {
    header: Header,
    stream: HTTPStream,
    timeout: Timeout,
    proxy: Proxy,
    fingerprint: Fingerprint,
    verify: bool,
    auto_redirect: bool,
    redirect_times: i32,
    certs: Vec<Certificate>,
    key: RsaKey,
    ca_certs: Vec<Certificate>,
    alpn: ALPN,
    key_log: Option<PathBuf>,
    url: Url,
    tls_session: Option<TlsSession>,
    ignore_order: bool,
    responses: HashMap<u64, Response>,
    recv_ids: HashSet<u64>,
}

impl Default for AcReq {
    fn default() -> Self {
        AcReq {
            header: Header::default(),
            stream: HTTPStream::NonConnection,
            timeout: Timeout::default(),
            proxy: Proxy::Null,
            fingerprint: Fingerprint::default(),
            verify: true,
            auto_redirect: true,
            redirect_times: i32::MAX,
            certs: vec![],
            key: RsaKey::none(),
            ca_certs: vec![],
            alpn: ALPN::HTTP20,
            key_log: None,
            url: Default::default(),
            tls_session: None,
            ignore_order: false,
            responses: HashMap::with_capacity(100),
            recv_ids: HashSet::new(),
        }
    }
}

impl AcReq {
    pub fn new() -> AcReq {
        AcReq::default()
    }

    pub async fn get<'a>(&mut self, url: impl Into<ReqUrl<'a>>, body: impl Into<Body<'a>>) -> HlsResult<Response> {
        self.do_http(Method::GET, url, body).await
    }

    pub async fn post<'a>(&mut self, url: impl Into<ReqUrl<'a>>, body: impl Into<Body<'a>>) -> HlsResult<Response> {
        self.do_http(Method::POST, url, body).await
    }

    pub async fn put<'a>(&mut self, url: impl Into<ReqUrl<'a>>, body: impl Into<Body<'a>>) -> HlsResult<Response> {
        self.do_http(Method::PUT, url, body).await
    }

    pub async fn options<'a>(&mut self, url: impl Into<ReqUrl<'a>>, body: impl Into<Body<'a>>) -> HlsResult<Response> {
        self.do_http(Method::OPTIONS, url, body).await
    }

    pub async fn delete<'a>(&mut self, url: impl Into<ReqUrl<'a>>, body: impl Into<Body<'a>>) -> HlsResult<Response> {
        self.do_http(Method::DELETE, url, body).await
    }

    pub async fn head<'a>(&mut self, url: impl Into<ReqUrl<'a>>, body: impl Into<Body<'a>>) -> HlsResult<Response> {
        self.do_http(Method::HEAD, url, body).await
    }

    pub async fn trace<'a>(&mut self, url: impl Into<ReqUrl<'a>>, body: impl Into<Body<'a>>) -> HlsResult<Response> {
        self.do_http(Method::TRACE, url, body).await
    }

    pub async fn patch<'a>(&mut self, url: impl Into<ReqUrl<'a>>, body: impl Into<Body<'a>>) -> HlsResult<Response>    {
        self.do_http(Method::PATCH, url, body).await
    }

    pub async fn query<'a>(&mut self, url: impl Into<ReqUrl<'a>>, body: impl Into<Body<'a>>) -> HlsResult<Response> {
        self.do_http(Method::QUERY, url, body).await
    }


    pub async fn send<'a>(&mut self, method: Method, url: impl Into<ReqUrl<'a>>, body: impl Into<Body<'a>>) -> HlsResult<u64> {
        let url = url.into().build()?;
        self.header.set_method(method);
        self.set_url(url.as_ref()).await?;
        let sid = self.stream.send_async(&self.header, &body.into(), HeaderParam {
            url: url.as_ref(),
            hpack_encoder: None,
            h_sid: &0,
            #[cfg(feature = "quic")]
            qpack_encoder: None,
            #[cfg(feature = "quic")]
            q_sid: &0,
            body_len: 0,
            priority: &self.fingerprint.h2().priority,
            weight: &self.fingerprint.h2().weight,
        }).await?;
        self.responses.insert(sid, Response::new());
        Ok(sid)
    }

    pub async fn recv(&mut self, sid: u64) -> HlsResult<Response> {
        if self.recv_ids.remove(&sid) && let Some(resp) = self.get_resp(sid) { return Ok(resp); }
        loop {
            let ids = self.stream.recv_async(&mut self.responses).await?;
            ids.into_iter().for_each(|id| { self.recv_ids.insert(id); });
            if self.recv_ids.remove(&sid) && let Some(resp) = self.get_resp(sid) { return Ok(resp); }
        }
    }

    async fn handle_recv(&mut self, mut sid: u64) -> HlsResult<Response> {
        let mut redirect_times = 0;
        while redirect_times < self.redirect_times {
            let resp = self.recv(sid).await?;
            let code = resp.header().status().code();
            if self.auto_redirect && (300..400).contains(&code) {
                let location = resp.header().location().ok_or("missing location")?;
                let location = match location.starts_with("http") {
                    false => Cow::Owned(format!("{}://{}{}", self.url.scheme(), self.url.addr(), location)),
                    true => Cow::Borrowed(location),
                };
                sid = self.send(Method::GET, location.as_ref(), &Body::none()).await?;
                redirect_times += 1;
                continue;
            }
            return Ok(resp);
        }
        Err("redirection exceeds the maximum".into())
    }

    async fn recv_stream(&mut self, sid: u64) -> HlsResult<&Header> {
        loop {
            let resp = self.responses.get(&sid).ok_or("response not inited or finished")?;
            if !resp.header().is_empty() { break; }
            let ids = self.stream.recv_async(&mut self.responses).await?;
            ids.into_iter().for_each(|id| { self.recv_ids.insert(id); });
        }
        let resp = self.responses.get(&sid).ok_or("response not inited or finished")?;
        Ok(resp.header())
    }

    pub async fn next_chunk(&mut self, sid: u64) -> HlsResult<Option<&[u8]>> {
        loop {
            let resp = self.responses.get(&sid).ok_or("response not inited or finished")?;
            if !resp.raw.is_empty() { break; }
            if self.recv_ids.remove(&sid) {
                self.responses.remove(&sid);
                return Ok(None);
            }
            let ids = self.stream.recv_async(&mut self.responses).await?;
            ids.into_iter().for_each(|id| { self.recv_ids.insert(id); });
        }
        let resp = self.responses.get_mut(&sid).ok_or("response not inited or finished")?;
        let offset = resp.raw.offset();
        resp.raw.reset();
        Ok(Some(resp.raw.slice(offset)))
    }

    /// 流式请求，仅返回请求头，请求体需调next_chunk
    pub async fn send_stream<'a>(&mut self, method: Method, url: impl Into<ReqUrl<'a>>, body: impl Into<Body<'a>>) -> HlsResult<(u64, &Header)> {
        let sid = self.send(method, url, body).await?;
        let header = self.recv_stream(sid).await?;
        Ok((sid, header))
    }

    pub async fn do_http<'a>(&mut self, method: Method, url: impl Into<ReqUrl<'a>>, body: impl Into<Body<'a>>) -> HlsResult<Response> {
        let url = url.into().build()?;
        let body = body.into();
        for i in 1..=self.timeout.handle_times() {
            let sid = self.send(method, url.as_ref(), &body).await?;
            let res = tokio::time::timeout(self.timeout.handle(), self.handle_recv(sid)).await;
            match res {
                Err(_) => if i >= self.timeout.handle_times() { return Err(HlsError::Time(TimeError::HandleTimeout)) }
                Ok(Err(e)) => if i >= self.timeout.handle_times() {
                    return Err(e)
                } else if self.timeout.is_peer_closed(e.to_string()) {
                    self.re_conn(None).await?;
                },
                Ok(Ok(resp)) => return Ok(resp)
            }
        }
        Err("stream io error".into())
    }

    pub async fn connect<'a>(mut self, url: impl Into<ReqUrl<'a>>) -> HlsResult<AcReq> {
        let url = url.into().build()?;
        self.re_conn(Some(url.as_ref())).await?;
        Ok(self)
    }

    pub async fn re_conn(&mut self, url: Option<&Url>) -> HlsResult<()> {
        for i in 1..=self.timeout.connect_times() {
            let param = ConnParam {
                url: url.unwrap_or(&self.url),
                proxy: &self.proxy,
                timeout: &self.timeout,
                fingerprint: &mut self.fingerprint,
                alpn: &self.alpn,
                verify: self.verify,
                cert: &mut self.certs,
                key: &mut self.key,
                ca_cert: &self.ca_certs,
                key_log: &self.key_log,
                ech: false,
                session: &self.tls_session,
            };
            let res = tokio::time::timeout(self.timeout.connect(), self.stream.conn_async(param)).await;
            match res {
                Err(_) => if i >= self.timeout.handle_times() { return Err(HlsError::Time(TimeError::ConnectTimeout)) }
                Ok(Err(e)) => if i >= self.timeout.handle_times() { return Err(e) }
                Ok(Ok(alpn)) => {
                    #[cfg(feature = "log")]
                    debug!("[AcReq] Connected | ALPN: {} | RemoteAddr: {}", alpn, url.unwrap_or(&self.url).addr());
                    self.tls_session = None;
                    if !self.ignore_order { self.header.init_by_alpn(alpn); }
                    if let Some(url) = url {
                        self.url = url.clone();
                    }
                    return Ok(());
                }
            }
            continue;
        }
        Err("[AcReq] connection error".into())
    }

    pub(crate) async fn set_url(&mut self, url: &Url) -> HlsResult<()> {
        if self.url.addr().host() != url.addr().host() || url.scheme() != self.stream.scheme() {
            self.re_conn(Some(url)).await?;
        }
        Ok(())
    }

    pub async fn send_check<'a>(&mut self, method: Method, url: impl Into<ReqUrl<'a>>, body: impl Into<Body<'a>>) -> HlsResult<Response> {
        let url = url.into().build()?;
        let response = self.do_http(method, url.as_ref(), &body.into()).await?;
        self.check_status(url.as_ref(), &response)?;
        Ok(response)
    }

    pub async fn send_check_json<'a, U>(
        &mut self,
        method: Method,
        url: impl Into<ReqUrl<'a>>,
        body: impl Into<Body<'a>>,
        k: impl AsRef<str>,
        v: impl ToString,
        e: Vec<impl AsRef<str>>,
    ) -> HlsResult<JsonValue> {
        let response = self.send_check(method, url, body).await?;
        self.check_res(response, k, v, e)
    }
}

impl ReqStreamExt for AcReq {
    fn into_stream(self) -> HlsResult<Stream> {
        self.stream.into_stream()
    }

    fn http_stream_mut(&mut self) -> &mut HTTPStream {
        &mut self.stream
    }
}

impl ReqPriExt for AcReq {
    fn responses(&mut self) -> &mut HashMap<u64, Response> {
        &mut self.responses
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

    fn proxy(&self) -> &Proxy { &self.proxy }

    fn set_auto_redirect(&mut self, auto_redirect: bool) {
        self.auto_redirect = auto_redirect;
    }

    fn set_max_redirect_exceeds(&mut self, max_redirect_exceeded: i32) {
        self.redirect_times = max_redirect_exceeded
    }

    fn set_key_log(&mut self, path: impl AsRef<Path>) {
        self.key_log = Some(path.as_ref().to_path_buf());
    }

    fn set_alpn(&mut self, alpn: ALPN) {
        self.alpn = alpn;
    }

    fn set_mtls(&mut self, certs: Vec<Certificate>, key: RsaKey, ca: Option<Vec<Certificate>>) {
        self.certs = certs;
        self.key = key;
        self.ca_certs = ca.unwrap_or(vec![]);
    }

    fn set_tls_session(&mut self, tls_session: Option<TlsSession>) {
        self.tls_session = tls_session;
    }

    fn tls_session(&self) -> &Option<TlsSession> {
        &self.tls_session
    }

    fn set_fingerprint(&mut self, fingerprint: Fingerprint) {
        self.fingerprint = fingerprint;
    }

    fn set_header_keys(&mut self, headers: Vec<HeaderKey>, keep_sort: bool) -> HlsResult<()> {
        self.header.set_by_keys(headers, keep_sort)?;
        self.ignore_order = keep_sort;
        Ok(())
    }
}

unsafe impl Send for AcReq {}

unsafe impl Sync for AcReq {}