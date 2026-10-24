use crate::error::HlsResult;
use crate::packet::*;
use crate::stream::{HTTPStream, Stream, StreamMessage};
use crate::*;
use json::JsonValue;
use std::collections::HashMap;
use std::slice;

pub trait ReqExt: Sized {
    fn header_mut(&mut self) -> &mut Header;
    fn header(&self) -> &Header;
    fn with_timeout(mut self, timeout: Timeout) -> Self {
        self.set_timeout(timeout);
        self
    }
    fn set_timeout(&mut self, timeout: Timeout) {
        *self.timeout_mut() = timeout;
    }
    fn timeout(&self) -> &Timeout;
    fn timeout_mut(&mut self) -> &mut Timeout;
    fn set_proxy(&mut self, proxy: Proxy);
    fn with_proxy(mut self, proxy: Proxy) -> Self {
        self.set_proxy(proxy);
        self
    }

    /// Whether to verify server-provided messages (certificates, signatures, etc.); enabled by default.
    fn set_verify(&mut self, verify: bool);
    fn with_verify(mut self, verify: bool) -> Self {
        self.set_verify(verify);
        self
    }
    fn proxy(&self) -> &Proxy;

    /// Whether to automatically follow redirects.
    fn set_auto_redirect(&mut self, auto_redirect: bool);
    fn with_auto_redirect(mut self, auto_redirect: bool) -> Self {
        self.set_auto_redirect(auto_redirect);
        self
    }
    fn set_max_redirect_exceeds(&mut self, max_redirect_exceeded: i32);
    fn with_max_redirect_exceeded(mut self, max_redirect_exceeded: i32) -> Self {
        self.set_max_redirect_exceeds(max_redirect_exceeded);
        self
    }

    /// Export a TLS key log.
    /// Note: do not enable this in production as it can expose sensitive traffic data.
    fn set_key_log(&mut self, path: impl Into<String>);

    fn with_key_log(mut self, path: impl Into<String>) -> Self {
        self.set_key_log(path);
        self
    }
    /// Accept `SSLKEYLOGFILE`.
    fn with_env_key_log(mut self) -> Self {
        if let Ok(key_log) = std::env::var("SSLKEYLOGFILE") {
            self.set_key_log(key_log);
        }
        self
    }

    /// * Must be set before establishing the TLS connection; otherwise call `re_conn`.
    /// * HTTP/2.0 is used by default; the actual protocol is negotiated with the server.
    fn set_alpn(&mut self, alpn: ALPN);
    fn with_alpn(mut self, alpn: ALPN) -> Self {
        self.set_alpn(alpn);
        self
    }

    /// * Must be set before establishing the TLS connection; otherwise call `re_conn`.
    /// * TLS 1.3 is used by default; the actual protocol is negotiated with the server.
    fn set_version(&mut self, version: Version);
    fn with_version(mut self, version: Version) -> Self {
        self.set_version(version);
        self
    }

    /// Enable mTLS and provide the client certificate.
    ///```no_run
    /// use reqrio::*;
    ///
    /// let mut req=ScReq::new();
    /// let certs=Certificate::from_pem_file("path/to/cert").unwrap();
    /// let key=RsaKey::from_pri_pem_file("path/to/cert/key").unwrap();
    /// req.set_mtls(certs,key,None);
    /// ```
    fn set_mtls(&mut self, certs: Vec<Certificate>, key: RsaKey, ca: Option<Vec<Certificate>>);
    fn with_mtls(mut self, certs: Vec<Certificate>, key: RsaKey, ca: Option<Vec<Certificate>>) -> Self {
        self.set_mtls(certs, key, ca);
        self
    }

    /// TLS session data used to resume a session.
    fn set_tls_session(&mut self, tls_session: Option<TlsSession>);
    fn with_tls_session(mut self, tls_session: Option<TlsSession>) -> Self {
        self.set_tls_session(tls_session);
        self
    }
    fn tls_session(&self) -> Option<&TlsSession>;

    fn fingerprint_mut(&mut self) -> &mut Fingerprint;
    fn set_fingerprint(&mut self, fingerprint: Fingerprint) {
        #[repr(C)]
        struct Item<'a> {
            name: &'a str,
            value: &'a str,
        }
        if let Some(finger) = fingerprint.adv.as_ref() {
            let items = unsafe { slice::from_raw_parts(finger.hdr as *const Item, finger.hdr_count as usize) };
            for item in items {
                match (item.name, fingerprint.sec_full) {
                    ("sec-ch-ua" |
                    "sec-ch-ua-mobile" |
                    "sec-ch-ua-platform" |
                    "user-agent", _) => self.header_mut().insert(item.name, item.value),
                    (_, true) => self.header_mut().insert(item.name, item.value),
                    (_, false) => {}
                }
            }
        }
        *self.fingerprint_mut() = fingerprint;
    }
    fn with_fingerprint(mut self, fingerprint: Fingerprint) -> Self {
        self.set_fingerprint(fingerprint);
        self
    }
    fn set_headers(&mut self, mut headers: Header, keep_cookie: bool) {
        let header = ReqExt::header_mut(self);
        if keep_cookie {
            let cks = header.cookies().unwrap_or(&[]).to_vec();
            headers.set_cookies(cks);
        }
        *header = headers;
    }

    fn set_headers_json(&mut self, headers: JsonValue) {
        let header = ReqExt::header_mut(self);
        header.set_by_json(headers)
    }

    fn with_header_json(mut self, data: JsonValue) -> Self {
        self.set_headers_json(data);
        self
    }

    fn with_header(mut self, header: Header) -> Self {
        *self.header_mut() = header;
        self
    }

    fn insert_header(&mut self, k: impl AsRef<str>, v: impl Into<HeaderValue>) {
        ReqExt::header_mut(self).insert(k, v)
    }

    fn remove_header(&mut self, k: impl AsRef<str>) -> Option<HeaderValue> {
        ReqExt::header_mut(self).remove(k)
    }


    /// Set request headers. When `keep_sort` is `true`, the headers must include required fields such as `Host` and `Content-Length`.
    fn with_headers_keys(mut self, headers: Vec<HeaderItem>, keep_sort: bool) -> HlsResult<Self> {
        self.set_header_keys(headers, keep_sort)?;
        Ok(self)
    }

    fn set_header_keys(&mut self, headers: Vec<HeaderItem>, keep_sort: bool) -> HlsResult<()>;
}

pub(crate) trait ReqPriExt: ReqExt {
    fn responses(&mut self) -> &mut HashMap<u64, StreamMessage>;


    fn get_resp(&mut self, sid: u64) -> Option<Response> {
        let resps = self.responses();
        let resp = resps.remove(&sid).map(|x| x.final_response())?;
        self.update_cookie(resp.header());
        Some(resp)
    }

    fn update_cookie(&mut self, header: &Header) {
        for cookie in header.cookies().unwrap_or(&[]) {
            if cookie.name() == "" && cookie.value() == "" { continue; }
            self.header_mut().add_cookie(cookie.clone());
        }
    }

    fn check_status(&self, uri: &Url, response: &Response) -> HlsResult<()> {
        let status = response.status();
        match status.code() {
            400..600 => Err(format!("网络请求错误-{}({})", status, uri).into()),
            _ => Ok(())
        }
    }

    fn check_res(&self, response: Response, k: impl AsRef<str>, v: impl ToString, e: Vec<impl AsRef<str>>) -> HlsResult<JsonValue> {
        let data = response.json()?;
        if data[k.as_ref()].to_string() != v.to_string() {
            for e in e {
                if !data[e.as_ref()].is_null() { return Err(data[e.as_ref()].to_string().into()); }
            }
            Err(format!("check fail: key: {}; value: {}", k.as_ref(), v.to_string()).into())
        } else { Ok(data) }
    }
}

pub trait ReqStreamExt: ReqExt {
    fn into_stream(self) -> HlsResult<Stream>;
    fn http_stream_mut(&mut self) -> &mut HTTPStream;
}

pub trait UrlExt {
    fn params(&self, params: impl AsRef<JsonValue>) -> Result<Url, UrlError>;
    fn sni(&self, sni: impl Into<String>) -> Result<Url, UrlError>;
}

impl UrlExt for str {
    fn params(&self, params: impl AsRef<JsonValue>) -> Result<Url, UrlError> {
        let mut url = Url::try_from(self)?;
        for (key, value) in params.as_ref().entries() {
            match value {
                JsonValue::String(value) => url.uri_mut().insert_param(key, value),
                _ => url.uri_mut().insert_param(key, value.dump())
            }
        }
        Ok(url)
    }

    fn sni(&self, sni: impl Into<String>) -> Result<Url, UrlError> {
        Ok(Url::try_from(self)?.with_domain(sni))
    }
}

impl UrlExt for String {
    fn params(&self, params: impl AsRef<JsonValue>) -> Result<Url, UrlError> {
        self.as_str().params(params)
    }

    fn sni(&self, sni: impl Into<String>) -> Result<Url, UrlError> {
        self.as_str().sni(sni)
    }
}

pub enum ReqUrl<'a> {
    Own(Url),
    Ref(&'a Url),
    Str(&'a str),
    String(String),
    Res(Result<Url, UrlError>),
}

impl<'a> ReqUrl<'a> {
    pub fn build(self) -> HlsResult<Self> {
        Ok(match self {
            ReqUrl::Str(url) => ReqUrl::Own(Url::try_from(url)?),
            ReqUrl::String(url) => ReqUrl::Own(Url::try_from(url.as_str())?),
            ReqUrl::Res(url) => ReqUrl::Own(url?),
            _ => self
        })
    }
}

impl<'a> AsRef<Url> for ReqUrl<'a> {
    fn as_ref(&self) -> &Url {
        match self {
            ReqUrl::Own(url) => url,
            ReqUrl::Ref(url) => url,
            _ => unreachable!()
        }
    }
}

impl<'a> From<Url> for ReqUrl<'a> {
    fn from(url: Url) -> Self {
        ReqUrl::Own(url)
    }
}

impl<'a> From<&'a Url> for ReqUrl<'a> {
    fn from(url: &'a Url) -> Self {
        ReqUrl::Ref(url)
    }
}

impl<'a> From<&'a str> for ReqUrl<'a> {
    fn from(url: &'a str) -> Self {
        ReqUrl::Str(url)
    }
}

impl<'a> From<String> for ReqUrl<'a> {
    fn from(url: String) -> Self {
        ReqUrl::String(url)
    }
}

impl<'a> From<&'a String> for ReqUrl<'a> {
    fn from(url: &'a String) -> Self {
        ReqUrl::Str(url.as_str())
    }
}

impl<'a> From<&'a mut String> for ReqUrl<'a> {
    fn from(url: &'a mut String) -> Self {
        ReqUrl::Str(url.as_str())
    }
}

impl<'a> From<Result<Url, UrlError>> for ReqUrl<'a> {
    fn from(value: Result<Url, UrlError>) -> Self {
        ReqUrl::Res(value)
    }
}