use crate::error::HlsResult;
use crate::packet::*;
use crate::reader::ReadExt;
use crate::stream::{HTTPStream, Stream};
use crate::*;
use json::JsonValue;
use std::collections::HashMap;
use std::path::Path;


pub trait ReqExt: Sized {
    fn header_mut(&mut self) -> &mut Header;
    fn header(&self) -> &Header;
    fn with_timeout(mut self, timeout: Timeout) -> Self {
        self.set_timeout(timeout);
        self
    }
    fn set_timeout(&mut self, timeout: Timeout);
    fn timeout(&self) -> &Timeout;
    fn timeout_mut(&mut self) -> &mut Timeout;
    fn set_proxy(&mut self, proxy: Proxy);
    fn with_proxy(mut self, proxy: Proxy) -> Self {
        self.set_proxy(proxy);
        self
    }

    ///是否校验服务器下发的消息（证书、签名等），默认校验
    fn set_verify(&mut self, verify: bool);
    fn with_verify(mut self, verify: bool) -> Self {
        self.set_verify(verify);
        self
    }
    fn proxy(&self) -> &Proxy;

    ///是否自动进行跳转
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

    ///导出tls key log，不设置时读取SSLKEYLOGFILE环境变量，为保证通信安全，请勿用于生产模式，以免造成隐私泄露
    fn set_key_log(&mut self, path: impl AsRef<Path>);

    fn with_key_log(mut self, path: impl AsRef<Path>) -> Self {
        self.set_key_log(path);
        self
    }

    /// * 必须在建立tls连接（即：set_url/with_url）前设置, 否则需要调re_conn
    /// * 默认使用http2.0去连接，实际使用协议需要和服务器协商
    fn set_alpn(&mut self, alpn: ALPN);
    fn with_alpn(mut self, alpn: ALPN) -> Self {
        self.set_alpn(alpn);
        self
    }

    ///启用mtls，并传入客户端证书
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

    ///用户恢复tls会话的数据
    fn set_tls_session(&mut self, tls_session: Option<TlsSession>);
    fn with_tls_session(mut self, tls_session: Option<TlsSession>) -> Self {
        self.set_tls_session(tls_session);
        self
    }
    fn tls_session(&self) -> &Option<TlsSession>;

    fn set_fingerprint(&mut self, fingerprint: Fingerprint);
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

    fn set_headers_json(&mut self, headers: JsonValue) -> HlsResult<()> {
        let header = ReqExt::header_mut(self);
        header.set_by_json(headers)
    }

    fn with_header_json(mut self, data: JsonValue) -> HlsResult<Self> {
        self.set_headers_json(data)?;
        Ok(self)
    }

    fn with_header(mut self, header: Header) -> Self {
        *self.header_mut() = header;
        self
    }

    fn insert_header(&mut self, k: impl AsRef<str>, v: impl ToString) -> HlsResult<()> {
        ReqExt::header_mut(self).insert(k, v)
    }

    fn remove_header(&mut self, k: impl AsRef<str>) -> Option<HeaderValue> {
        ReqExt::header_mut(self).remove(k)
    }


    ///设置请求头，keep_sort为true时请求头内务必包含必要参数（如：Host, Content-Length等）
    fn with_headers_keys(mut self, headers: Vec<HeaderKey>, keep_sort: bool) -> HlsResult<Self> {
        self.set_header_keys(headers, keep_sort)?;
        Ok(self)
    }

    fn set_header_keys(&mut self, headers: Vec<HeaderKey>, keep_sort: bool) -> HlsResult<()>;
}

pub(crate) trait ReqPriExt: ReqExt {
    fn responses(&mut self) -> &mut HashMap<u64, Response>;


    fn get_resp(&mut self, sid: u64) -> Option<Response> {
        let resp = self.responses().remove(&sid);
        if let Some(resp) = &resp { self.update_cookie(resp) };
        resp
    }

    fn update_cookie(&mut self, response: &Response) {
        let Some(cookies) = response.header().cookies()else { return; };
        for cookie in cookies {
            if cookie.name() == "" && cookie.value() == "" { continue; }
            self.header_mut().add_cookie(cookie.clone());
        }
    }

    fn check_status(&self, uri: &Url, response: &Response) -> HlsResult<()> {
        let status = response.header().status();
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
    fn read_to_vec<T: ReadExt>(mut reader: T) -> HlsResult<Vec<u8>> {
        let mut res = vec![0; reader.len()];
        let mut buffer = Writer::from_ptr(&mut res);
        loop {
            reader.read(&mut buffer)?;
            if reader.wrote() { break; }
            res.resize(res.capacity() + 1024, 0);
        }
        assert_eq!(res.len(), buffer.len());
        Ok(res)
    }
    /// * 最好在调试模式使用，生产模式使用时，一个请求将会产生两次reader，影响效率
    /// * H2严禁使用，否则影响hpack编码
    fn h1_raw_string(&mut self, url: &Url, body: &Body<'_>) -> HlsResult<String> {
        let body_raw = body.to_vec()?;
        let header_reader = self.header().as_reader(HeaderParam {
            url,
            h_sid: &0,
            hpack_encoder: None,
            #[cfg(feature = "quic")]
            q_sid: &0,
            #[cfg(feature = "quic")]
            qpack_encoder: None,
            body_len: body_raw.len(),
            priority: &false,
            weight: &0,
        }, body.context_type())?;
        let mut header = Self::read_to_vec(header_reader)?;
        header.extend(body_raw);
        Ok(String::from_utf8_lossy(&header).to_string())
    }
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
        Ok(Url::try_from(self)?.with_domain(sni))
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