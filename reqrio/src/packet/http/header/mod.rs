use super::content_type::ContentType;
use super::cookie::Cookie;
use crate::cookie::CookieManager;
use crate::error::{HlsError, HlsResult};
use crate::pack::PackItem;
use crate::json::JsonValue;
use crate::reader::{RefReader, StrCow};
use crate::*;
pub use key::HeaderKey;
pub use method::Method;
use reader::{H1HeaderReader, H2HeaderReader};
pub use reader::{HeaderParam, HeaderReader};
pub use status::HttpStatus;
use std::borrow::Cow;
use std::fmt::Display;
use std::mem;
pub use value::HeaderValue;
pub use error::HeaderError;
#[cfg(feature = "quic")]
use crate::packet::http::header::reader::H3HeaderReader;

mod value;
mod key;
mod method;
mod status;
mod reader;
mod error;

#[derive(Clone)]
pub struct Header {
    method: Method,
    alpn: ALPN,
    uri: Uri,
    status: HttpStatus,
    keys: Vec<HeaderKey>,
}

impl Default for Header {
    fn default() -> Self {
        Header {
            method: Method::GET,
            alpn: ALPN::default(),
            uri: Uri::default(),
            status: HttpStatus::None,
            keys: vec![],
        }
    }
}

impl Header {
    #[cfg(feature = "quic")]
    pub fn new_req_h3() -> Self {
        Header {
            method: Method::GET,
            uri: Uri::default(),
            alpn: ALPN::HTTP30,
            status: HttpStatus::None,
            keys: vec![
                //h2 order
                HeaderKey::new_reserved("origin", ""),
                HeaderKey::new_reserved("sec-ch-ua-platform", ""),
                HeaderKey::new_reserved("user-agent", format!("reqrio/{}", env!("CARGO_PKG_VERSION"))),
                HeaderKey::new_reserved("sec-ch-ua", ""),
                HeaderKey::new_reserved("sec-ch-ua-mobile", ""),
                HeaderKey::new_reserved("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"),
                HeaderKey::new_reserved("sec-fetch-site", ""),
                HeaderKey::new_reserved("sec-fetch-mode", ""),
                HeaderKey::new_reserved("sec-fetch-user", ""),
                HeaderKey::new_reserved("sec-fetch-dest", ""),
                HeaderKey::new_reserved("referer", ""),
                HeaderKey::new_reserved("accept-encoding", "gzip, deflate, br, zstd"),
                HeaderKey::new_reserved("accept-language", "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6"),
                HeaderKey::new_reserved("priority", ""),


                //unknown or http
                HeaderKey::new_reserved("cache-control", ""),
                HeaderKey::new_reserved("sec-ch-ua-full-version", ""),
                HeaderKey::new_reserved("sec-ch-ua-arch", ""),
                HeaderKey::new_reserved("sec-ch-ua-platform-version", ""),
                HeaderKey::new_reserved("sec-ch-ua-model", ""),
                HeaderKey::new_reserved("sec-ch-ua-bitness", ""),
                HeaderKey::new_reserved("sec-ch-ua-full-version-list", ""),
                HeaderKey::new_reserved("upgrade-insecure-requests", ""),
                HeaderKey::new_reserved("sec-fetch-storage-access", ""),
                HeaderKey::new_reserved("cookie", HeaderValue::Cookies(CookieManager::new(vec![]))),
                HeaderKey::new_reserved("content-encoding", ""),
                HeaderKey::new_reserved("content-type", ""),
                HeaderKey::new_reserved("authorization", ""),
            ],
        }
    }

    pub fn new_req_h2() -> Self {
        Header {
            method: Method::GET,
            uri: Uri::default(),
            alpn: ALPN::HTTP20,
            status: HttpStatus::None,
            keys: vec![
                //h2 order
                HeaderKey::new_reserved("pragma", ""),
                HeaderKey::new_reserved("cache-control", ""),
                HeaderKey::new_reserved("ect", ""),
                HeaderKey::new_reserved("sec-ch-ua", ""),
                HeaderKey::new_reserved("sec-ch-ua-mobile", ""),
                HeaderKey::new_reserved("sec-ch-ua-full-version", ""),
                HeaderKey::new_reserved("sec-ch-ua-arch", ""),
                HeaderKey::new_reserved("sec-ch-ua-platform", ""),
                HeaderKey::new_reserved("sec-ch-ua-platform-version", ""),
                HeaderKey::new_reserved("sec-ch-ua-model", ""),
                HeaderKey::new_reserved("sec-ch-ua-bitness", ""),
                HeaderKey::new_reserved("sec-ch-ua-full-version-list", ""),
                HeaderKey::new_reserved("sec-ch-prefers-color-scheme", ""),
                HeaderKey::new_reserved("upgrade-insecure-requests", ""),
                HeaderKey::new_reserved("user-agent", format!("reqrio/{}", env!("CARGO_PKG_VERSION"))),
                HeaderKey::new_reserved("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"),
                HeaderKey::new_reserved("origin", ""),
                HeaderKey::new_reserved("sec-fetch-site", ""),
                HeaderKey::new_reserved("sec-fetch-mode", ""),
                HeaderKey::new_reserved("sec-fetch-user", ""),
                HeaderKey::new_reserved("sec-fetch-dest", ""),
                HeaderKey::new_reserved("sec-fetch-storage-access", ""),
                HeaderKey::new_reserved("referer", ""),
                HeaderKey::new_reserved("accept-encoding", "gzip, deflate, br, zstd"),
                HeaderKey::new_reserved("accept-language", "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6"),
                HeaderKey::new_reserved("cookie", HeaderValue::Cookies(CookieManager::new(vec![]))),
                HeaderKey::new_reserved("priority", ""),
                //unknown or http
                HeaderKey::new_reserved("content-encoding", ""),
                HeaderKey::new_reserved("content-type", ""),
                HeaderKey::new_reserved("authorization", ""),
            ],
        }
    }

    pub fn new_req_h1() -> Self {
        Header {
            method: Method::GET,
            uri: Uri::default(),
            alpn: ALPN::HTTP11,
            status: HttpStatus::None,
            keys: vec![
                HeaderKey::new_reserved("Host", ""),
                HeaderKey::new_reserved("Connection", ""),
                HeaderKey::new_reserved("Content-Length", 0),
                HeaderKey::new_reserved("Authorization", ""),
                HeaderKey::new_reserved("Content-Type", ""),
                HeaderKey::new_reserved("Cache-Control", ""),
                HeaderKey::new_reserved("sec-ch-ua", ""),
                HeaderKey::new_reserved("sec-ch-ua-mobile", ""),
                HeaderKey::new_reserved("sec-ch-ua-platform", ""),
                HeaderKey::new_reserved("Upgrade-Insecure-Requests", ""),
                HeaderKey::new_reserved("User-Agent", format!("reqrio/{}", env!("CARGO_PKG_VERSION"))),
                HeaderKey::new_reserved("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"),
                HeaderKey::new_reserved("Sec-Fetch-Site", ""),
                HeaderKey::new_reserved("Sec-Fetch-Mode", ""),
                HeaderKey::new_reserved("Sec-Fetch-User", ""),
                HeaderKey::new_reserved("Sec-Fetch-Dest", ""),
                HeaderKey::new_reserved("Sec-Fetch-Storage-Access", ""),
                HeaderKey::new_reserved("Referer", ""),
                HeaderKey::new_reserved("Accept-Encoding", "gzip, deflate, br, zstd"),
                HeaderKey::new_reserved("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6"),
                HeaderKey::new_reserved("Cookie", HeaderValue::Cookies(CookieManager::new(vec![]))),
                HeaderKey::new_reserved("Origin", ""),
            ],
        }
    }

    pub fn to_req_cookie_str(&self) -> String {
        let header = self.keys.iter().find(|x| x.name().eq_ignore_ascii_case("cookie"));
        if let Some(header) = header && let Some(cookie) = header.cookies() {
            cookie.iter().map(|cookie| cookie.as_req()).collect::<Vec<_>>().join("; ")
        } else {
            "".to_string()
        }
    }

    pub fn get(&self, name: impl AsRef<str>) -> Option<&HeaderValue> {
        let header = self.keys.iter().find(|x| x.name().eq_ignore_ascii_case(name.as_ref()))?;
        Some(header.value())
    }

    pub fn get_str(&self, name: impl AsRef<str>) -> Option<&str> {
        let header = self.keys.iter().find(|x| x.name().eq_ignore_ascii_case(name.as_ref()))?;
        header.value().as_string()
    }

    pub fn get_mut(&mut self, name: impl AsRef<str>) -> Option<&mut HeaderValue> {
        let header = self.keys.iter_mut().find(|x| x.name().eq_ignore_ascii_case(name.as_ref()))?;
        Some(header.value_mut())
    }

    pub fn remove(&mut self, name: impl AsRef<str>) -> Option<HeaderValue> {
        let pos = self.keys.iter().position(|x| x.name().eq_ignore_ascii_case(name.as_ref()))?;
        Some(self.keys.remove(pos).into_value())
    }

    #[deprecated]
    pub fn as_h2c(&self) -> HlsResult<Vec<HeaderKey>> {
        let mut res = self.keys.clone();
        res.insert(0, HeaderKey::new(":method", HeaderValue::String(self.method.to_string())));
        let invalid_keys = ["connection", "host", "content-length", "transfer-encoding", "upgrade"];
        let res = res.into_iter().filter(|x| !invalid_keys.contains(&x.name_lower().as_str()) && x.value().to_string() != "").collect();
        Ok(res)
    }

    pub fn add_cookie(&mut self, cookie: Cookie) {
        match self.keys.iter_mut().find(|x| x.name().eq_ignore_ascii_case("cookie")) {
            None => self.keys.push(HeaderKey::new("cookie", HeaderValue::Cookies(CookieManager::new(vec![cookie])))),
            Some(header) => header.value_mut().add_cookie(cookie)
        }
    }

    pub fn set_cookies(&mut self, ck: Vec<Cookie>) {
        let header = self.keys.iter_mut().find(|x| x.name().eq_ignore_ascii_case("cookie"));
        match header {
            None => self.keys.push(HeaderKey::new("cookie", HeaderValue::Cookies(CookieManager::new(ck)))),
            Some(header) => header.set_value(HeaderValue::Cookies(CookieManager::new(ck))),
        }
    }

    pub fn set_cookie(&mut self, ck: impl AsRef<str>) -> HlsResult<()> {
        let cookies = Cookie::from_req(ck.as_ref())?;
        self.set_cookies(cookies);
        Ok(())
    }

    ///cookie请使用set_cookie/add_cookie
    pub fn insert(&mut self, k: impl AsRef<str>, v: impl ToString) -> HlsResult<()> {
        let lower_key = k.as_ref().to_lowercase().replace("contentlength", "content-length")
            .replace("contenttype", "content-type");
        let header = self.keys.iter_mut().find(|x| x.name().eq_ignore_ascii_case(&lower_key));
        if let Some(header) = header {
            match header.name_lower().as_str() {
                "cookie" => {
                    let mut cookies = Cookie::from_req(v.to_string())?;
                    match cookies.len() {
                        2.. => header.set_value(HeaderValue::Cookies(CookieManager::new(cookies))),
                        1 => header.value_mut().add_cookie(cookies.remove(0)),
                        0 => {}
                    }
                }
                "content-length" => header.set_value(HeaderValue::Number(v.to_string().parse()?)),
                "content-type" => header.set_value(HeaderValue::ContextType(ContentType::try_from(&v.to_string())?)),
                "upgrade-insecure-requests" => header.set_value(HeaderValue::String(v.to_string())),
                "set-cookie" => header.value_mut().add_cookie(Cookie::from_res(v.to_string())?),
                _ => header.set_value(HeaderValue::String(v.to_string())),
            }
        } else {
            match lower_key.as_ref() {
                "set-cookie" => {
                    let cookie = Cookie::from_res(v.to_string())?;
                    self.keys.push(HeaderKey::new(k.as_ref(), HeaderValue::Cookies(CookieManager::new(vec![cookie]))));
                }
                "cookie" => {
                    let cookies = Cookie::from_req(v.to_string())?;
                    self.keys.push(HeaderKey::new(k.as_ref(), HeaderValue::Cookies(CookieManager::new(cookies))));
                }
                "content-length" => self.keys.push(HeaderKey::new(k.as_ref(), HeaderValue::Number(v.to_string().parse()?))),
                "content-type" => self.keys.push(HeaderKey::new(k.as_ref(), HeaderValue::ContextType(ContentType::try_from(&v.to_string())?))),
                "update-table-size" => self.keys.push(HeaderKey::new(k.as_ref(), HeaderValue::Number(v.to_string().parse()?))),
                _ => self.keys.push(HeaderKey::new(k.as_ref(), HeaderValue::String(v.to_string()))),
            }
        }
        Ok(())
    }

    pub fn set_user_agent(&mut self, user_agent: impl ToString) -> HlsResult<()> {
        self.insert("user-agent", user_agent)
    }

    pub fn set_sec_ch_ua(&mut self, sec_ch_ua: impl ToString) -> HlsResult<()> {
        self.insert("sec-ch-ua", sec_ch_ua.to_string())
    }

    pub fn sec_ch_ua(&self) -> Option<&str> {
        self.get("sec-ch-ua")?.as_string()
    }

    pub fn set_sec_ch_ua_mobile(&mut self, sec_ch_ua_mobile: impl ToString) -> HlsResult<()> {
        self.insert("sec-ch-ua-mobile", sec_ch_ua_mobile.to_string())
    }

    pub fn sec_ch_ua_mobile(&self) -> Option<&str> {
        self.get("sec-ch-ua-mobile")?.as_string()
    }

    pub fn set_sec_ch_ua_platform(&mut self, sec_ch_ua_platform: impl ToString) -> HlsResult<()> {
        self.insert("sec-ch-ua-platform", sec_ch_ua_platform.to_string())
    }

    pub fn sec_ch_ua_platform(&self) -> Option<&str> {
        self.get("sec-ch-ua-platform")?.as_string()
    }

    pub fn user_agent(&self) -> Option<&str> {
        self.get("user-agent")?.as_string()
    }


    pub fn host(&self) -> Option<&str> {
        self.get("host")?.as_string()
    }

    pub fn set_origin(&mut self, origin: impl ToString) -> HlsResult<()> {
        self.insert("origin", origin)
    }

    pub fn set_referer(&mut self, referer: impl ToString) -> HlsResult<()> {
        self.insert("referer", referer)
    }

    pub fn referer(&self) -> Option<&str> {
        self.get("referer")?.as_string()
    }

    pub fn set_accept(&mut self, accept: impl ToString) -> HlsResult<()> {
        self.insert("accept", accept)
    }

    pub fn set_content_length(&mut self, content_length: usize) -> HlsResult<()> {
        self.insert("content-length", content_length)
    }

    pub fn max_table_size(&self) -> Option<usize> {
        if let HeaderValue::Number(size) = self.get("update-table-size")? {
            Some(*size)
        } else { None }
    }

    pub fn set_content_type(&mut self, content_type: ContentType) {
        let header = self.keys.iter_mut().find(|x| x.name_lower() == "content-type");
        if let Some(header) = header {
            header.set_value(HeaderValue::ContextType(content_type))
        } else {
            self.keys.push(HeaderKey::new("content-type", HeaderValue::ContextType(content_type)));
        }
    }

    pub fn set_connection(&mut self, connection: impl ToString) -> HlsResult<()> {
        self.insert("connection", connection)
    }

    pub fn content_length(&self) -> Option<usize> {
        let value = self.get("content-length")?;
        match value {
            HeaderValue::Number(len) => Some(*len),
            _ => None
        }
    }

    pub fn content_type(&self) -> Option<&ContentType> {
        match self.get("content-type")? {
            HeaderValue::ContextType(ct) => Some(ct),
            _ => None
        }
    }

    pub fn cookies(&self) -> Option<&[Cookie]> {
        let header = self.keys.iter().find(|x|
            x.name().eq_ignore_ascii_case("cookie")
                || x.name().eq_ignore_ascii_case("set-cookie")
        );
        header?.cookies()
    }

    pub fn cookies_mut(&mut self) -> Option<&mut [Cookie]> {
        let header = self.keys.iter_mut().find(|x|
            x.name().eq_ignore_ascii_case("cookie")
                || x.name().eq_ignore_ascii_case("set-cookie")
        );
        header?.cookies_mut()
    }

    pub fn method(&self) -> &Method { &self.method }

    pub fn alpn(&self) -> &ALPN { &self.alpn }

    pub fn uri(&self) -> &Uri {
        &self.uri
    }

    pub fn is_empty(&self) -> bool {
        self.alpn.value().is_empty() && self.status == HttpStatus::None
    }

    pub fn content_encoding(&self) -> Option<&str> {
        self.get("content-encoding")?.as_string()
    }

    pub fn set_content_encoding(&mut self, encoding: impl ToString) -> HlsResult<()> {
        self.insert("content-encoding", encoding)
    }

    pub fn accept_encoding(&self) -> Option<&str> {
        self.get("accept-encoding")?.as_string()
    }

    pub fn set_method(&mut self, method: Method) { self.method = method; }

    pub fn set_uri(&mut self, uri: Uri) {
        self.uri = uri;
    }

    pub fn location(&self) -> Option<&str> {
        self.get("location")?.as_string()
    }

    pub fn authorization(&self) -> Option<&str> {
        self.get("authorization")?.as_string()
    }

    pub fn set_authorization(&mut self, authorization: impl ToString) -> HlsResult<()> {
        self.insert("authorization", authorization)
    }

    fn parse_req(value: &str) -> HlsResult<Header> {
        let mut header = Header::default();
        let value = value.replace("\r\n", "\n");
        for (index, line) in value.split("\n").enumerate() {
            if line.is_empty() { continue; }
            if index == 0 {
                let mut items = line.split(" ");
                header.method = Method::try_from(items.next().unwrap_or("GET")).unwrap_or(Method::GET);
                header.set_uri(Uri::try_from(items.next().unwrap_or(""))?);
                header.alpn = ALPN::from_slice(items.collect::<Vec<_>>().join(" ").to_lowercase().as_bytes());
                continue;
            }
            let pos = line.find(':').unwrap_or(line.len());
            let name = &line[..pos];
            let value = if pos == line.len() { "" } else { line[pos + 1..].trim() };
            header.insert(name, value)?;
        }
        Ok(header)
    }

    fn parse_res(value: &str) -> HlsResult<Header> {
        let mut header = Header::default();
        let value = value.replace("\r\n", "\n");
        for (index, line) in value.split("\n").enumerate() {
            if line.is_empty() { continue; }
            if index == 0 {
                let mut items = line.split(" ");
                header.alpn = ALPN::from_slice(items.next().unwrap_or("").to_lowercase().as_bytes());
                let status = items.next().unwrap_or("100").parse().unwrap_or(100);
                header.status = HttpStatus::new(status);
                continue;
            }
            let pos = line.find(':').unwrap_or(line.len());
            let name = &line[..pos];
            let value = if pos == line.len() { "" } else { line[pos + 1..].trim() };
            header.insert(name, value)?;
        }
        Ok(header)
    }

    pub fn push_pack_item(&mut self, item: &PackItem) -> HlsResult<()> {
        self.insert(item.name(), item.value())?;
        match item.name() {
            ":method" => self.method = Method::try_from(item.value().to_uppercase())?,
            ":path" => self.uri = Uri::try_from(item.value())?,
            ":status" => self.status = HttpStatus::new(item.value().parse::<u16>()?),
            _ => {}
        }
        Ok(())
    }

    pub fn parse_h2(packs: Vec<PackItem>) -> HlsResult<Header> {
        let mut header = Header {
            alpn: ALPN::HTTP20,
            ..Header::default()
        };
        for pack in packs {
            header.push_pack_item(&pack)?
        }
        Ok(header)
    }

    pub fn status(&self) -> &HttpStatus {
        &self.status
    }

    pub fn keys(&self) -> &Vec<HeaderKey> { &self.keys }

    pub(crate) fn init_by_alpn(&mut self, alpn: ALPN) {
        if alpn == self.alpn { return; }
        self.alpn = alpn;
        let keys = match &self.alpn {
            #[cfg(feature = "quic")]
            h3 if h3 == ALPN::HTTP30 => Header::new_req_h3().keys,
            h2 if h2 == ALPN::HTTP20 => Header::new_req_h2().keys,
            _ => Header::new_req_h1().keys
        };
        let keys = mem::replace(&mut self.keys, keys);
        for ok in keys {
            let nk = self.keys.iter_mut().find(|x| x.name_lower() == ok.name_lower());
            match nk {
                None => self.keys.push(ok),
                Some(nk) => nk.set_value(ok.into_value())
            }
        }
    }

    pub fn set_by_json(&mut self, headers: JsonValue) -> HlsResult<()> {
        for (k, v) in headers.into_entries() {
            match k.as_str() {
                "cookie" | "Cookie" => self.set_cookie(v.dump())?,
                _ => self.insert(k, v.dump())?
            }
        }
        Ok(())
    }

    fn as_h1_reader<'a>(&'a self, params: HeaderParam<'a>, ct: &'a ContentType) -> H1HeaderReader<'a> {
        let mut reader = RefReader::default();
        reader.add_str(self.method.spec());
        reader.add_str(" ");
        if params.url.uri().is_empty() {
            reader.add_str("/")
        } else {
            reader.add_str(params.url.uri().path());
        }
        if !params.url.uri().params().is_empty() { reader.add_str("?") };
        for (i, param) in params.url.uri().params().iter().enumerate() {
            reader.add_str(param.name());
            if param.equal_sign() { reader.add_str("="); }
            reader.add_str(param.value_raw());
            if i != params.url.uri().params().len() - 1 { reader.add_str("&") }
        }
        reader.add_str(" ");
        reader.add_str("HTTP/1.1");
        reader.add_str("\r\n");
        for key in self.keys.iter() {
            if H1HeaderReader::skip_h1_key(key, &params.body_len, ct) { continue; }

            reader.add_str(key.name());
            reader.add_str(": ");
            match key.name() {
                "host" | "Host" => {
                    reader.add_str(params.url.sni());
                    if params.url.addr().port() != 80 && params.url.addr().port() != 443 {
                        reader.add_str(":");
                        reader.add_string(params.url.addr().port().to_string());
                    }
                }
                "content-length" | "Content-Length" => reader.add_string(params.body_len.to_string()),
                "content-type" | "Content-Type" => match ct.spec() {
                    Cow::Borrowed(b) => reader.add_str(b),
                    Cow::Owned(o) => reader.add_string(o),
                }
                "cookie" | "Cookie" => {
                    if let Some(cookies) = key.cookies() {
                        for (index, cookie) in cookies.iter().enumerate() {
                            reader.add_str(cookie.name());
                            if cookie.equal_sign() { reader.add_str("="); }
                            reader.add_str(cookie.value());
                            if index != key.cookies().unwrap_or(&[]).len() - 1 { reader.add_str("; ") }
                        }
                    }
                }
                _ => match key.value().as_string() {
                    None => reader.add_string(key.value().to_string()),
                    Some(v) => reader.add_str(v),
                }
            }
            reader.add_str("\r\n");
        }
        reader.add_str("\r\n");
        H1HeaderReader {
            reader,
            pos: 0,
            wrote: false,
        }
    }

    fn gen_frame_keys<'a>(&'a self, param: &HeaderParam<'a>, ct: &'a ContentType) -> Vec<(StrCow<'a>, StrCow<'a>)> {
        let mut keys = vec![];
        keys.push((StrCow::Borrowed(":method"), StrCow::Borrowed(self.method.spec())));
        if param.url.addr().port() == 443 || param.url.addr().port() == 80 {
            keys.push((StrCow::Borrowed(":authority"), StrCow::Borrowed(param.url.sni())));
        } else {
            keys.push((StrCow::Borrowed(":authority"), StrCow::Owned(format!("{}:{}", param.url.sni(), param.url.addr().port()))));
        }
        keys.push((StrCow::Borrowed(":scheme"), StrCow::Borrowed(param.url.scheme().spec())));
        let uri = if param.url.uri().is_empty() { StrCow::Borrowed("/") } else { StrCow::Owned(param.url.uri().to_string()) };
        for key in self.keys.iter() {
            if H2HeaderReader::skip_h2_key(key, ct, param.body_len, &self.method) { continue; }
            let name = key.name_lower();
            if name == "content-type" {
                match ct.spec() {
                    Cow::Borrowed(b) => keys.push((StrCow::Owned(name), StrCow::Borrowed(b))),
                    Cow::Owned(o) => keys.push((StrCow::Owned(name), StrCow::Owned(o))),
                }
                continue;
            } else if name == "content-length" {
                keys.push((StrCow::Owned(name), StrCow::Owned(param.body_len.to_string())));
                continue;
            }
            match key.value() {
                HeaderValue::Cookies(cookies) => for cookie in cookies.as_req(param.url.sni(), uri.as_ref()) {
                    keys.push((StrCow::Owned(name.clone()), StrCow::Owned(cookie.as_req())));
                }
                _ => keys.push((StrCow::Owned(name), StrCow::Owned(key.value().to_string()))),
            }
        }
        keys.insert(3, (StrCow::Borrowed(":path"), uri));
        keys
    }

    fn as_h2_reader<'a>(&'a self, param: HeaderParam<'a>, ct: &'a ContentType) -> HlsResult<H2HeaderReader<'a>> {
        Ok(H2HeaderReader {
            keys: self.gen_frame_keys(&param, ct),
            encoder: param.hpack_encoder.ok_or("missing hpack encoder")?,
            wrote: false,
            pos: 0,
            body_len: param.body_len,
            stream_identifier: param.h_sid,
            weight: param.weight,
            priority: param.priority,
        })
    }

    #[cfg(feature = "quic")]
    fn as_h3_reader<'a>(&'a self, param: HeaderParam<'a>, ct: &'a ContentType) -> HlsResult<H3HeaderReader<'a>> {
        Ok(H3HeaderReader {
            keys: self.gen_frame_keys(&param, ct),
            encoder: param.qpack_encoder.ok_or("missing qpack encoder")?,
            // priority: self.keys.iter().find(|x| x.name() == "priority")
            //     .and_then(|x| x.value().as_string()).unwrap_or(""),
            wrote: false,
            sid: param.q_sid,
        })
    }

    pub(crate) fn as_reader<'a>(&'a self, param: HeaderParam<'a>, ct: &'a ContentType) -> HlsResult<HeaderReader<'a>> {
        Ok(match &self.alpn {
            h2 if h2 == ALPN::HTTP20 => HeaderReader::H2(self.as_h2_reader(param, ct)?),
            #[cfg(feature = "quic")]
            h3 if h3 == ALPN::HTTP30 => HeaderReader::H3(self.as_h3_reader(param, ct)?),
            _ => HeaderReader::H1(self.as_h1_reader(param, ct))
        })
    }

    pub(crate) fn add_key(&mut self, key: HeaderKey) {
        let header = self.keys.iter_mut().find(|x| x.name().eq_ignore_ascii_case(key.name()));
        match header {
            None => self.keys.push(key),
            Some(hdr) => {
                let value = key.into_value();
                match value {
                    HeaderValue::Cookies(cookies) => for cookie in cookies.into_inner() {
                        hdr.value_mut().add_cookie(cookie);
                    }
                    _ => hdr.set_value(value),
                }
            }
        }
    }

    pub(crate) fn set_by_keys(&mut self, keys: Vec<HeaderKey>, keep_sort: bool) -> Result<(), HeaderError> {
        let mut have_host = false;
        let mut have_content_type = false;
        let mut have_content_length = false;
        if keep_sort { self.keys.clear(); }
        for key in keys {
            if key.name().eq_ignore_ascii_case("host") { have_host = true; }
            if key.name().eq_ignore_ascii_case("content-type") { have_content_type = true; }
            if key.name().eq_ignore_ascii_case("content-length") { have_content_length = true; }
            self.add_key(key);
        }
        if keep_sort {
            if !have_host { return Err(HeaderError::MissingBasicKey("Host")); }
            if !have_content_type { return Err(HeaderError::MissingBasicKey("Content-Type")); }
            if !have_content_length { return Err(HeaderError::MissingBasicKey("Content-Length")); }
        }
        Ok(())
    }
}

impl TryFrom<String> for Header {
    type Error = HlsError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Header::try_from(value.as_str())
    }
}

impl TryFrom<&str> for Header {
    type Error = HlsError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_uppercase().starts_with("HTTP/1") {
            true => Header::parse_res(value),
            false => Header::parse_req(value),
        }
    }
}

impl Display for Header {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut write_header = false;
        match self.status {
            HttpStatus::None => {
                if self.alpn == ALPN::HTTP11 {
                    write!(f, "{} {} {}", self.method, self.uri, self.alpn)?;
                    write_header = true;
                }
            }
            _ => {
                if self.alpn == ALPN::HTTP11 {
                    write!(f, "{} {} {}", self.alpn, self.status.code(), self.status.spec())?;
                    write_header = true;
                }
            }
        }
        if !self.keys.is_empty() && write_header { write!(f, "\r\n")?; }
        for (i, key) in self.keys.iter().enumerate() {
            if key.value().is_empty() && key.is_reserved() { continue; }
            match key.name_lower().as_str() {
                "set-cookie" => for (i, cookie) in key.cookies().unwrap_or(&[]).iter().enumerate() {
                    write!(f, "{}: {}", key.name(), cookie.as_res())?;
                    if key.cookies().map(|x| x.len()).unwrap_or(0) != i + 1 { write!(f, "\r\n")?; }
                }
                _ => write!(f, "{}: {}", key.name(), key.value())?
            };
            if self.keys.len() != i + 1 { write!(f, "\r\n")? }
        }
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use crate::{json, Header};
    use reqtls::ALPN;

    #[test]
    fn test_header_order() {
        let headers = json::object! {
            "Connection": "keep-alive",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 MicroMessenger/7.0.20.1781(0x6700143B) NetType/WIFI MiniProgramEnv/Windows WindowsWechat/WMPF WindowsWechat(0x63090a13) UnifiedPCWindowsWechat(0xf254181b) XWEB/20001",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "xweb_xhr": "1",
            "Host-Ip": "",
            "Sec-Fetch-Site": "cross-site",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Referer": "https://xxxxx/wx9e2927dd595b0473/99/page-frame.html",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "zh-CN,zh;q=0.9",
        };
        let mut header = Header::default();
        header.set_by_json(headers.clone()).unwrap();
        header.insert("host", "xxxxx").unwrap();
        header.insert("content-length", "748").unwrap();
        header.insert("cookie", "wzws_sid=xxx").unwrap();
        header.insert("Authorization", "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.xxx.hKMvQpkzp5YpEN_B2fjhIQ1VHyi6dkwhtH8pjrDNJWM").unwrap();
        assert_eq!(header.to_string(), r#"Connection: keep-alive
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 MicroMessenger/7.0.20.1781(0x6700143B) NetType/WIFI MiniProgramEnv/Windows WindowsWechat/WMPF WindowsWechat(0x63090a13) UnifiedPCWindowsWechat(0xf254181b) XWEB/20001
Accept: application/json
Content-Type: application/json
xweb_xhr: 1
Host-Ip:
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://xxxxx/wx9e2927dd595b0473/99/page-frame.html
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
host: xxxxx
content-length: 748
cookie: wzws_sid=xxx
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.xxx.hKMvQpkzp5YpEN_B2fjhIQ1VHyi6dkwhtH8pjrDNJWM"#
            .replace("\n", "\r\n").replace("Host-Ip:", "Host-Ip: "));

        let mut header = Header::default();
        header.init_by_alpn(ALPN::HTTP11);
        header.set_by_json(headers).unwrap();
        header.insert("host", "xxxxx").unwrap();
        header.insert("content-length", "748").unwrap();
        header.insert("cookie", "wzws_sid=xxx").unwrap();
        header.insert("Authorization", "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.xxx.hKMvQpkzp5YpEN_B2fjhIQ1VHyi6dkwhtH8pjrDNJWM").unwrap();
        assert_eq!(header.to_string(), r#"GET  HTTP/1.1
Host: xxxxx
Connection: keep-alive
Content-Length: 748
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.xxx.hKMvQpkzp5YpEN_B2fjhIQ1VHyi6dkwhtH8pjrDNJWM
Content-Type: application/json
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 MicroMessenger/7.0.20.1781(0x6700143B) NetType/WIFI MiniProgramEnv/Windows WindowsWechat/WMPF WindowsWechat(0x63090a13) UnifiedPCWindowsWechat(0xf254181b) XWEB/20001
Accept: application/json
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://xxxxx/wx9e2927dd595b0473/99/page-frame.html
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: wzws_sid=xxx
xweb_xhr: 1
Host-Ip: "#.replace("\n", "\r\n"))
    }
}


