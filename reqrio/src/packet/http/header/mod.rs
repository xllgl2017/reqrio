use super::content_type::ContentType;
use super::cookie::Cookie;
use crate::cookie::CookieManager;
use crate::json::JsonValue;
use crate::*;
pub use error::HeaderError;
pub use key::HeaderItem;
pub use method::Method;
pub use status::HttpStatus;
use std::borrow::Cow;
use std::fmt::Display;
use std::mem;
pub use value::HeaderValue;
use std::ops::Deref;

mod value;
mod key;
mod method;
mod status;
mod error;

#[derive(Clone)]
pub struct Header {
    alpn: ALPN,
    inner: Vec<HeaderItem>,
}
impl Default for Header {
    fn default() -> Self {
        Header {
            alpn: ALPN::default(),
            inner: Vec::with_capacity(30 * size_of::<HeaderItem>()),
        }
    }
}

impl Deref for Header {
    type Target = Vec<HeaderItem>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Header {
    #[cfg(feature = "quic")]
    pub fn new_req_h3() -> Self {
        Header {
            alpn: ALPN::HTTP30,
            inner: vec![
                //h2 order
                HeaderItem::new_reserved(":method", HeaderValue::new_str("")),
                HeaderItem::new_reserved(":authority", HeaderValue::new_str("")),
                HeaderItem::new_reserved(":scheme", HeaderValue::new_str("")),
                HeaderItem::new_reserved(":path", HeaderValue::new_str("")),
                HeaderItem::new_reserved("origin", HeaderValue::new_str("")),
                HeaderItem::new_reserved("sec-ch-ua-platform", HeaderValue::new_str("")),
                HeaderItem::new_reserved("user-agent", HeaderValue::String(Cow::Owned(format!("reqrio/{}", env!("CARGO_PKG_VERSION"))))),
                HeaderItem::new_reserved("sec-ch-ua", HeaderValue::new_str("")),
                HeaderItem::new_reserved("sec-ch-ua-mobile", HeaderValue::new_str("")),
                HeaderItem::new_reserved("accept", HeaderValue::new_str("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")),
                HeaderItem::new_reserved("sec-fetch-site", HeaderValue::new_str("")),
                HeaderItem::new_reserved("sec-fetch-mode", HeaderValue::new_str("")),
                HeaderItem::new_reserved("sec-fetch-user", HeaderValue::new_str("")),
                HeaderItem::new_reserved("sec-fetch-dest", HeaderValue::new_str("")),
                HeaderItem::new_reserved("referer", HeaderValue::new_str("")),
                HeaderItem::new_reserved("accept-encoding", HeaderValue::new_str("gzip, deflate, br, zstd")),
                HeaderItem::new_reserved("accept-language", HeaderValue::new_str("zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6")),
                HeaderItem::new_reserved("priority", HeaderValue::new_str("")),


                //unknown or http
                HeaderItem::new_reserved("cache-control", HeaderValue::new_str("")),
                HeaderItem::new_reserved("sec-ch-ua-full-version", HeaderValue::new_str("")),
                HeaderItem::new_reserved("sec-ch-ua-arch", HeaderValue::new_str("")),
                HeaderItem::new_reserved("sec-ch-ua-platform-version", HeaderValue::new_str("")),
                HeaderItem::new_reserved("sec-ch-ua-model", HeaderValue::new_str("")),
                HeaderItem::new_reserved("sec-ch-ua-bitness", HeaderValue::new_str("")),
                HeaderItem::new_reserved("sec-ch-ua-full-version-list", HeaderValue::new_str("")),
                HeaderItem::new_reserved("upgrade-insecure-requests", HeaderValue::new_str("")),
                HeaderItem::new_reserved("sec-fetch-storage-access", HeaderValue::new_str("")),
                HeaderItem::new_reserved("cookie", HeaderValue::Cookies(CookieManager::new(vec![]))),
                HeaderItem::new_reserved("content-encoding", HeaderValue::new_str("")),
                HeaderItem::new_reserved("content-type", HeaderValue::new_str("")),
                HeaderItem::new_reserved("authorization", HeaderValue::new_str("")),
            ],
        }
    }

    pub fn new_req_h2() -> Self {
        Header {
            alpn: ALPN::HTTP20,
            inner: vec![
                //h2 order
                HeaderItem::new_reserved(":method", HeaderValue::new_str("")),
                HeaderItem::new_reserved(":authority", HeaderValue::new_str("")),
                HeaderItem::new_reserved(":scheme", HeaderValue::new_str("")),
                HeaderItem::new_reserved(":path", HeaderValue::new_str("")),
                HeaderItem::new_reserved("pragma", HeaderValue::new_str("")),
                HeaderItem::new_reserved("cache-control", HeaderValue::new_str("")),
                HeaderItem::new_reserved("ect", HeaderValue::new_str("")),
                HeaderItem::new_reserved("sec-ch-ua", HeaderValue::new_str("")),
                HeaderItem::new_reserved("sec-ch-ua-mobile", HeaderValue::new_str("")),
                HeaderItem::new_reserved("sec-ch-ua-full-version", HeaderValue::new_str("")),
                HeaderItem::new_reserved("sec-ch-ua-arch", HeaderValue::new_str("")),
                HeaderItem::new_reserved("sec-ch-ua-platform", HeaderValue::new_str("")),
                HeaderItem::new_reserved("sec-ch-ua-platform-version", HeaderValue::new_str("")),
                HeaderItem::new_reserved("sec-ch-ua-model", HeaderValue::new_str("")),
                HeaderItem::new_reserved("sec-ch-ua-bitness", HeaderValue::new_str("")),
                HeaderItem::new_reserved("sec-ch-ua-full-version-list", HeaderValue::new_str("")),
                HeaderItem::new_reserved("sec-ch-prefers-color-scheme", HeaderValue::new_str("")),
                HeaderItem::new_reserved("upgrade-insecure-requests", HeaderValue::new_str("")),
                HeaderItem::new_reserved("user-agent", HeaderValue::String(Cow::Owned(format!("reqrio/{}", env!("CARGO_PKG_VERSION"))))),
                HeaderItem::new_reserved("accept", HeaderValue::new_str("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")),
                HeaderItem::new_reserved("origin", HeaderValue::new_str("")),
                HeaderItem::new_reserved("sec-fetch-site", HeaderValue::new_str("")),
                HeaderItem::new_reserved("sec-fetch-mode", HeaderValue::new_str("")),
                HeaderItem::new_reserved("sec-fetch-user", HeaderValue::new_str("")),
                HeaderItem::new_reserved("sec-fetch-dest", HeaderValue::new_str("")),
                HeaderItem::new_reserved("sec-fetch-storage-access", HeaderValue::new_str("")),
                HeaderItem::new_reserved("referer", HeaderValue::new_str("")),
                HeaderItem::new_reserved("accept-encoding", HeaderValue::new_str("gzip, deflate, br, zstd")),
                HeaderItem::new_reserved("accept-language", HeaderValue::new_str("zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6")),
                HeaderItem::new_reserved("cookie", HeaderValue::Cookies(CookieManager::new(vec![]))),
                HeaderItem::new_reserved("priority", HeaderValue::new_str("")),
                //unknown or http
                HeaderItem::new_reserved("content-encoding", HeaderValue::new_str("")),
                HeaderItem::new_reserved("content-type", HeaderValue::new_str("")),
                HeaderItem::new_reserved("authorization", HeaderValue::new_str("")),
            ],
        }
    }

    pub fn new_req_h1() -> Self {
        Header {
            alpn: ALPN::HTTP11,
            inner: vec![
                HeaderItem::new_reserved("Host", HeaderValue::new_str("")),
                HeaderItem::new_reserved("Connection", HeaderValue::new_str("")),
                HeaderItem::new_reserved("Content-Length", HeaderValue::Number(0)),
                HeaderItem::new_reserved("Authorization", HeaderValue::new_str("")),
                HeaderItem::new_reserved("Content-Type", HeaderValue::new_str("")),
                HeaderItem::new_reserved("Cache-Control", HeaderValue::new_str("")),
                HeaderItem::new_reserved("sec-ch-ua", HeaderValue::new_str("")),
                HeaderItem::new_reserved("sec-ch-ua-mobile", HeaderValue::new_str("")),
                HeaderItem::new_reserved("sec-ch-ua-platform", HeaderValue::new_str("")),
                HeaderItem::new_reserved("Upgrade-Insecure-Requests", HeaderValue::new_str("")),
                HeaderItem::new_reserved("User-Agent", HeaderValue::String(Cow::Owned(format!("reqrio/{}", env!("CARGO_PKG_VERSION"))))),
                HeaderItem::new_reserved("Accept", HeaderValue::new_str("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")),
                HeaderItem::new_reserved("Sec-Fetch-Site", HeaderValue::new_str("")),
                HeaderItem::new_reserved("Sec-Fetch-Mode", HeaderValue::new_str("")),
                HeaderItem::new_reserved("Sec-Fetch-User", HeaderValue::new_str("")),
                HeaderItem::new_reserved("Sec-Fetch-Dest", HeaderValue::new_str("")),
                HeaderItem::new_reserved("Sec-Fetch-Storage-Access", HeaderValue::new_str("")),
                HeaderItem::new_reserved("Referer", HeaderValue::new_str("")),
                HeaderItem::new_reserved("Accept-Encoding", HeaderValue::new_str("gzip, deflate, br, zstd")),
                HeaderItem::new_reserved("Accept-Language", HeaderValue::new_str("zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6")),
                HeaderItem::new_reserved("Cookie", HeaderValue::Cookies(CookieManager::new(vec![]))),
                HeaderItem::new_reserved("Origin", HeaderValue::new_str("")),
            ],
        }
    }

    pub fn to_req_cookie_str(&self) -> String {
        let header = self.inner.iter().find(|x| x.name().eq_ignore_ascii_case("cookie"));
        if let Some(header) = header && let Some(cookie) = header.cookies() {
            cookie.iter().map(|cookie| cookie.as_req()).collect::<Vec<_>>().join("; ")
        } else {
            "".to_string()
        }
    }

    pub fn get(&self, name: impl AsRef<str>) -> Option<&HeaderValue> {
        let header = self.inner.iter().find(|x| x.name().eq_ignore_ascii_case(name.as_ref()))?;
        Some(header.value())
    }

    /// HPack table size
    ///
    /// on first header item
    pub fn update_table_size(&self) -> Option<usize> {
        let value = self.get("update-table-size")?;
        match value {
            HeaderValue::Number(len) => Some(*len),
            HeaderValue::String(len) => Some(len.parse().ok()?),
            _ => None
        }
    }

    ///获取值为str的item，非str，请使用get
    pub fn get_str(&self, name: impl AsRef<str>) -> Option<&str> {
        let header = self.inner.iter().find(|x| x.name().eq_ignore_ascii_case(name.as_ref()))?;
        header.value().as_string()
    }

    pub fn get_mut(&mut self, name: impl AsRef<str>) -> Option<&mut HeaderValue> {
        let header = self.inner.iter_mut().find(|x| x.name().eq_ignore_ascii_case(name.as_ref()))?;
        Some(header.value_mut())
    }

    pub fn remove(&mut self, name: impl AsRef<str>) -> Option<HeaderValue> {
        let pos = self.inner.iter().position(|x| x.name().eq_ignore_ascii_case(name.as_ref()))?;
        Some(self.inner.remove(pos).into_value())
    }

    pub fn add_cookie(&mut self, cookie: Cookie) {
        match self.inner.iter_mut().find(|x| x.name().eq_ignore_ascii_case("cookie")) {
            None => self.inner.push(HeaderItem::new("cookie", HeaderValue::Cookies(CookieManager::new(vec![cookie])))),
            Some(header) => header.value_mut().add_cookie(cookie)
        }
    }

    pub fn set_cookies(&mut self, ck: Vec<Cookie>) {
        let header = self.inner.iter_mut().find(|x| x.name().eq_ignore_ascii_case("cookie"));
        match header {
            None => self.inner.push(HeaderItem::new("cookie", HeaderValue::Cookies(CookieManager::new(ck)))),
            Some(header) => header.set_value(HeaderValue::Cookies(CookieManager::new(ck))),
        }
    }

    pub fn set_cookie(&mut self, ck: impl AsRef<str>) {
        let cookies = Cookie::from_req(ck.as_ref());
        self.set_cookies(cookies);
    }

    /// For cookies, use `set_cookie` or `add_cookie`.
    pub fn insert(&mut self, k: impl AsRef<str>, value: impl Into<HeaderValue>) {
        let value = value.into();
        let lower_key = k.as_ref().to_lowercase().replace("contentlength", "content-length")
            .replace("contenttype", "content-type");
        let value = match (lower_key.as_str(), value) {
            ("cookie", HeaderValue::Cookies(cookie)) => HeaderValue::Cookies(cookie),
            ("cookie", HeaderValue::String(value)) => {
                let cookies = Cookie::from_req(value);
                HeaderValue::Cookies(CookieManager::new(cookies))
            }
            ("cookie", _) => unreachable!(),
            ("content-length" | "contentlength", HeaderValue::Number(value)) => HeaderValue::Number(value),
            ("content-length" | "contentlength", HeaderValue::String(value)) => HeaderValue::Number(value.trim().parse().unwrap_or(0)),
            ("content-length" | "contentlength", _) => unreachable!(),
            ("content-type" | "contenttype", HeaderValue::ContextType(typ)) => HeaderValue::ContextType(typ),
            ("content-type" | "contenttype", HeaderValue::String(typ)) => HeaderValue::ContextType(ContentType::try_from(typ.as_ref())
                .unwrap_or_else(|_| ContentType::Custom(typ.to_string()))),
            ("content-type" | "contenttype", _) => unreachable!(),
            (_, value) => value,
        };
        let header = self.inner.iter_mut().find(|x| x.name().eq_ignore_ascii_case(&lower_key));
        match (lower_key.as_str(), header) {
            ("set-cookie", Some(header)) => {
                let cookie = Cookie::from_res(value.as_string().unwrap_or(""));
                header.value_mut().add_cookie(cookie);
            }
            ("set-cookie", None) => {
                let cookie = Cookie::from_res(value.as_string().unwrap_or(""));
                self.inner.push(HeaderItem::new(k.as_ref(), HeaderValue::Cookies(CookieManager::new(vec![cookie]))));
            }
            (_, Some(header)) => header.set_value(value),
            (_, None) => self.inner.push(HeaderItem::new(k.as_ref(), value)),
        }
    }

    pub fn set_user_agent(&mut self, user_agent: impl Into<HeaderValue>) {
        self.insert("user-agent", user_agent)
    }

    pub fn set_sec_ch_ua(&mut self, sec_ch_ua: impl Into<HeaderValue>) {
        self.insert("sec-ch-ua", sec_ch_ua)
    }

    pub fn sec_ch_ua(&self) -> Option<&str> {
        self.get("sec-ch-ua")?.as_string()
    }

    pub fn set_sec_ch_ua_mobile(&mut self, sec_ch_ua_mobile: impl Into<HeaderValue>) {
        self.insert("sec-ch-ua-mobile", sec_ch_ua_mobile)
    }

    pub fn sec_ch_ua_mobile(&self) -> Option<&str> {
        self.get("sec-ch-ua-mobile")?.as_string()
    }

    pub fn set_sec_ch_ua_platform(&mut self, sec_ch_ua_platform: impl Into<HeaderValue>) {
        self.insert("sec-ch-ua-platform", sec_ch_ua_platform)
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

    pub fn set_origin(&mut self, origin: impl Into<HeaderValue>) {
        self.insert("origin", origin)
    }

    pub fn set_referer(&mut self, referer: impl Into<HeaderValue>) {
        self.insert("referer", referer)
    }

    pub fn referer(&self) -> Option<&str> {
        self.get("referer")?.as_string()
    }

    pub fn set_accept(&mut self, accept: impl Into<HeaderValue>) {
        self.insert("accept", accept)
    }

    pub fn set_content_length(&mut self, content_length: impl Into<HeaderValue>) {
        self.insert("content-length", content_length)
    }

    pub fn max_table_size(&self) -> Option<usize> {
        if let HeaderValue::Number(size) = self.get("update-table-size")? {
            Some(*size)
        } else { None }
    }

    pub fn set_content_type(&mut self, content_type: ContentType) {
        match self.get_mut("content-type") {
            None => self.inner.push(HeaderItem::new("content-type", content_type)),
            Some(value) => *value = HeaderValue::ContextType(content_type)
        }
    }

    pub fn set_connection(&mut self, connection: impl Into<HeaderValue>) {
        self.insert("connection", connection)
    }

    pub fn content_length(&self) -> Option<usize> {
        let value = self.get("content-length")?;
        match value {
            HeaderValue::Number(len) => Some(*len),
            HeaderValue::String(len) => Some(len.parse().ok()?),
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
        let header = self.inner.iter().find(|x|
            x.name().eq_ignore_ascii_case("cookie")
                || x.name().eq_ignore_ascii_case("set-cookie")
        );
        header?.cookies()
    }

    pub fn cookies_mut(&mut self) -> Option<&mut [Cookie]> {
        let header = self.inner.iter_mut().find(|x|
            x.name().eq_ignore_ascii_case("cookie")
                || x.name().eq_ignore_ascii_case("set-cookie")
        );
        header?.cookies_mut()
    }

    pub fn alpn(&self) -> &ALPN { &self.alpn }

    pub fn content_encoding(&self) -> Option<&str> {
        self.get("content-encoding")?.as_string()
    }

    pub fn set_content_encoding(&mut self, encoding: impl Into<HeaderValue>) {
        self.insert("content-encoding", encoding)
    }

    pub fn accept_encoding(&self) -> Option<&str> {
        self.get("accept-encoding")?.as_string()
    }

    pub fn location(&self) -> Option<&str> {
        self.get("location")?.as_string()
    }

    pub fn authorization(&self) -> Option<&str> {
        self.get("authorization")?.as_string()
    }

    pub fn set_authorization(&mut self, authorization: impl Into<HeaderValue>) {
        self.insert("authorization", authorization)
    }

    pub fn keys(&self) -> &Vec<HeaderItem> { &self.inner }

    pub(crate) fn init_by_alpn(&mut self, alpn: ALPN) {
        if alpn == self.alpn { return; }
        self.alpn = alpn;
        let keys = match &self.alpn {
            #[cfg(feature = "quic")]
            h3 if h3 == ALPN::HTTP30 => Header::new_req_h3().inner,
            h2 if h2 == ALPN::HTTP20 => Header::new_req_h2().inner,
            _ => Header::new_req_h1().inner
        };
        let keys = mem::replace(&mut self.inner, keys);
        for ok in keys {
            let nk = self.inner.iter_mut().find(|x| x.name().eq_ignore_ascii_case(ok.name()));
            match nk {
                None => self.inner.push(ok),
                Some(nk) => nk.set_value(ok.into_value())
            }
        }
    }

    pub fn set_by_json(&mut self, headers: JsonValue) {
        for (k, v) in headers.into_entries() {
            match k.as_str() {
                "cookie" | "Cookie" => self.set_cookie(v.dump()),
                _ => self.insert(k, v.dump())
            }
        }
    }

    pub(crate) fn add_item(&mut self, key: HeaderItem) {
        let header = self.inner.iter_mut().find(|x| x.name().eq_ignore_ascii_case(key.name()));
        match header {
            None => self.inner.push(key),
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

    pub(crate) fn set_by_keys(&mut self, keys: Vec<HeaderItem>, keep_sort: bool) -> Result<(), HeaderError> {
        let mut have_host = false;
        let mut have_content_type = false;
        let mut have_content_length = false;
        if keep_sort { self.inner.clear(); }
        for key in keys {
            if key.name().eq_ignore_ascii_case("host") { have_host = true; }
            if key.name().eq_ignore_ascii_case("content-type") { have_content_type = true; }
            if key.name().eq_ignore_ascii_case("content-length") { have_content_length = true; }
            self.add_item(key);
        }
        if keep_sort {
            if !have_host { return Err(HeaderError::MissingBasicKey("Host")); }
            if !have_content_type { return Err(HeaderError::MissingBasicKey("Content-Type")); }
            if !have_content_length { return Err(HeaderError::MissingBasicKey("Content-Length")); }
        }
        Ok(())
    }
}

impl Display for Header {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, key) in self.inner.iter().enumerate() {
            if key.value().is_empty() && key.is_reserved() { continue; }
            match key.name() {
                "encoded-head" | "update-table-size" => write!(f, "[{}: {}]", key.name(), key.value())?,
                "set-cookie" | "Set-Cookie" => for (i, cookie) in key.cookies().unwrap_or(&[]).iter().enumerate() {
                    write!(f, "{}: {}", key.name(), cookie.as_res())?;
                    if key.cookies().map(|x| x.len()).unwrap_or(0) != i + 1 { write!(f, "\r\n")?; }
                }
                _ => write!(f, "{}: {}", key.name(), key.value())?
            };
            if self.inner.len() != i + 1 { write!(f, "\r\n")? }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{Header, json};
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
        header.set_by_json(headers.clone());
        header.insert("host", "xxxxx");
        header.insert("content-length", "748");
        header.insert("cookie", "wzws_sid=xxx");
        header.insert("Authorization", "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.xxx.hKMvQpkzp5YpEN_B2fjhIQ1VHyi6dkwhtH8pjrDNJWM");
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
        header.set_by_json(headers);
        header.insert("host", "xxxxx");
        header.insert("content-length", "748");
        header.insert("cookie", "wzws_sid=xxx");
        header.insert("Authorization", "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.xxx.hKMvQpkzp5YpEN_B2fjhIQ1VHyi6dkwhtH8pjrDNJWM");
        assert_eq!(header.to_string(), r#"Host: xxxxx
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


