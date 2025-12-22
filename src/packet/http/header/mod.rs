use std::fmt::Display;
use json::JsonValue;
pub use key::HeaderKey;
pub use value::HeaderValue;
pub use method::Method;
pub use status::HttpStatus;
use crate::coder::HPack;
use crate::error::{HlsError, HlsResult};

use super::content_type::ContentType;
use super::cookie::Cookie;
use super::super::super::url::Uri;

mod value;
mod key;
mod method;
mod status;

pub struct Header {
    method: Method,
    agreement: String,
    uri: Uri,
    status: HttpStatus,
    keys: Vec<HeaderKey>,
}

impl Header {
    pub fn new_res() -> Self {
        Self {
            method: Method::GET,
            agreement: "".to_string(),
            uri: Uri::new(),
            status: HttpStatus::None,
            keys: vec![],
        }
    }


    pub fn new_req_h2() -> Self {
        let mut res = Header::new_res();
        res.keys = vec![
            //h2 order
            HeaderKey::new("cache-control", HeaderValue::String("".to_string())),
            HeaderKey::new("sec-ch-ua", HeaderValue::String("".to_string())),
            HeaderKey::new("sec-ch-ua-mobile", HeaderValue::String("".to_string())),
            HeaderKey::new("sec-ch-ua-platform", HeaderValue::String("".to_string())),
            HeaderKey::new("upgrade-insecure-requests", HeaderValue::Bool(true)),
            HeaderKey::new("user-agent", HeaderValue::String("".to_string())),
            HeaderKey::new("accept", HeaderValue::String("".to_string())),
            HeaderKey::new("sec-fetch-site", HeaderValue::String("".to_string())),
            HeaderKey::new("sec-fetch-mode", HeaderValue::String("".to_string())),
            HeaderKey::new("sec-fetch-user", HeaderValue::String("".to_string())),
            HeaderKey::new("sec-fetch-dest", HeaderValue::String("".to_string())),
            HeaderKey::new("referer", HeaderValue::String("".to_string())),
            HeaderKey::new("accept-encoding", HeaderValue::String("".to_string())),
            HeaderKey::new("accept-language", HeaderValue::String("".to_string())),
            HeaderKey::new("cookie", HeaderValue::Cookies(vec![])),
            HeaderKey::new("priority", HeaderValue::String("".to_string())),
            //unknown or http
            // HeaderKey::new("host", HeaderValue::String("".to_string())),
            HeaderKey::new("origin", HeaderValue::String("".to_string())),
            HeaderKey::new("content-encoding", HeaderValue::String("".to_string())),
            // HeaderKey::new("content-length", HeaderValue::Number(0)),
            HeaderKey::new("content-type", HeaderValue::String("".to_string())),
            // HeaderKey::new("connection", HeaderValue::String("".to_string())),
            HeaderKey::new("authorization", HeaderValue::String("".to_string())),
            HeaderKey::new("content-type", HeaderValue::String("".to_string())),
        ];
        res
    }

    pub fn new_req_h1() -> Self {
        let mut res = Header::new_res();
        res.keys = vec![
            HeaderKey::new("accept", HeaderValue::String("".to_string())),
            HeaderKey::new("accept-encoding", HeaderValue::String("".to_string())),
            HeaderKey::new("accept-language", HeaderValue::String("".to_string())),
            HeaderKey::new("cache-control", HeaderValue::String("".to_string())),
            HeaderKey::new("connection", HeaderValue::String("".to_string())),
            HeaderKey::new("cookie", HeaderValue::Cookies(vec![])),
            HeaderKey::new("host", HeaderValue::String("".to_string())),
            // HeaderKey::new("origin", HeaderValue::String("".to_string())),
            HeaderKey::new("pragma", HeaderValue::String("".to_string())),
            HeaderKey::new("referer", HeaderValue::String("".to_string())),
            HeaderKey::new("sec-fetch-dest", HeaderValue::String("".to_string())),
            HeaderKey::new("sec-fetch-mode", HeaderValue::String("".to_string())),
            HeaderKey::new("sec-fetch-site", HeaderValue::String("".to_string())),
            HeaderKey::new("sec-fetch-user", HeaderValue::String("".to_string())),
            HeaderKey::new("upgrade-insecure-requests", HeaderValue::Bool(true)),
            HeaderKey::new("user-agent", HeaderValue::String("".to_string())),
            HeaderKey::new("sec-ch-ua", HeaderValue::String("".to_string())),
            HeaderKey::new("sec-ch-ua-mobile", HeaderValue::String("".to_string())),
            HeaderKey::new("sec-ch-ua-platform", HeaderValue::String("".to_string())),
            HeaderKey::new("content-length", HeaderValue::Number(0)),
        ];
        res
    }

    pub fn to_req_cookie_str(&self) -> String {
        let header = self.keys.iter().find(|x| x.name() == "cookie");
        if let Some(header) = header && let Some(cookie) = header.cookies() {
            cookie.iter().map(|cookie| cookie.as_req()).collect::<Vec<_>>().join("; ")
        } else {
            "".to_string()
        }
    }

    pub fn as_raw(&mut self, body_len: usize) -> HlsResult<Vec<String>> {
        self.set_content_length(body_len)?;
        Ok(self.raw())
    }

    fn raw(&self) -> Vec<String> {
        let mut res = vec![];
        for key in &self.keys {
            if key.value().to_string() == "" { continue; }
            match key.name() {
                "set-cookie" => for cookie in key.cookies().unwrap_or(&vec![]) {
                    res.push(format!("set-cookie: {}", cookie.as_res()));
                },
                _ => res.push(format!("{}: {}", key.name(), key.value().to_string()))
            }
        }
        res
    }


    pub fn get(&self, name: &str) -> Option<&HeaderValue> {
        let k = name.to_lowercase();
        let header = self.keys.iter().find(|x| x.name() == k)?;
        Some(header.value())
    }

    pub fn remove(&mut self, name: impl AsRef<str>) -> Option<HeaderValue> {
        let lower = name.as_ref().to_lowercase();
        let pos = self.keys.iter().position(|x| x.name() == lower)?;
        Some(self.keys.remove(pos).into_value())
    }

    pub fn as_h2c(&self) -> HlsResult<Vec<HeaderKey>> {
        let mut res = self.keys.clone();
        res.insert(0, HeaderKey::new(":method", HeaderValue::String(self.method.to_string())));
        let res = res.into_iter().filter_map(|x| {
            if x.value().to_string() == "" {
                None
            } else if x.name() == "connection" || x.name() == "host" || x.name() == "content-length" {
                None
            } else {
                Some(x)
            }
        }).collect();
        Ok(res)
    }

    pub fn add_cookie(&mut self, cookie: Cookie){
        match self.keys.iter_mut().find(|x| x.name() == "cookie") {
            None => self.keys.push(HeaderKey::new("cookie",HeaderValue::Cookies(vec![cookie]))),
            Some(header) => header.value_mut().add_cookie(cookie)
        }
    }

    pub fn set_cookies(&mut self, ck: Vec<Cookie>) {
        let header = self.keys.iter_mut().find(|x| x.name() == "cookie");
        if let Some(header) = header {
            header.set_value(HeaderValue::Cookies(ck));
        } else {
            self.keys.push(HeaderKey::new("cookie", HeaderValue::Cookies(ck)));
        }
    }

    pub fn set_cookie(&mut self, ck: impl AsRef<str>) -> HlsResult<()> {
        let cookies = Cookie::from_req(ck.as_ref())?;
        self.set_cookies(cookies);
        Ok(())
    }

    pub fn insert(&mut self, k: impl AsRef<str>, v: impl ToString) -> HlsResult<()> {
        let k = k.as_ref().to_lowercase().replace("contentlength", "content-length")
            .replace("contenttype", "ccontent-type");
        let header = self.keys.iter_mut().find(|x| x.name() == k);
        if let Some(header) = header {
            match header.name() {
                "cookie" => self.set_cookie(v.to_string())?,
                "content-length" => header.set_value(HeaderValue::Number(v.to_string().parse()?)),
                "content-type" => header.set_value(HeaderValue::ContextType(ContentType::try_from(&v.to_string())?)),
                "upgrade-insecure-requests" => header.set_value(HeaderValue::Bool(v.to_string() == "1")),
                "set-cookie" => header.value_mut().add_cookie(Cookie::from_res(v.to_string())?),
                _ => header.set_value(HeaderValue::String(v.to_string())),
            }
        } else {
            match k.as_ref() {
                "set-cookie" => {
                    let cookie = Cookie::from_res(v.to_string())?;
                    self.keys.push(HeaderKey::new("set-cookie", HeaderValue::Cookies(vec![cookie])));
                }
                "content-length" => self.keys.push(HeaderKey::new("content-length", HeaderValue::Number(v.to_string().parse()?))),
                _ => self.keys.push(HeaderKey::new(k, HeaderValue::String(v.to_string()))),
            }
        }
        Ok(())
    }

    pub fn set_user_agent(&mut self, user_agent: impl ToString) -> HlsResult<()> {
        self.insert("user-agent", user_agent)
    }

    pub fn user_agent(&self) -> Option<&str> {
        self.get("user-agent")?.as_string()
    }

    pub fn set_host(&mut self, host: impl ToString) -> HlsResult<()> {
        self.insert("host", host)
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

    pub fn set_accept(&mut self, accept: impl ToString) -> HlsResult<()> {
        self.insert("accept", accept)
    }

    pub fn set_content_length(&mut self, content_length: usize) -> HlsResult<()> {
        self.insert("content-length", content_length)
    }

    pub fn set_content_type(&mut self, content_type: ContentType) {
        let header = self.keys.iter_mut().find(|x| x.name() == "content-type");
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

    pub fn cookies(&self) -> Option<&Vec<Cookie>> {
        let header = self.keys.iter().find(|x| x.name() == "cookie" || x.name() == "set-cookie");
        header?.cookies()
    }

    pub fn method(&self) -> &Method { &self.method }

    pub fn agreement(&self) -> &str {
        &self.agreement
    }

    pub fn uri(&self) -> String {
        self.uri.to_string()
    }

    pub fn is_empty(&self) -> bool { self.agreement == "" }

    pub fn content_encoding(&self) -> Option<&str> {
        self.get("content-encoding")?.as_string()
    }

    pub fn set_method(&mut self, method: Method) { self.method = method; }

    pub fn set_uri(&mut self, uri: impl AsRef<str>) -> HlsResult<()> {
        let mut items = uri.as_ref().split("?");
        self.uri.set_uri(items.next().ok_or("invalid uri")?);
        self.uri.parse_param(items.next().unwrap_or(""))
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

    pub fn parse_req(mut value: String) -> HlsResult<Header> {
        let mut header = Header::new_res();
        value = value.replace("\r\n", "\n");
        for (index, line) in value.split("\n").enumerate() {
            if index == 0 {
                let mut items = line.split(" ");
                header.method = Method::try_from(items.next().unwrap_or("GET")).unwrap_or(Method::GET);
                let _ = header.set_uri(items.next().unwrap_or(""));
                header.agreement = items.collect::<Vec<_>>().join(" ").to_uppercase();
            }
            let mut items = line.split(": ");
            let name = items.next().unwrap_or("");
            let v = items.collect::<Vec<_>>().join(": ");
            header.insert(name, v)?;
        }
        Ok(header)
    }

    pub fn parse_res(mut value: String) -> HlsResult<Header> {
        let mut header = Header::new_res();
        value = value.replace("\r\n", "\n");
        for (index, line) in value.split("\n").enumerate() {
            if index == 0 {
                let mut items = line.split(" ");
                header.agreement = items.next().unwrap_or("").to_string();
                let status = items.next().unwrap_or("100").parse().unwrap_or(100);
                header.status = HttpStatus::try_from(status).unwrap_or(HttpStatus::Continue);
            }
            let mut items = line.split(": ");
            let name = items.next().unwrap_or("");
            let v = items.collect::<Vec<_>>().join(": ");
            header.insert(name, v)?;
        }
        Ok(header)
    }

    pub fn parse_h2(packs: Vec<HPack>) -> HlsResult<Header> {
        let mut header = Header::new_res();
        header.agreement = "HTTP/2.0".to_string();
        for pack in packs {
            // println!("{}", pack);
            match pack.name() {
                ":status" => header.status = HttpStatus::try_from(pack.value().parse::<i32>()?)?,
                _ => header.insert(pack.name(), pack.value())?,
            }
        }
        Ok(header)
    }

    pub fn status(&self) -> &HttpStatus {
        &self.status
    }
}

impl TryFrom<JsonValue> for Header {
    type Error = HlsError;
    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        let mut ss = Self::new_res();
        for (k, v) in value.entries() {
            ss.insert(k.to_string(), v.to_string())?;
        }
        Ok(ss)
    }
}

impl Display for Header {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let raw = match self.status {
            HttpStatus::None => {
                let mut raw = self.raw();
                raw.insert(0, format!("{} {} {}", self.method, self.uri, self.agreement));
                raw.push("".to_string());
                raw.push("".to_string());
                raw
            }
            _ => {
                if self.agreement.starts_with("HTTP/1") {
                    let mut raw = self.raw();
                    raw.insert(0, format!("{} {} {}", self.agreement, self.status.status_num(), self.status.to_string()));
                    raw.push("".to_string());
                    raw.push("".to_string());
                    raw
                } else {
                    let mut raw = vec![format!(":status: {}", self.status.status_num())];
                    self.keys.iter().for_each(|k| match k.value() {
                        HeaderValue::Cookies(cookies) => for cookie in cookies {
                            raw.push(format!("{}: {}", k.name(), cookie.as_res()));
                        },
                        _ => raw.push(format!("{}: {}", k.name(), k.value()))
                    });
                    raw
                }
            }
        };
        f.write_str(&raw.join("\r\n"))
    }
}