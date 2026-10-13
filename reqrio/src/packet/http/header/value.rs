use std::borrow::Cow;
use std::fmt::Display;
use crate::cookie::CookieManager;
use crate::packet::http::content_type::ContentType;
use crate::packet::http::cookie::Cookie;

#[derive(Clone)]
pub enum HeaderValue {
    String(Cow<'static, str>),
    Number(usize),
    ContextType(ContentType),
    Cookies(CookieManager),
}

impl HeaderValue {
    pub const fn new_str(value: &'static str) -> HeaderValue {
        HeaderValue::String(Cow::Borrowed(value))
    }

    pub fn add_cookie(&mut self, cookie: Cookie) {
        if let HeaderValue::Cookies(cookies) = self {
            cookies.push(cookie);
        } else { *self = HeaderValue::Cookies(CookieManager::new(vec![cookie])) }
    }

    pub fn as_string(&self) -> Option<&str> {
        match self {
            HeaderValue::String(v) => Some(v),
            _ => None
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            HeaderValue::String(v) => v.is_empty(),
            HeaderValue::Number(v) => *v == 0,
            HeaderValue::ContextType(_) => false,
            HeaderValue::Cookies(v) => v.is_empty(),
        }
    }

    #[deprecated]
    pub fn may_len(&self) -> usize {
        match self {
            HeaderValue::String(v) => v.len(),
            HeaderValue::Number(_) => 10,
            HeaderValue::ContextType(_) => 64,
            HeaderValue::Cookies(cookies) => cookies.req_may_len()
        }
    }
}

impl Display for HeaderValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HeaderValue::String(v) => write!(f, "{}", v),
            HeaderValue::Number(v) => write!(f, "{}", v),
            HeaderValue::ContextType(v) => write!(f, "{}", v.spec()),
            HeaderValue::Cookies(v) => write!(f, "{}", v)
        }
    }
}

impl From<String> for HeaderValue {
    fn from(value: String) -> Self {
        HeaderValue::String(Cow::Owned(value))
    }
}

impl From<&str> for HeaderValue {
    fn from(value: &str) -> Self {
        HeaderValue::String(Cow::Owned(value.to_string()))
    }
}


impl From<usize> for HeaderValue {
    fn from(value: usize) -> Self {
        HeaderValue::Number(value)
    }
}

impl From<ContentType> for HeaderValue {
    fn from(value: ContentType) -> Self {
        HeaderValue::ContextType(value)
    }
}