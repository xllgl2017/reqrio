use crate::packet::http::cookie::Cookie;
use super::value::HeaderValue;

#[derive(Clone)]
pub struct HeaderKey {
    name: String,
    value: HeaderValue,
}

impl HeaderKey {
    pub fn none() -> HeaderKey {
        HeaderKey {
            name: "".to_string(),
            value: HeaderValue::String("".to_string()),
        }
    }
    pub fn new(name: impl ToString, value: HeaderValue) -> HeaderKey {
        HeaderKey {
            name: name.to_string(),
            value,
        }
    }

    pub fn cookies(&self) -> Option<&Vec<Cookie>> {
        match self.value {
            HeaderValue::Cookies(ref cookies) => Some(cookies),
            _ => None,
        }
    }

    pub fn name(&self) -> &str { &self.name }

    pub fn value(&self) -> &HeaderValue { &self.value }

    pub fn value_mut(&mut self) -> &mut HeaderValue { &mut self.value }

    pub fn set_value(&mut self, value: HeaderValue) {
        self.value = value;
    }

    pub fn into_value(self) -> HeaderValue { self.value }
}