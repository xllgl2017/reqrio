use std::borrow::Cow;
use super::value::HeaderValue;
use crate::packet::http::cookie::Cookie;

#[derive(Clone)]
pub struct HeaderItem {
    name: Cow<'static, str>,
    value: HeaderValue,
    reserved: bool,
}

impl HeaderItem {
    pub const fn none() -> HeaderItem {
        HeaderItem {
            name: Cow::Borrowed(""),
            value: HeaderValue::String(Cow::Borrowed("")),
            reserved: false,
        }
    }

    pub fn new(name: impl Into<String>, value: impl Into<HeaderValue>) -> HeaderItem {
        HeaderItem {
            name: Cow::Owned(name.into()),
            value: value.into(),
            reserved: false,
        }
    }

    #[cfg(feature = "export")]
    pub(crate) fn with_reserved(mut self, reserved: bool) -> HeaderItem {
        self.reserved = reserved;
        self
    }

    /// Reserved key. When the key value is empty, it will not be sent; use `new` to send it.
    pub const fn new_reserved(name: &'static str, value: HeaderValue) -> HeaderItem {
        HeaderItem {
            name: Cow::Borrowed(name),
            value,
            reserved: true,
        }
    }

    pub fn cookies(&self) -> Option<&[Cookie]> {
        match self.value {
            HeaderValue::Cookies(ref cookies) => Some(cookies.inner()),
            _ => None,
        }
    }

    pub fn cookies_mut(&mut self) -> Option<&mut [Cookie]> {
        match self.value {
            HeaderValue::Cookies(ref mut cookies) => Some(cookies.inner_mut()),
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

    pub(crate) fn is_reserved(&self) -> bool { self.reserved }
}