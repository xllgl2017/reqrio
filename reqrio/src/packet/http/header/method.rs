use std::fmt::{Display, Formatter};
use crate::error::HlsError;

pub enum Method {
    GET,
    POST,
    OPTIONS,
    HEAD,
    PUT,
    DELETE,
    CONNECT,
    TRACH,
}

impl Display for Method {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Method::GET => f.write_str("GET"),
            Method::POST => f.write_str("POST"),
            Method::OPTIONS => f.write_str("OPTIONS"),
            Method::HEAD => f.write_str("HEAD"),
            Method::PUT => f.write_str("PUT"),
            Method::DELETE => f.write_str("DELETE"),
            Method::CONNECT => f.write_str("CONNECT"),
            Method::TRACH => f.write_str("TRACE"),
        }
    }
}

impl TryFrom<&str> for Method {
    type Error = HlsError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Method::try_from(value.as_bytes())
    }
}

impl TryFrom<String> for Method {
    type Error = HlsError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Method::try_from(value.as_bytes())
    }
}

impl TryFrom<&[u8]> for Method {
    type Error = HlsError;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        match value {
            b"GET" => Ok(Method::GET),
            b"POST" => Ok(Method::POST),
            b"OPTIONS" => Ok(Method::OPTIONS),
            b"HEAD" => Ok(Method::HEAD),
            b"PUT" => Ok(Method::PUT),
            b"DELETE" => Ok(Method::DELETE),
            b"CONNECT" => Ok(Method::CONNECT),
            b"TRACH" => Ok(Method::TRACH),
            _ => Err("Invalid HTTP method".into())
        }
    }
}