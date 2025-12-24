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
        match value.to_uppercase().as_str() {
            "GET" => Ok(Method::GET),
            "POST" => Ok(Method::POST),
            "OPTIONS" => Ok(Method::OPTIONS),
            "HEAD" => Ok(Method::HEAD),
            "PUT" => Ok(Method::PUT),
            "DELETE" => Ok(Method::DELETE),
            "CONNECT" => Ok(Method::CONNECT),
            "TRACH" => Ok(Method::TRACH),
            _ => Err("Invalid HTTP method".into())
        }
    }
}

impl TryFrom<String> for Method {
    type Error = HlsError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Method::try_from(value.as_str())
    }
}