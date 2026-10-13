use crate::error::HlsResult;
use crate::json::JsonValue;
use crate::*;
use std::fmt::{Display, Formatter};
use std::str::Utf8Error;


#[repr(C)]
pub struct Response {
    //share c
    #[cfg(feature = "export")]
    pub(crate) sid: u64,
    pub(crate) status: HttpStatus,
    pub(crate) alpn: ALPN,
    pub(crate) body: Writer,
    pub(crate) header: Header,
}

impl Default for Response {
    fn default() -> Self {
        Response {
            alpn: Default::default(),
            status: HttpStatus::None,
            #[cfg(feature = "export")]
            sid: 0,
            header: Header::default(),
            body: Writer::with_capacity(8192),
        }
    }
}

impl Response {
    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn header_mut(&mut self) -> &mut Header { &mut self.header }

    pub fn json(self) -> HlsResult<JsonValue> { Ok(json::from_bytes(self.body.filled())?) }

    pub fn as_text(&self) -> Result<&str, Utf8Error> { std::str::from_utf8(self.body.filled()) }

    pub fn text(self) -> Result<String, Utf8Error> { Ok(self.as_text()?.to_owned()) }

    pub fn as_bytes(&self) -> &[u8] { self.body.filled() }

    pub fn bytes(self) -> Vec<u8> { self.body.filled().to_vec() }

    pub fn status(&self) -> HttpStatus { self.status }

    pub fn alpn(&self) -> &ALPN { &self.alpn }
}

impl Display for Response {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if !self.alpn.is_empty() {
            write!(f, "{} {} {}", self.alpn, self.status.code(), self.status.spec())?;
            write!(f, "\r\n")?;
        }
        write!(f, "{}", self.header)?;
        let body = self.as_text().unwrap_or("(二进制数据)");
        if !body.is_empty() {
            write!(f, "\r\n\r\n")?;
            write!(f, "{}", body)?;
            write!(f, "\r\n")?;
        }
        Ok(())
    }
}

// #[cfg(feature = "serde")]
// use serde::{Deserialize, Deserializer};
// use serde::de::{Error, MapAccess, Unexpected};
// #[cfg(feature = "serde")]
// use serde::de::Visitor;
// 
// #[cfg(feature = "serde")]
// impl<'de> Deserialize<'de> for Response {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//     where
//         D: Deserializer<'de>,
//     {
//         struct RespVisitor;
//         impl<'de> Visitor<'de> for RespVisitor {
//             type Value = Response;
// 
//             fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
//                 write!(formatter, "{}", 1)
//             }
// 
//             fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
//             where
//                 A: MapAccess<'de>,
//             {
//                 let mut resp = Response::default();
//                 while let Some(key) = map.next_key::<reqrio_json::JsonValue>()? {
//                     resp.sid = map.next_value::<u64>()?;
//                 }
//                 Err(Error::invalid_type(Unexpected::Map, &self))
//             }
//         }
//         deserializer.deserialize_struct("Response", &["sid1"], RespVisitor)
//     }
// }