use crate::error::HlsResult;
use crate::json::JsonValue;
use crate::*;
use std::fmt::{Display, Formatter};
use std::str::Utf8Error;


/// HTTP response returned by the request engine.
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
    /// Return response headers.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Return response headers as mutable.
    pub fn header_mut(&mut self) -> &mut Header { &mut self.header }

    /// Parse the response body as JSON.
    pub fn json(self) -> HlsResult<JsonValue> { Ok(json::from_bytes(self.body.filled())?) }

    /// Read the response body as UTF-8 text.
    pub fn as_text(&self) -> Result<&str, Utf8Error> { std::str::from_utf8(self.body.filled()) }

    /// Consume the response and return the text body.
    pub fn text(self) -> Result<String, Utf8Error> { Ok(self.as_text()?.to_owned()) }

    /// Return the raw response body bytes.
    pub fn as_bytes(&self) -> &[u8] { self.body.filled() }

    /// Consume the response and return the raw body bytes.
    pub fn bytes(self) -> Vec<u8> { self.body.filled().to_vec() }

    /// Return the HTTP status.
    pub fn status(&self) -> HttpStatus { self.status }

    /// Return the negotiated ALPN value.
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