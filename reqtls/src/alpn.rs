use std::fmt::Display;
use crate::error::RlsResult;
use crate::{BufferError, Reader, Writer};

#[derive(Debug, PartialEq, Clone)]
pub enum ALPN {
    #[cfg(feature = "quic")]
    Http30,
    Http20,
    Http11,
    Http10,
    Custom(Vec<u8>),
}

impl ALPN {
    pub fn from_slice(opt: &[u8]) -> ALPN {
        match opt {
            b"http/1.0" => ALPN::Http10,
            b"http/1.1" => ALPN::Http11,
            b"h2" => ALPN::Http20,
            #[cfg(feature = "quic")]
            b"h3" => ALPN::Http30,
            _ => ALPN::Custom(opt.to_vec()),
        }
    }

    pub fn value(&self) -> &str {
        match self {
            ALPN::Http10 => "http/1.0",
            ALPN::Http11 => "http/1.1",
            ALPN::Http20 => "h2",
            #[cfg(feature = "quic")]
            ALPN::Http30 => "h3",
            ALPN::Custom(v) => unsafe { std::str::from_utf8_unchecked(v.as_slice()) }
        }
    }

    pub fn from_reader(reader: &mut Reader<'_>) -> RlsResult<Vec<ALPN>> {
        let mut res = Vec::with_capacity(reader.unread_len());
        while reader.unread_len() > 0 {
            let len = reader.read_u8()?;
            res.push(ALPN::from_slice(reader.read_slice(len as usize)?));
        }
        Ok(res)
    }

    pub fn is_empty(&self) -> bool { self.len() == 0 }

    pub fn len(&self) -> usize { 1 + self.value().len() }

    pub fn write_to(self, writer: &mut Writer) -> Result<(), BufferError> {
        writer.write_u8(self.value().len() as u8)?;
        writer.write_slice(self.value().as_bytes())
    }
}

impl Display for ALPN {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "quic")]
            ALPN::Http30 => write!(f, "HTTP/3.0"),
            ALPN::Http20 => write!(f, "HTTP/2.0"),
            ALPN::Http11 => write!(f, "HTTP/1.1"),
            ALPN::Http10 => write!(f, "HTTP/1.0"),
            ALPN::Custom(v) => write!(f, "{}", String::from_utf8_lossy(v)),
        }
    }
}