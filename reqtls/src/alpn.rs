use crate::error::RlsResult;
use crate::{Buf, BufferError, Reader, Writer};
use std::fmt::Display;

#[repr(C)]
#[derive(Default, Clone)]
pub struct ALPN {
    inner: Buf<'static>,
}

impl ALPN {
    pub const HTTP11: ALPN = ALPN { inner: Buf::new_ref(b"http/1.1") };
    pub const HTTP20: ALPN = ALPN { inner: Buf::new_ref(b"h2") };
    #[cfg(feature = "quic")]
    pub const HTTP30: ALPN = ALPN { inner: Buf::new_ref(b"h3") };

    pub fn nullptr() -> Self {
        ALPN {
            inner: Buf::new_c()
        }
    }

    pub fn from_slice(opt: &[u8]) -> ALPN {
        ALPN {
            inner: Buf::Vec(opt.to_vec())
        }
    }

    pub const fn value(&self) -> &str {
        unsafe { std::str::from_utf8_unchecked(self.inner.as_slice()) }
    }

    pub fn from_reader(reader: &mut Reader<'_>) -> RlsResult<Vec<ALPN>> {
        let mut res = Vec::with_capacity(reader.unread_len());
        while reader.unread_len() > 0 {
            let len = reader.read_u8()?;
            res.push(ALPN::from_slice(reader.read_slice(len as usize)?));
        }
        Ok(res)
    }

    pub fn is_empty(&self) -> bool { self.inner.is_empty() }

    #[deprecated]
    pub fn write_to(self, writer: &mut Writer) -> Result<(), BufferError> {
        writer.write_u8(self.inner.len() as u8)?;
        writer.write_slice(self.value().as_bytes())
    }
}

impl PartialEq for ALPN {
    fn eq(&self, other: &ALPN) -> bool {
        self.value() == other.value()
    }
}

impl PartialEq<ALPN> for &ALPN {
    fn eq(&self, other: &ALPN) -> bool {
        self.value() == other.value()
    }
}

impl Display for ALPN {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "quic")]
            h3 if h3 == ALPN::HTTP30 => write!(f, "HTTP/3.0"),
            h2 if h2 == ALPN::HTTP20 => write!(f, "HTTP/2.0"),
            h1 if h1 == ALPN::HTTP11 => write!(f, "HTTP/1.1"),
            _ => write!(f, "Unknown({})", self.value().to_uppercase()),
        }
    }
}


impl std::fmt::Debug for ALPN {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}