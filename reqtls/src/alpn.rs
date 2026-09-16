use crate::error::RlsResult;
use crate::{BufferError, Reader, Writer};
use std::fmt::Display;
use std::slice;

#[repr(C)]
#[derive(Default)]
pub struct ALPN {
    len: u8,
    ptr: *mut u8,
    capacity: usize,
}

impl ALPN {
    pub const HTTP11: ALPN = ALPN { capacity: 0, ptr: "http/1.1".as_ptr().cast_mut(), len: 8 };
    pub const HTTP20: ALPN = ALPN { capacity: 0, ptr: "h2".as_ptr().cast_mut(), len: 2 };
    #[cfg(feature = "quic")]
    pub const HTTP30: ALPN = ALPN { capacity: 0, ptr: "h3".as_ptr().cast_mut(), len: 2 };

    pub fn from_slice(opt: &[u8]) -> ALPN {
        let (ptr, len, capacity) = opt.to_vec().into_raw_parts();
        ALPN {
            ptr,
            len: len as u8,
            capacity,
        }
    }

    pub const fn value(&self) -> &str {
        if self.ptr.is_null() { return ""; }
        unsafe {
            let slice = slice::from_raw_parts(self.ptr, self.len as usize);
            std::str::from_utf8_unchecked(slice)
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

    pub fn len(&self) -> usize { 1 + self.len as usize }

    pub fn write_to(self, writer: &mut Writer) -> Result<(), BufferError> {
        writer.write_u8(self.len)?;
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
            _ => write!(f, "{}", String::from_utf8_lossy(unsafe { slice::from_raw_parts(self.ptr, self.len as usize) }).to_uppercase()),
        }
    }
}

impl Drop for ALPN {
    fn drop(&mut self) {
        if self.capacity == 0 { return; }
        unsafe {
            drop(Vec::from_raw_parts(self.ptr, self.len as usize, self.len as usize))
        }
    }
}

impl Clone for ALPN {
    fn clone(&self) -> Self {
        ALPN::from_slice(self.value().as_bytes())
    }
}

unsafe impl Send for ALPN {}
unsafe impl Sync for ALPN {}

#[cfg(debug_assertions)]
impl std::fmt::Debug for ALPN {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}