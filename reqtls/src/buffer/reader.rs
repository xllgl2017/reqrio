use std::marker::PhantomData;
use std::os::raw::c_int;
use std::slice;
use crate::boring::BoringResExt;
use crate::{u24, BufferError};


unsafe extern "C" {
    fn Reader_read_u8(reader: *mut Reader, out: *mut u8) -> c_int;
    fn Reader_read_u16_le(reader: *mut Reader, out: *mut u16) -> c_int;
    fn Reader_read_u24_le(reader: *mut Reader, out: *mut u24) -> c_int;
    fn Reader_read_u32_le(reader: *mut Reader, out: *mut u32) -> c_int;
    fn Reader_read_u64_le(reader: *mut Reader, out: *mut u64) -> c_int;
    fn Reader_read_slice(reader: *mut Reader, size: usize) -> *const u8;
}


#[repr(C)]
pub struct Reader<'a> {
    ptr: *const u8,
    size: usize,
    pos: usize,
    _unused: &'a PhantomData<()>,
}

impl<'a> Reader<'a> {
    pub fn from_slice(slice: &'a [u8]) -> Reader<'a> {
        Reader::from_ptr(slice.as_ptr(), slice.len())
    }

    pub fn from_ptr(ptr: *const u8, size: usize) -> Reader<'a> {
        Reader {
            ptr,
            pos: 0,
            size,
            _unused: &PhantomData,
        }
    }

    pub fn read_u8(&mut self) -> Result<u8, BufferError> {
        let mut out = 0;
        unsafe { Reader_read_u8(self, &mut out) }.ok(BufferError::Insufficient)?;
        Ok(out)
    }

    pub fn read_u16_le(&mut self) -> Result<u16, BufferError> {
        let mut out = 0;
        unsafe { Reader_read_u16_le(self, &mut out) }.ok(BufferError::IndexOutBound {
            index: self.pos,
            want: 2,
            size: self.size,
        })?;
        Ok(out)
    }

    pub fn read_u16(&mut self) -> Result<u16, BufferError> {
        Ok(self.read_u16_le()?.to_be())
    }

    pub fn read_u24_le(&mut self) -> Result<u24, BufferError> {
        let mut out = 0;
        unsafe { Reader_read_u24_le(self, &mut out) }.ok(BufferError::IndexOutBound {
            index: self.pos,
            want: 3,
            size: self.size,
        })?;
        Ok(out)
    }

    pub fn read_u24(&mut self) -> Result<u24, BufferError> {
        Ok(self.read_u24_le()?.to_be())
    }

    pub fn read_u32_le(&mut self) -> Result<u32, BufferError> {
        let mut out = 0;
        unsafe { Reader_read_u32_le(self, &mut out) }.ok(BufferError::IndexOutBound {
            index: self.pos,
            want: 4,
            size: self.size,
        })?;
        Ok(out)
    }

    pub fn read_u32(&mut self) -> Result<u32, BufferError> {
        Ok(self.read_u32_le()?.to_be())
    }

    pub fn read_u64_le(&mut self) -> Result<u64, BufferError> {
        let mut out = 0;
        unsafe { Reader_read_u64_le(self, &mut out) }.ok(BufferError::IndexOutBound {
            index: self.pos,
            want: 8,
            size: self.size,
        })?;
        Ok(out)
    }

    pub fn read_u64(&mut self) -> Result<u64, BufferError> {
        Ok(self.read_u64_le()?.to_be())
    }

    pub fn read_slice(&mut self, size: usize) -> Result<&'a [u8], BufferError> {
        let ptr = unsafe { Reader_read_slice(self, size) };
        if ptr.is_null() {
            return Err(BufferError::IndexOutBound {
                index: self.pos,
                want: size,
                size: self.size,
            });
        }
        Ok(unsafe { std::slice::from_raw_parts(ptr, size) })
    }

    pub fn read_reader(&mut self, size: usize) -> Result<Reader<'a>, BufferError> {
        let slice = self.read_slice(size)?;
        Ok(Reader::from_slice(slice))
    }

    pub fn read_str(&mut self, size: usize) -> Result<&'a str, BufferError> {
        let slice = self.read_slice(size)?;
        Ok(std::str::from_utf8(slice)?)
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn unread_len(&self) -> usize {
        self.size - self.pos
    }

    pub fn unread_ptr(&self) -> *const u8 {
        unsafe { self.ptr.add(self.pos) }
    }

    pub fn add_len(&mut self, size: usize) {
        self.pos += size;
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn set_position(&mut self, pos: usize) {
        self.pos = pos;
    }

    pub fn inner(&self) -> &'a [u8] {
        unsafe { slice::from_raw_parts(self.ptr, self.size) }
    }

    pub fn find<P: FnMut(&u8) -> bool>(&self, predicate: P) -> Option<usize> {
        self.inner()[self.pos..].iter().position(predicate)
    }

    pub fn read_to(&mut self, end: &[u8]) -> Result<&'a [u8], BufferError> {
        let filled = &self.inner()[self.pos..];
        let pos = filled.windows(end.len()).position(|window| window == end);
        match pos {
            None => Err(BufferError::Insufficient),
            Some(pos) => {
                let res = &filled[..pos];
                self.add_len(pos);
                Ok(res)
            }
        }
    }

    pub fn current(&mut self) -> Result<u8, BufferError> {
        if self.pos >= self.size {
            return Err(BufferError::IndexOutBound {
                index: self.pos,
                want: 1,
                size: self.size,
            });
        }
        Ok(unsafe { self.ptr.add(self.pos).read_unaligned() })
    }
}


#[cfg(test)]
mod tests {
    use super::Reader;
    #[test]
    fn test_reader() {
        let buf = [12, 23, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18];
        let mut reader = Reader::from_slice(&buf);
        assert_eq!(reader.read_u8().unwrap(), 12);
        assert_eq!(reader.read_u16().unwrap(), 5891);
        assert_eq!(reader.read_u24().unwrap(), 263430);
        assert_eq!(reader.read_u32().unwrap(), 117967114);
        assert_eq!(reader.read_u64().unwrap(), 796025588171149586);
        assert!(reader.read_u8().is_err());

        // println!("{}", u64::from_be_bytes([11, 12, 13, 14, 15, 16, 17, 18]));
    }
}