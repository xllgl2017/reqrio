use crate::buffer::*;
use crate::error::RlsResult;
use crate::{Buffer, BufferError, RlsError};
use std::ffi::CString;
use std::ops::Range;
use std::slice;

#[allow(non_camel_case_types)]
pub type u24 = u32;

pub trait WriteExt {
    fn buffer(&self) -> &Buffer;
    fn buffer_mut(&mut self) -> &mut Buffer;

    fn capacity(&self) -> usize {
        unsafe { Buffer_capacity(self.buffer().0.as_ptr()) }
    }
    fn check_write(&self, res: i32, size: usize) -> Result<(), BufferError> {
        if res == 1 { return Ok(()); };
        Err(BufferError::CapacityTooSmall {
            current: self.capacity(),
            file: file!(),
            needed: self.capacity() + size,
            line: line!(),
        })
    }

    fn write_u8(&mut self, v: u8) -> Result<(), BufferError> {
        let res = unsafe { Buffer_write_u8(self.buffer_mut().0.as_mut_ptr(), &v) };
        self.check_write(res, 1)
    }
    fn write_u16_be(&mut self, v: u16) -> Result<(), BufferError> {
        let res = unsafe { Buffer_write_u16(self.buffer_mut().0.as_mut_ptr(), &v) };
        self.check_write(res, 2)
    }

    #[inline]
    fn write_u16(&mut self, v: u16) -> Result<(), BufferError> {
        self.write_u16_be(v.to_be())
    }

    fn write_u16_in(&mut self, place: usize, n: u16) -> Result<(), BufferError> {
        self.write_slice_in(place, &n.to_be_bytes())?;
        Ok(())
    }

    fn write_u24_be(&mut self, v: u24) -> Result<(), BufferError> {
        let res = unsafe { Buffer_write_u24(self.buffer_mut().0.as_mut_ptr(), &v) };
        self.check_write(res, 3)
    }

    #[inline]
    fn write_u24(&mut self, v: u24) -> Result<(), BufferError> {
        self.write_u24_be(v.to_be())
    }

    fn write_u24_be_in(&mut self, place: usize, v: u24) -> Result<usize, BufferError> {
        let res = unsafe { Buffer_write_u24_in(self.buffer_mut().0.as_mut_ptr(), place, &v) };
        self.check_write(res, 3)?;
        Ok(3)
    }

    fn write_u24_in(&mut self, place: usize, v: u24) -> Result<usize, BufferError> {
        self.write_u24_be_in(place, v.to_be())
    }

    fn write_u32_be(&mut self, v: u32) -> Result<(), BufferError> {
        let res = unsafe { Buffer_write_u32(self.buffer_mut().0.as_mut_ptr(), &v) };
        self.check_write(res, 4)
    }

    #[inline]
    fn write_u32(&mut self, v: u32) -> Result<(), BufferError> {
        self.write_u32_be(v.to_be())
    }

    #[inline]
    fn write_ru32(&mut self, v: &u32) -> Result<(), BufferError> {
        self.write_u32_be(v.to_be())
    }

    fn write_u64_be(&mut self, v: u64) -> Result<(), BufferError> {
        let res = unsafe { Buffer_write_u64(self.buffer_mut().0.as_mut_ptr(), &v) };
        self.check_write(res, 8)
    }

    fn write_u64(&mut self, v: u64) -> Result<(), BufferError> {
        self.write_u64_be(v.to_be())
    }

    fn write_slice(&mut self, v: &[u8]) -> Result<(), BufferError> {
        let res = unsafe { Buffer_write_slice(self.buffer_mut().0.as_mut_ptr(), v.as_ptr(), v.len()) };
        self.check_write(res, v.len())
    }

    ///不更新长度，需要更新使用write_slice
    fn write_slice_in(&mut self, place: usize, v: &[u8]) -> Result<usize, BufferError> {
        let res = unsafe { Buffer_write_slice_in(self.buffer_mut().0.as_mut_ptr(), place, v.as_ptr(), v.len()) };
        self.check_write(res, v.len())?;
        Ok(v.len())
    }


    fn flush(&mut self, offset: usize, sni: String, h2: bool) -> RlsResult<()> {
        let csni = CString::new(sni)?;
        let res = unsafe { Buffer_flush(self.buffer_mut().0.as_mut_ptr(), self.offset().end - offset, csni.as_ptr(), h2) };
        if res != 1 { return Err(RlsError::Currently("buffer flush error".to_string())); }
        Ok(())
    }

    fn check_subscription(token: impl AsRef<str>) -> RlsResult<i32> {
        let is_subscribed = unsafe { is_subscription(CString::new(token.as_ref())?.as_ptr()) };
        if !is_subscribed {
            println!("\x1b[01;33m[Fingerprint] WARN \x1b[0m You have not subscribed yet, so this call will be ignored.");
        }
        Ok(if is_subscribed { 0 } else { -2 })
    }

    #[inline]
    fn unfilled_len(&self) -> usize {
        let capacity = unsafe { Buffer_capacity(self.buffer().0.as_ptr()) };
        capacity - self.end()
    }

    #[inline]
    fn start(&self) -> usize {
        unsafe { Buffer_start(self.buffer().0.as_ptr()) }
    }

    #[inline]
    fn end(&self) -> usize {
        unsafe { Buffer_end(self.buffer().0.as_ptr()) }
    }

    #[inline]
    fn unfilled_ptr(&mut self) -> *mut u8 {
        let ptr = unsafe { Buffer_pointer_mut(self.buffer_mut().0.as_mut_ptr()) };
        unsafe { ptr.add(self.end()) }
    }

    fn unfilled(&mut self) -> &mut [u8] {
        let ptr = self.unfilled_ptr();
        unsafe { slice::from_raw_parts_mut(ptr, self.unfilled_len()) }
    }
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn len(&self) -> usize {
        unsafe { Buffer_len(self.buffer().0.as_ptr()) }
    }
    fn add_len(&mut self, len: usize) {
        unsafe { Buffer_add_len(self.buffer_mut().0.as_mut_ptr(), len) }
    }
    fn offset(&self) -> Range<usize> {
        self.start()..self.end()
    }
}


