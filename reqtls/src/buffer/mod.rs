mod encode;
mod decode;
mod ext;
mod error;
mod reader;

use std::cmp::max;
use crate::ffi;
use crate::ffi::CPointer;
pub use decode::CipherDecodeBuffer;
pub use encode::CipherEncodeBuffer;
pub use error::BufferError;
pub use ext::{u24, WriteExt};
use std::fmt::{Debug, Formatter};
use std::ops::Range;
use std::os::raw::{c_char, c_int};
use std::slice;
pub use reader::Reader;

#[repr(C)]
#[allow(clippy::upper_case_acronyms)]
struct BUFFER {
    _unused: [u8; 0],
}
ffi::c_pointer_free!(BUFFER, Buffer_free);

unsafe extern "C" {
    fn Buffer_new(capacity: usize) -> *mut BUFFER;
    fn Buffer_resize(buffer: *mut BUFFER, capacity: usize) -> c_int;
    fn Buffer_reset_offset(buffer: *mut BUFFER, start: usize, end: usize);
    fn Buffer_from_ptr(ptr: *mut u8, capacity: usize) -> *mut BUFFER;
    fn Buffer_free(buffer: *mut BUFFER);
    fn Buffer_len(buffer: *const BUFFER) -> usize;
    fn Buffer_capacity(buffer: *const BUFFER) -> usize;
    fn Buffer_start(buffer: *const BUFFER) -> usize;
    fn Buffer_end(buffer: *const BUFFER) -> usize;
    fn Buffer_add_len(buffer: *mut BUFFER, len: usize);
    fn Buffer_reset(buffer: *mut BUFFER);
    fn Buffer_used_empty(buffer: *mut BUFFER, size: usize) -> bool;
    fn Buffer_pointer(buffer: *const BUFFER) -> *const u8;
    fn Buffer_pointer_mut(buffer: *mut BUFFER) -> *mut u8;
    fn Buffer_write_u8(buffer: *mut BUFFER, val: &u8) -> i32;
    fn Buffer_write_u16(buffer: *mut BUFFER, val: &u16) -> i32;
    fn Buffer_write_u24(buffer: *mut BUFFER, val: &u24) -> i32;
    fn Buffer_write_u24_in(buffer: *mut BUFFER, place: usize, val: &u24) -> i32;
    fn Buffer_write_u32(buffer: *mut BUFFER, val: &u32) -> i32;
    fn Buffer_write_u64(buffer: *mut BUFFER, val: &u64) -> i32;
    fn Buffer_write_slice(buffer: *mut BUFFER, ptr: *const u8, len: usize) -> i32;
    fn Buffer_write_slice_in(buffer: *mut BUFFER, place: usize, ptr: *const u8, len: usize) -> i32;
    fn Buffer_flush(buffer: *mut BUFFER, len: usize, sni: *const c_char, h2: bool) -> i32;
    fn Buffer_move_to(buffer: *mut BUFFER, from: usize, to: usize, pos: usize);
    pub fn is_subscription(token: *const c_char) -> bool;
}


pub struct Buffer(CPointer<BUFFER>);

impl Default for Buffer {
    fn default() -> Self {
        Buffer::with_capacity(16438)
    }
}

impl Debug for Buffer {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.filled()))
    }
}

impl Buffer {
    pub fn none() -> Buffer {
        Buffer(CPointer::nullptr())
    }

    pub fn with_capacity(capacity: usize) -> Self {
        let buffer = unsafe { Buffer_new(capacity) };
        if buffer.is_null() { panic!("failed to create buffer") };
        Buffer(CPointer::new(buffer))
    }

    pub fn resize(&mut self, at_least: usize) -> Result<(), BufferError> {
        let mut capacity = self.capacity() * 2;
        while capacity < at_least { capacity *= 2; }
        let ret = unsafe { Buffer_resize(self.0.as_mut_ptr(), capacity) };
        if ret != 1 {
            return Err(BufferError::ResizeFail {
                current: self.capacity(),
                at_least,
                new: capacity,
            });
        }
        Ok(())
    }

    pub fn truncate(&mut self, size: usize) {
        let start = self.start();
        let end = max(size - self.end(), start);
        self.reset_offset(start..end)
    }

    pub fn reset_offset(&mut self, offset: Range<usize>) {
        unsafe { Buffer_reset_offset(self.0.as_mut_ptr(), offset.start, offset.end) };
    }

    pub fn from_ptr(buf: &mut [u8]) -> Self {
        let buffer = unsafe { Buffer_from_ptr(buf.as_mut_ptr(), buf.len()) };
        Buffer(CPointer::new(buffer))
    }

    fn filled_ptr(&self) -> *const u8 {
        let ptr = unsafe { Buffer_pointer(self.0.as_ptr()) };
        unsafe { ptr.add(self.start()) }
    }


    pub fn filled(&self) -> &[u8] {
        let offset = self.offset();
        unsafe { slice::from_raw_parts(self.filled_ptr(), offset.len()) }
    }

    pub fn filled_mut(&mut self) -> &mut [u8] {
        let offset = self.offset();
        unsafe { slice::from_raw_parts_mut(self.raw_ptr_mut().add(offset.start), offset.len()) }
    }

    pub fn raw_ptr(&self) -> *const u8 {
        unsafe { Buffer_pointer(self.0.as_ptr()) }
    }

    pub fn raw_ptr_mut(&mut self) -> *mut u8 {
        unsafe { Buffer_pointer_mut(self.0.as_mut_ptr()) }
    }

    pub fn reset(&mut self) {
        unsafe { Buffer_reset(self.0.as_mut_ptr()) }
    }

    pub fn slice_at(&self, place: usize) -> &[u8] {
        let ptr = unsafe { Buffer_pointer(self.0.as_ptr()) };
        let len = self.end() - place;
        unsafe { slice::from_raw_parts(ptr.add(place), len) }
    }

    pub fn slice(&self, range: Range<usize>) -> &[u8] {
        let ptr = unsafe { Buffer_pointer(self.0.as_ptr()) };
        unsafe { slice::from_raw_parts(ptr.add(range.start), range.len()) }
    }

    pub fn used_empty(&mut self, size: usize) -> bool {
        unsafe { Buffer_used_empty(self.0.as_mut_ptr(), size) }
    }

    pub fn move_to(&mut self, r: Range<usize>, pos: usize) -> Result<(), BufferError> {
        if r.end < r.start || r.end > self.end() { return Err(BufferError::RangeEdgeError(r)); };
        unsafe { Buffer_move_to(self.0.as_mut_ptr(), r.start, r.end, pos) };
        Ok(())
    }

    pub fn check_move(&mut self, need: usize) -> Result<(), BufferError> {
        if self.len() >= need { return Ok(()); }
        if self.unfilled_len() < need && self.offset().start != 0 {
            self.move_to(self.offset(), 0)?;
        }
        if self.unfilled().is_empty() {
            return Err(BufferError::CapacityTooSmall {
                needed: need,
                current: self.capacity(),
                file: file!(),
                line: line!(),
            });
        }
        Ok(())
    }
}

impl WriteExt for Buffer {
    fn buffer(&self) -> &Buffer {
        self
    }

    fn buffer_mut(&mut self) -> &mut Buffer {
        self
    }
}

#[derive(Clone)]
pub enum Buf<'a> {
    Ptr(BufPtr),
    Ref(&'a [u8]),
    Vec(Vec<u8>),
}

impl<'a> Buf<'a> {
    pub fn is_empty(&self) -> bool {
        match self {
            Buf::Ptr(v) => v.is_null(),
            Buf::Ref(v) => v.is_empty(),
            Buf::Vec(v) => v.is_empty(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Buf::Ptr(v) => v.len,
            Buf::Ref(v) => v.len(),
            Buf::Vec(v) => v.len()
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            Buf::Ptr(v) => v.as_slice().to_vec(),
            Buf::Ref(v) => v.to_vec(),
            Buf::Vec(v) => v.clone()
        }
    }
}

impl<'a> AsRef<[u8]> for Buf<'a> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Buf::Ptr(v) => v.as_slice(),
            Buf::Ref(v) => v,
            Buf::Vec(v) => v.as_slice(),
        }
    }
}

impl<'a> Debug for Buf<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Buf::Ptr(v) => write!(f, "{:?}", v),
            Buf::Ref(v) => write!(f, "{:?}", hex::encode(v)),
            Buf::Vec(v) => write!(f, "{:?}", hex::encode(v)),
        }
    }
}

pub struct BufPtr {
    ptr: CPointer<u8>,
    len: usize,
}

impl BufPtr {
    pub fn nullptr() -> Self {
        BufPtr {
            ptr: CPointer::nullptr(),
            len: 0,
        }
    }

    pub fn disable_auto_free(mut self) -> Self {
        self.ptr.disable_auto_free();
        self
    }

    pub fn is_null(&self) -> bool { self.ptr.is_null() }

    pub fn ptr_mut(&mut self) -> &mut *mut u8 { self.ptr.as_mut() }

    pub fn len(&self) -> usize { self.len }

    pub fn check_ptr(&mut self, len: usize) -> Result<(), BufferError> {
        if self.is_null() || len == usize::MAX { return Err(BufferError::Nullptr); };
        self.len = len;
        Ok(())
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl Debug for BufPtr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.as_slice())
    }
}

impl Clone for BufPtr {
    fn clone(&self) -> Self {
        BufPtr{
            ptr: CPointer::new(self.ptr.as_mut_ptr()).with_free(false),
            len: self.len,
        }
    }
}

// pub struct Reader<'a> {
//     buf: &'a [u8],
//     pos: usize,
// }
// 
// impl<'a> Reader<'a> {
//     pub fn from_slice(buf: &'a [u8]) -> Self {
//         Self { buf, pos: 0 }
//     }
// 
//     pub fn with_position(mut self, pos: usize) -> Self {
//         self.pos = pos;
//         self
//     }
//     pub fn unread_len(&self) -> usize {
//         self.buf.len() - self.pos
//     }
// 
//     pub fn into_inner(self) -> &'a [u8] { self.buf }
// 
//     pub fn inner(&self) -> &'a [u8] { self.buf }
// 
//     pub fn find<P: FnMut(&u8) -> bool>(&self, predicate: P) -> Option<usize> {
//         // self.buf[self.pos..].iter().position(predicate).map(|x| x + self.pos);
//         self.buf[self.pos..].iter().position(predicate)
//     }
// }

// impl<'a> From<&'a [u8]> for Reader<'a> {
//     fn from(buf: &'a [u8]) -> Self {
//         Self::from_slice(buf)
//     }
// }
// 
// impl<'a> From<&'a Vec<u8>> for Reader<'a> {
//     fn from(buf: &'a Vec<u8>) -> Self {
//         Self::from_slice(buf.as_slice())
//     }
// }

// impl<'a> ReadExt<'a> for Reader<'a> {
//     fn size(&self) -> usize {
//         self.buf.len()
//     }
// 
//     fn position(&self) -> usize {
//         self.pos
//     }
// 
//     fn set_position(&mut self, pos: usize) {
//         self.pos = pos;
//     }
// 
//     fn add_len(&mut self, len: usize) {
//         self.pos += len;
//     }
// 
//     fn unread_ptr(&self) -> *const u8 {
//         unsafe { self.buf.as_ptr().add(self.pos) }
//     }
// }

#[cfg(test)]
mod test_buffer {
    use crate::{Buffer, WriteExt};

    #[test]
    fn buffer_test() {
        let mut buffer = Buffer::with_capacity(1024);
        buffer.write_slice(&[1, 2, 3, 4, 5]).unwrap();
        assert_eq!(buffer.filled(), [1, 2, 3, 4, 5]);
        buffer.used_empty(1);
        assert_eq!(buffer.filled(), [2, 3, 4, 5]);
        assert_eq!(buffer.unfilled().len(), 1019);

        buffer.move_to(3..buffer.offset().end, 2).unwrap();
        assert_eq!(buffer.filled(), [2, 4, 5]);
        assert_eq!(buffer.offset(), 1..4);
        buffer.move_to(buffer.offset(), 0).unwrap();
        assert_eq!(buffer.filled(), [2, 4, 5]);
        assert_eq!(buffer.offset(), 0..3);

        buffer.resize(2048).unwrap();
        assert_eq!(buffer.capacity(), 2048);


        let mut data = vec![0u8; 1024];
        let mut buffer = Buffer::from_ptr(data.as_mut_slice());
        buffer.write_slice(&[1, 2, 3, 4, 5]).unwrap();
        assert_eq!(buffer.filled(), [1, 2, 3, 4, 5]);
    }
}