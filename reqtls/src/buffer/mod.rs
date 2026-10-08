mod encode;
mod decode;
mod error;
mod reader;

use crate::error::RlsResult;
use crate::ffi::{c_struct_free, CPointer};
pub use decode::TlsDecodeBuffer;
pub use encode::CipherEncodeBuffer;
pub use error::BufferError;
pub use reader::Reader;
use std::cmp::max;
use std::ffi::CString;
use std::fmt::{Debug, Formatter};
use std::ops::Range;
use std::os::raw::{c_char, c_int};
use std::ptr::null_mut;
use std::slice;

#[allow(non_camel_case_types)]
pub type u24 = u32;

unsafe extern "C" {
    fn Writer_new(buffer: *mut Writer) -> c_int;
    fn Writer_resize(buffer: *mut Writer, capacity: usize) -> c_int;
    fn Writer_free(buffer: *mut Writer);
    fn Writer_used_empty(buffer: *mut Writer, size: usize) -> bool;
    fn Writer_write_u8(buffer: *mut Writer, val: u8) -> i32;
    fn Writer_write_u8_unchecked(buffer: *mut Writer, val: u8);
    fn Writer_write_u16_le(buffer: *mut Writer, val: u16) -> i32;
    fn Writer_write_u16(buffer: *mut Writer, val: u16);
    fn Writer_write_u24_le(buffer: *mut Writer, val: u24) -> i32;
    fn Writer_write_u24(buffer: *mut Writer, val: u24);
    fn Writer_write_u24_le_in(buffer: *mut Writer, place: usize, val: u24) -> i32;
    fn Writer_write_u32_le(buffer: *mut Writer, val: u32) -> i32;
    fn Writer_write_u32(buffer: *mut Writer, val: u32);
    fn Writer_write_u64_le(buffer: *mut Writer, val: u64) -> i32;
    fn Writer_write_u64(buffer: *mut Writer, val: u64);
    fn Writer_write_slice(buffer: *mut Writer, ptr: *const u8, len: usize) -> i32;
    fn Writer_write_slice_unchecked(buffer: *mut Writer, ptr: *const u8, len: usize);
    fn Writer_write_slice_in(buffer: *mut Writer, place: usize, ptr: *const u8, len: usize) -> i32;
    fn Writer_move_to(buffer: *mut Writer, from: usize, to: usize, pos: usize);
    pub fn is_subscription(token: *const c_char) -> bool;
}

c_struct_free!(Writer, Writer_free);
#[repr(C)]
pub struct Writer {
    capacity: usize,
    start: usize,
    end: usize,
    ptr: *mut u8,
    _rsv1: bool,
    _rsv2: usize,
}

impl Writer {
    const fn new(ptr: *mut u8, capacity: usize) -> Writer {
        Writer {
            capacity,
            start: 0,
            end: 0,
            ptr,
            _rsv1: false,
            _rsv2: 0,
        }
    }

    pub const fn none() -> Writer {
        Writer::new(null_mut(), 0)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        let mut buffer = Writer::new(null_mut(), capacity);
        let ret = unsafe { Writer_new(&mut buffer) };
        if ret != 1 { panic!("failed to create buffer") };
        buffer
    }

    pub fn resize(&mut self, at_least: usize) -> Result<(), BufferError> {
        let mut capacity = self.capacity() * 2;
        while capacity < at_least { capacity *= 2; }
        let ret = unsafe { Writer_resize(self, capacity) };
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
        self.end = match offset.end > self.capacity {
            true => self.capacity,
            false => offset.end
        };
        self.start = offset.start;
    }

    pub const fn from_ptr(buf: *mut u8, len: usize) -> Self {
        Writer::new(buf, len)
    }

    pub fn filled_ptr(&self) -> *const u8 {
        unsafe { self.ptr.add(self.start) }
    }


    pub fn filled(&self) -> &[u8] {
        let len = self.end - self.start;
        unsafe { slice::from_raw_parts(self.filled_ptr(), len) }
    }

    pub fn filled_mut(&mut self) -> &mut [u8] {
        let len = self.end - self.start;
        unsafe { slice::from_raw_parts_mut(self.filled_ptr().cast_mut(), len) }
    }

    pub fn raw_ptr(&self) -> *const u8 {
        self.ptr
    }

    pub fn raw_ptr_mut(&mut self) -> *mut u8 {
        self.ptr
    }

    pub fn reset(&mut self) {
        self.start = 0;
        self.end = 0;
    }

    pub fn slice_at(&self, place: usize) -> &[u8] {
        let len = self.end - place;
        unsafe { slice::from_raw_parts(self.ptr.add(place), len) }
    }

    pub fn slice(&self, range: Range<usize>) -> &[u8] {
        unsafe { slice::from_raw_parts(self.ptr.add(range.start), range.len()) }
    }

    pub fn used_empty(&mut self, size: usize) -> bool {
        unsafe { Writer_used_empty(self, size) }
    }

    pub fn move_to(&mut self, r: Range<usize>, pos: usize) -> Result<(), BufferError> {
        if r.end < r.start || r.end > self.end() { return Err(BufferError::RangeEdgeError(r)); };
        unsafe { Writer_move_to(self, r.start, r.end, pos) };
        Ok(())
    }

    pub fn check_move(&mut self, need: usize) -> Result<(), BufferError> {
        if self.unfilled_len() >= need { return Ok(()); }
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

    pub fn capacity(&self) -> usize {
        self.capacity
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

    pub fn write_u8(&mut self, v: u8) -> Result<(), BufferError> {
        let res = unsafe { Writer_write_u8(self, v) };
        self.check_write(res, 1)
    }
    #[allow(unsafe_op_in_unsafe_fn)]
    #[allow(clippy::missing_safety_doc)]
    pub unsafe fn write_u8_unchecked(&mut self, v: u8) {
        Writer_write_u8_unchecked(self, v)
    }
    pub fn write_u16_be(&mut self, v: u16) -> Result<(), BufferError> {
        let res = unsafe { Writer_write_u16_le(self, v) };
        self.check_write(res, 2)
    }

    #[inline]
    pub fn write_u16(&mut self, v: u16) -> Result<(), BufferError> {
        self.write_u16_be(v.to_be())
    }

    #[allow(unsafe_op_in_unsafe_fn)]
    #[allow(clippy::missing_safety_doc)]
    pub unsafe fn write_u16_unchecked(&mut self, v: u16) {
        Writer_write_u16(self, v)
    }

    pub fn write_u16_in(&mut self, place: usize, n: u16) -> Result<(), BufferError> {
        self.write_slice_in(place, &n.to_be_bytes())?;
        Ok(())
    }

    pub fn write_u24_be(&mut self, v: u24) -> Result<(), BufferError> {
        let res = unsafe { Writer_write_u24_le(self, v) };
        self.check_write(res, 3)
    }

    #[inline]
    pub fn write_u24(&mut self, v: u24) -> Result<(), BufferError> {
        self.write_u24_be(v.to_be())
    }

    #[allow(unsafe_op_in_unsafe_fn)]
    #[allow(clippy::missing_safety_doc)]
    pub unsafe fn write_u24_unchecked(&mut self, v: u24) {
        Writer_write_u24(self, v)
    }


    pub fn write_u24_be_in(&mut self, place: usize, v: u24) -> Result<usize, BufferError> {
        let res = unsafe { Writer_write_u24_le_in(self, place, v) };
        self.check_write(res, 3)?;
        Ok(3)
    }

    pub fn write_u24_in(&mut self, place: usize, v: u24) -> Result<usize, BufferError> {
        self.write_u24_be_in(place, v.to_be())
    }

    pub fn write_u32_be(&mut self, v: u32) -> Result<(), BufferError> {
        let res = unsafe { Writer_write_u32_le(self, v) };
        self.check_write(res, 4)
    }

    #[inline]
    pub fn write_u32(&mut self, v: u32) -> Result<(), BufferError> {
        self.write_u32_be(v.to_be())
    }

    #[allow(unsafe_op_in_unsafe_fn)]
    #[allow(clippy::missing_safety_doc)]
    pub unsafe fn write_u32_unchecked(&mut self, v: u32) {
        Writer_write_u32(self, v)
    }

    pub fn write_u64_be(&mut self, v: u64) -> Result<(), BufferError> {
        let res = unsafe { Writer_write_u64_le(self, v) };
        self.check_write(res, 8)
    }

    pub fn write_u64(&mut self, v: u64) -> Result<(), BufferError> {
        self.write_u64_be(v.to_be())
    }

    #[allow(unsafe_op_in_unsafe_fn)]
    #[allow(clippy::missing_safety_doc)]
    pub unsafe fn write_u64_unchecked(&mut self, v: u64) {
        Writer_write_u64(self, v)
    }

    pub fn write_slice(&mut self, v: &[u8]) -> Result<(), BufferError> {
        let res = unsafe { Writer_write_slice(self, v.as_ptr(), v.len()) };
        self.check_write(res, v.len())
    }

    #[allow(unsafe_op_in_unsafe_fn)]
    #[allow(clippy::missing_safety_doc)]
    pub unsafe fn write_slice_unchecked(&mut self, v: &[u8]) {
        Writer_write_slice_unchecked(self, v.as_ptr(), v.len())
    }


    ///不更新长度，需要更新使用write_slice
    pub fn write_slice_in(&mut self, place: usize, v: &[u8]) -> Result<usize, BufferError> {
        let res = unsafe { Writer_write_slice_in(self, place, v.as_ptr(), v.len()) };
        self.check_write(res, v.len())?;
        Ok(v.len())
    }

    pub fn check_subscription(token: impl AsRef<str>) -> RlsResult<i32> {
        let is_subscribed = unsafe { is_subscription(CString::new(token.as_ref())?.as_ptr()) };
        if !is_subscribed {
            println!("\x1b[01;33m[Fingerprint] WARN \x1b[0m You have not subscribed yet, so this call will be ignored.");
        }
        Ok(if is_subscribed { 0 } else { -2 })
    }

    #[inline]
    pub const fn unfilled_len(&self) -> usize {
        self.capacity - self.end
    }

    #[inline]
    pub const fn start(&self) -> usize {
        self.start
    }

    #[inline]
    pub const fn end(&self) -> usize {
        self.end
    }

    #[inline]
    pub fn unfilled_ptr(&mut self) -> *mut u8 {
        unsafe { self.ptr.add(self.end) }
    }

    pub fn unfilled(&mut self) -> &mut [u8] {
        let ptr = self.unfilled_ptr();
        unsafe { slice::from_raw_parts_mut(ptr, self.unfilled_len()) }
    }
    pub const fn is_empty(&self) -> bool {
        self.start == self.end
    }
    pub const fn len(&self) -> usize {
        self.end - self.start
    }
    pub const fn add_len(&mut self, len: usize) {
        self.end += len;
    }
    pub fn offset(&self) -> Range<usize> {
        self.start..self.end
    }
}

impl Debug for Writer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(self.filled()))
    }
}


///对应c的结构{
/// uint8_t tag;
/// size_t cap;
/// uint8_t *ptr;
/// size_t len;
/// }
#[repr(C)]
pub enum Buf<'a> {
    Ref {
        cap: usize,
        inner: &'a [u8],
    },
    Vec(Vec<u8>),
    ///outer maybe not used，only c use/free
    Raw {
        cap: usize,
        ptr: *mut u8,
        len: usize,
    },
}

impl<'a> Default for Buf<'a> {
    fn default() -> Self {
        Buf::new_ref(&[])
    }
}

impl<'a> Buf<'a> {
    pub const fn new_ref(val: &'a [u8]) -> Buf<'a> {
        Buf::Ref { cap: 0, inner: val }
    }
    pub const fn new_c() -> Buf<'static> { Buf::Raw { cap: 0, ptr: null_mut(), len: 0 } }
    pub const fn is_empty(&self) -> bool {
        match self {
            Buf::Ref { inner, .. } => inner.is_empty(),
            Buf::Vec(v) => v.is_empty(),
            Buf::Raw { len, ptr, .. } => *len == 0 || ptr.is_null(),
        }
    }
    pub const fn len(&self) -> usize {
        match self {
            Buf::Ref { inner, .. } => inner.len(),
            Buf::Vec(v) => v.len(),
            Buf::Raw { len, .. } => *len,
        }
    }
    pub const fn as_ptr(&self) -> *const u8 {
        match self {
            Buf::Ref { inner, .. } => inner.as_ptr(),
            Buf::Vec(buf) => buf.as_ptr(),
            Buf::Raw { ptr, .. } => *ptr,
        }
    }
    pub const fn as_slice(&self) -> &[u8] {
        match self {
            Buf::Ref { inner, .. } => inner,
            Buf::Vec(inner) => inner.as_slice(),
            Buf::Raw { len, ptr, .. } => {
                if ptr.is_null() { return &[]; }
                unsafe { slice::from_raw_parts(*ptr, *len) }
            }
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.as_slice().to_vec()
    }

    pub fn into_vec(self) -> Vec<u8> {
        match self {
            Buf::Ref { inner, .. } => inner.to_vec(),
            Buf::Vec(v) => v,
            Buf::Raw { .. } => panic!("please init by other"),
        }
    }
}

impl<'a> AsRef<[u8]> for Buf<'a> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

#[cfg(debug_assertions)]
impl<'a> Debug for Buf<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", hex::encode(self.as_slice()))
    }
}

impl<'a> Clone for Buf<'a> {
    fn clone(&self) -> Self {
        match self {
            Buf::Ref { cap, inner } => Buf::Ref { cap: *cap, inner },
            Buf::Vec(v) => Buf::Vec(v.clone()),
            Buf::Raw { .. } => Buf::Vec(self.to_vec())
        }
    }
}

unsafe impl<'a> Send for Buf<'a> {}
unsafe impl<'a> Sync for Buf<'a> {}

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

    ///注意外部指针，不自动释放
    pub fn from_ptr(ptr: *const u8) -> BufPtr {
        BufPtr {
            ptr: CPointer::new(ptr.cast_mut()).with_free(false),
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
        BufPtr {
            ptr: CPointer::new(self.ptr.as_mut_ptr()).with_free(false),
            len: self.len,
        }
    }
}

#[cfg(test)]
mod test_buffer {
    use crate::Writer;

    #[test]
    fn buffer_test() {
        let mut buffer = Writer::with_capacity(1024);
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
        let mut buffer = Writer::from_ptr(data.as_mut_ptr(), data.len());
        buffer.write_slice(&[1, 2, 3, 4, 5]).unwrap();
        assert_eq!(buffer.filled(), [1, 2, 3, 4, 5]);
    }
}