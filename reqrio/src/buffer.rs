#[cfg(feature = "tokio")]
use crate::error::HlsResult;
use std::ffi::c_void;
use std::ops::{Index, RangeFrom, RangeTo};
use std::ptr;
#[cfg(feature = "tokio")]
use tokio::io::AsyncReadExt;

pub struct Buffer {
    buffer: Vec<u8>,
    len: usize,
}

impl Buffer {
    pub fn with_capacity(capacity: usize) -> Buffer {
        let mut buffer = Vec::with_capacity(capacity);
        unsafe {
            buffer.set_len(capacity);
            ptr::write_bytes(buffer.as_mut_ptr(), 0, capacity);
        }
        Buffer { buffer, len: 0 }
    }

    pub fn new() -> Self {
        let res = Buffer::with_capacity(16 * 1024);
        res
    }

    pub fn new_bytes(bytes: Vec<u8>) -> Self {
        let mut res = Buffer::new();
        res.buffer[..bytes.len()].copy_from_slice(&bytes);
        res.len = bytes.len();
        res
    }

    #[cfg(feature = "tokio")]
    pub async fn read<S: AsyncReadExt + Unpin>(&mut self, stream: &mut S) -> HlsResult<()> {
        self.len = stream.read(&mut self.buffer).await?;
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn len_ptr(&mut self) -> *mut usize {
        &mut self.len
    }

    pub fn set_len(&mut self, len: usize) {
        self.len = len;
    }

    pub fn starts_with(&self, bs: &[u8]) -> bool {
        self.buffer.starts_with(bs)
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.buffer[..self.len].to_vec()
    }

    pub fn capacity(&self) -> usize {
        self.buffer.capacity()
    }

    pub fn as_mut_ptr(&mut self) -> *mut c_void {
        self.buffer.as_mut_ptr() as *mut c_void
    }

    pub fn push_slice(&mut self, slice: &[u8]) {
        unsafe {
            let dst = self.buffer.as_mut_ptr().add(self.buffer.len());
            ptr::copy_nonoverlapping(slice.as_ref().as_ptr(), dst, slice.len());
            self.buffer.set_len(self.buffer.len() + slice.len());
        }
    }
}

impl AsRef<[u8]> for Buffer {
    fn as_ref(&self) -> &[u8] {
        &self.buffer[..self.len]
    }
}

impl AsMut<[u8]> for Buffer {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buffer[self.len..]
    }
}

impl Index<RangeTo<usize>> for Buffer {
    type Output = [u8];
    fn index(&self, i: RangeTo<usize>) -> &[u8] {
        &self.buffer[..i.end]
    }
}

impl Index<RangeFrom<usize>> for Buffer {
    type Output = [u8];
    fn index(&self, i: RangeFrom<usize>) -> &[u8] {
        &self.buffer[i.start..self.len]
    }
}
