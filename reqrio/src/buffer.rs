use crate::error::{HlsResult, HlsError};
use std::ffi::c_void;
use std::io::Read;
use std::ops::{Index, IndexMut, Range, RangeFrom, RangeFull, RangeTo};
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
    pub async fn async_read<S: AsyncReadExt + Unpin>(&mut self, stream: &mut S) -> HlsResult<()> {
        self.async_read_limit(stream, self.buffer.capacity() - self.len).await
    }

    #[cfg(feature = "tokio")]
    pub async fn async_read_limit<S: AsyncReadExt + Unpin>(&mut self, stream: &mut S, limit: usize) -> HlsResult<()> {
        let len = stream.read(&mut self.buffer[self.len..self.len + limit]).await?;
        if len == 0 { return Err(HlsError::PeerClosedConnection); }
        self.len += len;
        Ok(())
    }

    pub fn sync_read<S: Read>(&mut self, stream: &mut S) -> HlsResult<()> {
        self.sync_read_limit(stream, self.buffer.capacity() - self.len)
    }

    pub fn sync_read_limit<S: Read>(&mut self, stream: &mut S, limit: usize) -> HlsResult<()> {
        let len = stream.read(&mut self.buffer[self.len..self.len + limit])?;
        if len == 0 { return Err(HlsError::PeerClosedConnection); }
        self.len += len;
        Ok(())
    }

    pub fn reset(&mut self) {
        self.len = 0;
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
            let dst = self.buffer.as_mut_ptr().add(self.len);
            ptr::copy_nonoverlapping(slice.as_ref().as_ptr(), dst, slice.len());
            self.buffer.set_len(self.len + slice.len());
            self.len += slice.len();
        }
    }

    ///必须手动管理len, 返回已push的长度
    #[must_use]
    pub fn push_slice_in(&mut self, place: usize, slice: &[u8]) -> usize {
        unsafe {
            let dst = self.buffer.as_mut_ptr().add(place);
            ptr::copy_nonoverlapping(slice.as_ref().as_ptr(), dst, slice.len());
        }
        slice.len()
    }

    pub fn filled(&self) -> &[u8] {
        &self.buffer[..self.len]
    }

    pub fn filled_mut(&mut self) -> &mut [u8] {
        &mut self.buffer[..self.len]
    }

    pub fn unfilled_mut(&mut self) -> &mut [u8] {
        &mut self.buffer[self.len..]
    }

    pub fn copy_within(&mut self, r: Range<usize>, pos: usize) {
        self.buffer.copy_within(r,pos);
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

impl Index<Range<usize>> for Buffer {
    type Output = [u8];
    fn index(&self, i: Range<usize>) -> &[u8] {
        &self.buffer[i]
    }
}

impl IndexMut<RangeTo<usize>> for Buffer {
    fn index_mut(&mut self, i: RangeTo<usize>) -> &mut [u8] {
        &mut self.buffer[i]
    }
}

impl IndexMut<RangeFrom<usize>> for Buffer {
    fn index_mut(&mut self, i: RangeFrom<usize>) -> &mut [u8] {
        &mut self.buffer[i]
    }
}

impl IndexMut<Range<usize>> for Buffer {
    fn index_mut(&mut self, i: Range<usize>) -> &mut [u8] {
        &mut self.buffer[i]
    }
}

impl Index<usize> for Buffer {
    type Output = u8;
    fn index(&self, i: usize) -> &u8 {
        &self.buffer[i]
    }
}

impl Index<RangeFull> for Buffer {
    type Output = [u8];
    fn index(&self, i: RangeFull) -> &[u8] {
        &self.buffer[i]
    }
}

impl IndexMut<RangeFull> for Buffer {
    fn index_mut(&mut self, i: RangeFull) -> &mut [u8] {
        &mut self.buffer[i]
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        self.buffer.clear();
        self.buffer.shrink_to_fit();
    }
}