use std::cmp::max;
use std::{ptr, slice};
use std::fmt::Debug;
use std::ops::Range;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Notify;
use reqtls::{Buffer, WriteExt};
#[cfg(feature = "log")]
use crate::trace;

pub struct RecordBuffer {
    read_cursor: Arc<AtomicUsize>,
    write_cursor: usize,
    last_record_end_pos: usize,
    buffer: Buffer,
    unread_size: Arc<AtomicUsize>,
    notify: Arc<Notify>,
}

impl Default for RecordBuffer {
    fn default() -> Self {
        RecordBuffer {
            read_cursor: Arc::new(Default::default()),
            write_cursor: 0,
            last_record_end_pos: 0,
            buffer: Buffer::with_capacity(16438 * 2),
            unread_size: Arc::new(Default::default()),
            notify: Arc::new(Default::default()),
        }
    }
}

impl RecordBuffer {
    //end_pos<start_post, after moved
    async fn end_less_start(&mut self, want: usize, current: usize, mut unread_start_pos: usize) -> &mut [u8] {
        //判断buffer后半段在使用后有足够的空间
        if self.buffer.capacity() - self.last_record_end_pos > want {
            let mut unused = unread_start_pos - self.last_record_end_pos;
            while unused < want {
                self.notify.notified().await;
                unread_start_pos = self.read_cursor.load(Ordering::SeqCst);
                if unread_start_pos < self.last_record_end_pos {
                    unused = self.buffer.capacity() - self.last_record_end_pos;
                    assert!(want < unused)
                } else if unread_start_pos == self.last_record_end_pos {
                    let res = Box::pin(self.start_eq_end(want, current, unread_start_pos)).await;
                    return res;
                } else {
                    unused = unread_start_pos - self.last_record_end_pos;
                }
            }
            let size = max(want - current, unused - current);
            let ptr = self.buffer.raw_ptr_mut();
            unsafe { slice::from_raw_parts_mut(ptr.add(self.write_cursor), size) }
        } else {
            while unread_start_pos > self.last_record_end_pos || unread_start_pos < want {
                self.notify.notified().await;
                unread_start_pos = self.read_cursor.load(Ordering::SeqCst);
            }
            self.move_buffer();
            let size = max(want - current, unread_start_pos - current);
            let ptr = self.buffer.raw_ptr_mut();
            unsafe { slice::from_raw_parts_mut(ptr.add(self.write_cursor), size) }
        }
    }


    fn move_buffer(&mut self) {
        self.write_cursor -= self.last_record_end_pos;
        //判断buffer后半段，若有数据需要把数据复制到前面
        if self.write_cursor > 0 {
            unsafe {
                let src = self.buffer.raw_ptr().add(self.last_record_end_pos);
                let dst = self.buffer.raw_ptr_mut();
                ptr::copy(src, dst, self.write_cursor);
            }
        }
        self.last_record_end_pos = 0;
    }

    //start_pos > end_pos
    async fn start_less_end(&mut self, want: usize, current: usize, mut unread_start_pos: usize) -> &mut [u8] {
        let can_used = self.buffer.capacity() - self.last_record_end_pos;
        if can_used > want {
            let size = max(want - current, can_used - current);
            let ptr = self.buffer.raw_ptr_mut();
            unsafe { slice::from_raw_parts_mut(ptr.add(self.write_cursor), size) }
        } else {
            //判断buffer前半段是否有足够空间，没有的话等待释放
            while unread_start_pos < want {
                self.notify.notified().await;
                unread_start_pos = self.read_cursor.load(Ordering::SeqCst);
            }
            self.move_buffer();
            let size = max(want - current, unread_start_pos - current);
            let ptr = self.buffer.raw_ptr_mut();
            unsafe { slice::from_raw_parts_mut(ptr.add(self.write_cursor), size) }
        }
    }

    async fn start_eq_end(&mut self, want: usize, current: usize, unread_start_pos: usize) -> &mut [u8] {
        if self.unread_size.load(Ordering::SeqCst) == 0 {
            let mut unused = self.buffer.capacity() - self.last_record_end_pos;
            if unused < want {
                self.move_buffer();
                self.read_cursor.store(0, Ordering::SeqCst);
                unused = self.buffer.capacity() - self.last_record_end_pos;
                assert!(want <= unused);
            }
            let ptr = self.buffer.raw_ptr_mut();
            let size = max(want - current, unused - current);
            unsafe { slice::from_raw_parts_mut(ptr.add(self.write_cursor), size) }
        } else {
            self.end_less_start(want, current, unread_start_pos).await
        }
    }

    pub fn current_size(&self) -> usize {
        self.write_cursor - self.last_record_end_pos
    }
    pub fn add_filled(&mut self, size: usize) {
        self.write_cursor += size;
        assert!(self.write_cursor <= self.buffer.capacity())
    }
    pub fn next_record_len(&self) -> usize {
        let ptr = unsafe { self.buffer.raw_ptr().add(self.last_record_end_pos + 3) } as *const u16;
        unsafe { ptr.read_unaligned() }.to_be() as usize + 5
    }
    pub fn next_record_offset(&mut self, record_len: usize) -> Range<usize> {
        let res = self.last_record_end_pos..self.last_record_end_pos + record_len;
        self.last_record_end_pos += record_len;
        self.unread_size.fetch_add(record_len, Ordering::SeqCst);
        res
    }
    pub async fn unfilled_mut(&mut self, want: usize, current: usize) -> &mut [u8] {
        let unread_start_pos = self.read_cursor.load(Ordering::SeqCst);
        if self.write_cursor > unread_start_pos {
            self.start_less_end(want, current, unread_start_pos).await
        } else if self.write_cursor < unread_start_pos {
            self.end_less_start(want, current, unread_start_pos).await
        } else {
            self.start_eq_end(want, current, unread_start_pos).await
        }
    }
}

pub struct ReadOffset {
    unread_start_pos: Arc<AtomicUsize>,
    unread_size: Arc<AtomicUsize>,
    offset: Range<usize>,
    notify: Arc<Notify>,
    buffer: Buffer,
}

impl Debug for ReadOffset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.offset)
    }
}

impl ReadOffset {
    pub fn new(offset: Range<usize>, buffer: &RecordBuffer) -> ReadOffset {
        ReadOffset {
            unread_start_pos: buffer.read_cursor.clone(),
            unread_size: buffer.unread_size.clone(),
            offset,
            notify: buffer.notify.clone(),
            buffer: buffer.buffer.clone(),
        }
    }
    pub fn record(&self) -> &[u8] {
        let ptr = self.buffer.raw_ptr();
        unsafe { slice::from_raw_parts(ptr.add(self.offset.start), self.offset.len()) }
    }

    pub fn release(&mut self) {
        self.unread_start_pos.store(self.offset.end, Ordering::SeqCst);
        self.unread_size.fetch_sub(self.offset.len(), Ordering::SeqCst);
        #[cfg(feature = "log")]
        trace!("release record: offset: {:?}; record_len: {}; data_len: {}", self.offset, self.offset.len(), self.offset.len() - 5);
        self.notify.notify_waiters();
    }
}