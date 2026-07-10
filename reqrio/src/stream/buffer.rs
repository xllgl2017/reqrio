use std::cmp::max;
use std::{ptr, slice};
use std::fmt::Debug;
use std::ops::Range;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
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
}

impl Default for RecordBuffer {
    fn default() -> Self {
        RecordBuffer {
            read_cursor: Arc::new(Default::default()),
            write_cursor: 0,
            last_record_end_pos: 0,
            buffer: Buffer::with_capacity(16438 * 2),
            unread_size: Arc::new(Default::default()),
        }
    }
}

impl RecordBuffer {
    pub fn new(buffer: Buffer) -> Self {
        RecordBuffer {
            read_cursor: Arc::new(AtomicUsize::new(0)),
            write_cursor: buffer.end(),
            unread_size: Arc::new(AtomicUsize::new(0)),
            last_record_end_pos: 0,
            buffer,
        }
    }


    //write<read, after moved
    fn write_less_read(&mut self, want: usize, current: usize, read_cursor: usize) -> Poll<&mut [u8]> {
        let remaining = read_cursor - self.last_record_end_pos;
        //判断buffer后半段在使用后有足够的空间
        if remaining > want {
            let size = max(want - current, remaining - current);
            let ptr = self.buffer.raw_ptr_mut();
            assert!(self.write_cursor + size <= self.buffer.capacity());
            Poll::Ready(unsafe { slice::from_raw_parts_mut(ptr.add(self.write_cursor), size) })
        } else {
            //后面数据已解析完成
            let remaining = self.buffer.capacity() - self.last_record_end_pos;
            let unread_size = self.unread_size.load(Ordering::SeqCst);
            if remaining >= want && unread_size == 0 {
                let size = max(want - current, remaining - current);
                let ptr = self.buffer.raw_ptr_mut();
                assert!(self.write_cursor + size <= self.buffer.capacity());
                Poll::Ready(unsafe { slice::from_raw_parts_mut(ptr.add(self.write_cursor), size) })
            } else {
                Poll::Pending
            }
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

    //read<write
    fn read_less_write(&mut self, want: usize, current: usize, read_cursor: usize) -> Poll<&mut [u8]> {
        let remaining = self.buffer.capacity() - self.last_record_end_pos;
        if remaining > want {
            let size = max(want - current, remaining - current);
            let ptr = self.buffer.raw_ptr_mut();
            assert!(self.write_cursor + size <= self.buffer.capacity());
            Poll::Ready(unsafe { slice::from_raw_parts_mut(ptr.add(self.write_cursor), size) })
        } else {
            if read_cursor < want { return Poll::Pending; }
            self.move_buffer();
            let size = max(want - current, read_cursor - current);
            let ptr = self.buffer.raw_ptr_mut();
            assert!(self.write_cursor + size <= self.buffer.capacity());
            Poll::Ready(unsafe { slice::from_raw_parts_mut(ptr.add(self.write_cursor), size) })
        }
    }

    fn start_eq_end(&mut self, want: usize, current: usize, unread_start_pos: usize) -> Poll<&mut [u8]> {
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
            assert!(self.write_cursor + size <= self.buffer.capacity());
            Poll::Ready(unsafe { slice::from_raw_parts_mut(ptr.add(self.write_cursor), size) })
        } else {
            self.write_less_read(want, current, unread_start_pos)
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
        assert!(self.last_record_end_pos + 5 <= self.buffer.capacity());
        unsafe { ptr.read_unaligned() }.to_be() as usize + 5
    }
    pub fn next_record_offset(&mut self, record_len: usize) -> Range<usize> {
        let res = self.last_record_end_pos..self.last_record_end_pos + record_len;
        self.last_record_end_pos += record_len;
        self.unread_size.fetch_add(record_len, Ordering::SeqCst);
        res
    }
    pub fn unfilled_mut(&mut self, want: usize, current: usize) -> Poll<&mut [u8]> {
        let read_cursor = self.read_cursor.load(Ordering::SeqCst);
        // println!("write_cursor: {}; read_cursor: {}; {}", self.write_cursor, read_cursor, self.unread_size.load(Ordering::SeqCst));
        if read_cursor < self.write_cursor {
            self.read_less_write(want, current, read_cursor)
        } else if self.write_cursor < read_cursor {
            self.write_less_read(want, current, read_cursor)
        } else {
            self.start_eq_end(want, current, read_cursor)
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
    pub fn new(offset: Range<usize>, buffer: &RecordBuffer, notify: Arc<Notify>) -> ReadOffset {
        ReadOffset {
            unread_start_pos: buffer.read_cursor.clone(),
            unread_size: buffer.unread_size.clone(),
            offset,
            notify,
            buffer: buffer.buffer.clone(),
        }
    }

    pub fn record_len(&self) -> usize {
        self.offset.len()
    }

    pub fn record(&self) -> &[u8] {
        println!("111111111111111");
        let ptr = self.buffer.raw_ptr();
        let res = unsafe { slice::from_raw_parts(ptr.add(self.offset.start), self.offset.len()) };
        println!("2222222222222222");
        return res;
    }

    pub fn release(&mut self) {
        self.unread_start_pos.store(self.offset.end, Ordering::SeqCst);
        self.unread_size.fetch_sub(self.offset.len(), Ordering::SeqCst);
        #[cfg(feature = "log")]
        trace!("release record: offset: {:?}; record_len: {}; data_len: {}", self.offset, self.offset.len(), self.offset.len() - 5);
        self.notify.notify_waiters();
    }
}