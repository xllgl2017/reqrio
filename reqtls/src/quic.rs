pub use super::message::{AckRange, QUICFrame, QUICFrameFlag, QUICPacket};
pub use super::extend::QUICParameter;
pub use crate::connection::QUICConnection;
pub use crate::error::QUICError;
use crate::{BufferError, PacketType, Reader, Writer};
use std::cmp::max;
use std::mem;
use std::ops::Range;
use std::time::{Duration, Instant};

pub fn read_variant(reader: &mut Reader) -> Result<usize, BufferError> {
    if reader.unread_len() == 0 { return Err(BufferError::Insufficient); }
    let flag = reader.current()?;
    match flag >> 6 {
        0b00 => Ok(reader.read_u8()? as usize),
        0b01 => Ok((reader.read_u16()? & 0x3FFF) as usize),
        0b10 => Ok((reader.read_u32()? & 0x3FFF_FFFF) as usize),
        0b11 => Ok((reader.read_u64()? & 0x3FFF_FFFF_FFFF_FFFF) as usize),
        _ => Err(BufferError::InvalidQUICVariant)
    }
}

pub fn variant_len(val: usize) -> usize {
    match val {
        ..0x40 => 1,
        0x40..0x4000 => 2,
        0x4000..0x4000_0000 => 4,
        0x4000_0000..0x4000_0000_0000_0000 => 8,
        _ => unreachable!()
    }
}


pub fn write_variant(val: usize, writer: &mut Writer) -> Result<(), BufferError> {
    match val {
        ..0x40 => writer.write_u8(val as u8),
        0x40..0x4000 => writer.write_u16(val as u16 | 0x4000),
        0x4000..0x4000_0000 => writer.write_u32(val as u32 | 0x8000_0000),
        0x4000_0000..0x4000_0000_0000_0000 => writer.write_u64(val as u64 | 0xc000_0000_0000_0000),
        _ => Err(BufferError::InvalidQUICVariant)
    }
}

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct QUICNum {
    value: u64,
    ///类型
    typ: PacketType,
    ///在哪个ack包中对改包进行了ack
    ack_nums: Vec<u64>,
    ///是否是缺失的
    missing: bool,
}
impl QUICNum {
    pub fn new(value: u64, typ: PacketType) -> QUICNum {
        QUICNum {
            value,
            typ,
            ack_nums: Vec::with_capacity(100),
            missing: false,
        }
    }

    pub fn new_missing(value: u64, typ: PacketType) -> QUICNum {
        QUICNum {
            value,
            typ,
            ack_nums: vec![],
            missing: true,
        }
    }
}

impl PartialEq for QUICNum {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value && self.missing == other.missing
    }
}

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct QUICRange {
    mapping: usize,
    pub ranges: Vec<QUICNum>,
    largest: u64,
    sent_largest: u64,
    last_sent: Instant,
    max_ack_delay: Duration,
}

impl Default for QUICRange {
    fn default() -> Self {
        QUICRange {
            mapping: 0,
            ranges: Vec::with_capacity(100),
            largest: 0,
            sent_largest: 0,
            last_sent: Instant::now(),
            max_ack_delay: Duration::from_millis(25),
        }
    }
}

impl QUICRange {
    pub fn insert(&mut self, num: QUICNum) {
        if self.ranges.contains(&num) { return; }
        let index = num.value as usize - self.mapping;
        match index >= self.ranges.len() {
            true => {
                for i in self.ranges.len()..index {
                    self.ranges.push(QUICNum::new_missing((self.mapping + i) as u64, num.typ));
                }
                self.ranges.push(num)
            }
            false => self.ranges[index] = num,
        }
    }

    pub fn ranges(&mut self, num: u64) -> Vec<Range<u64>> {
        let mut res = Vec::with_capacity(self.ranges.len());
        let first = self.ranges.iter().find(|x| !x.missing);
        let Some(mut current) = first.map(|x| x.value..x.value)else { return vec![] };
        for range in &mut self.ranges {
            range.ack_nums.push(num);
            if range.missing { continue; }
            self.largest = max(range.value, self.largest);
            if current.end + 1 == range.value {
                current.end += 1;
                continue;
            } else if current.end == range.value {
                continue
            } else {
                res.push(mem::replace(&mut current, range.value..range.value));
            }
        }
        res.push(current);
        self.last_sent = Instant::now();
        res
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty() || self.largest == self.sent_largest
    }

    pub fn clear(&mut self) {
        let range = &self.ranges[self.ranges.len() - 1];
        assert!(!range.missing);
        self.mapping = range.value as usize + 1;
        self.ranges.clear();
        self.last_sent = Instant::now();
    }

    pub fn remove(&mut self, num: u64) {
        self.ranges.retain(|x| !x.ack_nums.contains(&num));
        println!("remove:{} {}", num, self.ranges.len());
    }

    pub fn need_ack(&self) -> bool {
        //默认为25ms，目前先固定，后续可能有协商
        self.last_sent.elapsed() >= self.max_ack_delay
    }
}


#[cfg(test)]
mod test {
    use crate::PacketType;
    use crate::quic::{QUICNum, QUICRange};

    #[test]
    fn test_quic_range() {
        let mut range = QUICRange::default();
        for i in [14, 17, 18, 0, 1, 2, 3, 4, 5, 6, 7] {
            range.insert(QUICNum::new(i, PacketType::Initial));
        }
        assert_eq!(range.ranges(0), vec![0..7, 14..14, 17..18]);
        range.insert(QUICNum::new(15, PacketType::Initial));
        range.insert(QUICNum::new(16, PacketType::Initial));
        assert_eq!(range.ranges(1), vec![0..7, 14..18]);
        range.insert(QUICNum::new(13, PacketType::Initial));
        range.insert(QUICNum::new(12, PacketType::Initial));
        range.insert(QUICNum::new(11, PacketType::Initial));
        range.insert(QUICNum::new(10, PacketType::Initial));
        range.insert(QUICNum::new(9, PacketType::Initial));
        range.insert(QUICNum::new(8, PacketType::Initial));
        assert_eq!(range.ranges(2), vec![0..18]);

        range.clear();
        range.insert(QUICNum::new(20, PacketType::Handshake));
        assert_eq!(range.ranges(3), vec![20..20]);
    }
}



