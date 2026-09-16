pub use super::message::{AckRange, QUICFrame, QUICFrameFlag, QUICPacket};
pub use crate::connection::QUICConnection;
pub use crate::error::QUICError;
use crate::{BufferError, Reader, Writer};
use std::cmp::max;
use std::ops::Range;

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


#[derive(Debug)]
pub struct QUICRange {
    ranges: Vec<Range<u64>>,
    largest: u64,
    sent_largest: u64,
    need_ack: bool,
}

impl Default for QUICRange {
    fn default() -> Self {
        QUICRange {
            ranges: Vec::with_capacity(100),
            largest: 0,
            sent_largest: 0,
            need_ack: false,
        }
    }
}

impl QUICRange {
    pub fn insert(&mut self, num: u64) {
        let pos = self.ranges.iter_mut().position(|r| r.start == num + 1 || r.end + 1 == num);
        if let Some(pos) = pos {
            let range = &mut self.ranges[pos];
            if range.start == num + 1 {
                range.start = num;
                let opos = self.ranges.iter_mut().position(|r| r.end + 1 == num);
                if let Some(opos) = opos {
                    self.ranges[opos].end = self.ranges[pos].end;
                    self.ranges.remove(pos);
                }
            } else {
                range.end = num;
                let opos = self.ranges.iter().position(|r| num + 1 == r.start);
                if let Some(opos) = opos {
                    self.ranges[pos].end = self.ranges[opos].end;
                    self.ranges.remove(opos);
                }
            }
        } else { self.ranges.push(num..num) }
        self.largest = max(self.largest, num)
    }

    pub fn sort(&mut self) {
        self.ranges.sort_by_key(|a| a.start);
    }

    pub fn get(&self, index: usize) -> &Range<u64> {
        &self.ranges[index]
    }


    pub fn max_range(&self) -> Option<&Range<u64>> {
        self.ranges.iter().find(|r| r.end == self.largest)
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty() || self.largest == self.sent_largest
    }

    pub fn count(&self) -> usize {
        self.ranges.len()
    }

    pub fn clear(&mut self) {
        let max = if let Some(max) = self.max_range() {
            max.end..max.end
        } else { 0..0 };
        self.ranges.clear();
        self.ranges.push(max)
    }

    pub fn reset_sent_largest(&mut self) {
        self.sent_largest = self.largest;
    }

    pub fn set_ack(&mut self, ack: bool) {
        self.need_ack = ack;
    }
    
    pub fn need_ack(&self) -> bool {
        self.need_ack
    }
}


#[cfg(test)]
mod test {
    use crate::quic::QUICRange;

    #[test]
    fn test_quic_range() {
        let mut range = QUICRange::default();
        for i in [14, 17, 18, 0, 1, 2, 3, 4, 5, 6, 7] {
            range.insert(i);
        }
        range.sort();
        assert_eq!(range.ranges, vec![0..7, 14..14, 17..18]);
        range.insert(15);
        range.insert(16);
        assert_eq!(range.ranges, vec![0..7, 14..18]);
        range.insert(13);
        range.insert(12);
        range.insert(11);
        range.insert(10);
        range.insert(9);
        range.insert(8);
        assert_eq!(range.ranges, vec![0..18]);
    }
}



