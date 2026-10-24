use super::decode::HPackDecodeBuf;
use crate::pack::PackError;
use reqtls::{BufferError, Writer};
use std::ops::AddAssign;

pub enum Index {
    /// Both the name and value are found in the table.
    /// ```text
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 1 |        Index (7+)         |
    /// +---+---------------------------+
    /// ```
    Indexed(usize),
    /// Neither the name nor the value exists in the encode/decode table; it should be appended to the dynamic table.
    /// ```text
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 1 |           0           |
    /// +---+---+-----------------------+
    /// | H |     Name Length (7+)      |
    /// +---+---------------------------+
    /// |          Name String          |
    /// +---+---------------------------+
    /// | H |     Value Length (7+)     |
    /// +---+---------------------------+
    /// |          Value String         |
    /// +-------------------------------+
    /// ```
    NoIndexAdd,
    /// Neither the name nor the value exists in the encode/decode table; it should not be appended to the dynamic table.
    /// ```text
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 0 | 0 | 0 |       0       |
    /// +---+---+-----------------------+
    /// | H |     Name Length (7+)      |
    /// +---+---------------------------+
    /// |         Name String           |
    /// +---+---------------------------+
    /// | H |     Value Length (7+)     |
    /// +---+---------------------------+
    /// |         Value String          |
    /// +-------------------------------+
    /// ```
    NoIndexOnce,
    /// Neither the name nor the value exists in the encode/decode table; it is not added to the dynamic table.
    /// ```text
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 0 | 0 | 1 |       0       |
    /// +---+---+-----------------------+
    /// | H |     Name Length (7+)      |
    /// +---+---------------------------+
    /// |         Name String           |
    /// +---+---------------------------+
    /// | H |     Value Length (7+)     |
    /// +---+---------------------------+
    /// |         Value String          |
    /// +-------------------------------+
    /// ```
    NoIndexNever,
    /// * The name exists in the encode/decode table but the value does not; it should be appended to the dynamic table.
    /// ```text
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 1 |      Index (6+)       |
    /// +---+---+-----------------------+
    /// | H |     Value Length (7+)     |
    /// +---+---------------------------+
    /// |         Value String          |
    /// +-------------------------------+
    /// ```
    NameIndexedAdd(usize),
    /// * The name exists in the encode/decode table but the value does not; it should not be appended to the dynamic table.
    /// ```text
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 0 | 0 | 0 |  Index (4+)   |
    /// +---+---+-----------------------+
    /// | H |     Value Length (7+)     |
    /// +---+---------------------------+
    /// |         Value String          |
    /// +-------------------------------+
    /// ```
    NameIndexedOnce(usize),
    /// * The name exists in the encode/decode table but the value does not; it is not added to the dynamic table.
    /// ```text
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 0 | 0 | 1 |  Index (4+)   |
    /// +---+---+-----------------------+
    /// | H |     Value Length (7+)     |
    /// +---+---------------------------+
    /// |         Value String          |
    /// +-------------------------------+
    /// ```
    NameIndexedNever(usize),
    /// * Dynamic table size update
    /// ```text
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 0 | 1 |   Max size (5+)   |
    /// +---+---------------------------+
    /// ```
    UpdateDynamicSize(usize),
    ValueLen { huffman: bool, value: usize },
}

impl Index {
    ///* The maximum value of `Index` is `2^N - 1`.
    /// ```text
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | ? | ? | ? |       Value       |
    /// +---+---+---+-------------------+
    /// ```
    /// Here `N` is 5.
    fn max_value(&self) -> u8 {
        match self {
            Index::Indexed(_) => 2i32.pow(7) as u8 - 1,
            Index::NoIndexAdd => 0,
            Index::NoIndexOnce => 0,
            Index::NoIndexNever => 0,
            Index::NameIndexedAdd(_) => 2i32.pow(6) as u8 - 1,
            Index::NameIndexedOnce(_) => 2i32.pow(4) as u8 - 1,
            Index::NameIndexedNever(_) => 2i32.pow(4) as u8 - 1,
            Index::UpdateDynamicSize(_) => 2i32.pow(5) as u8 - 1,
            Index::ValueLen { .. } => 2i32.pow(7) as u8 - 1,
        }
    }

    pub fn remain(&self) -> usize {
        match self {
            Index::Indexed(v) => *v - self.max_value() as usize,
            Index::NoIndexAdd => 0,
            Index::NoIndexOnce => 0,
            Index::NoIndexNever => 0,
            Index::NameIndexedAdd(v) => *v - self.max_value() as usize,
            Index::NameIndexedOnce(v) => *v - self.max_value() as usize,
            Index::NameIndexedNever(v) => *v - self.max_value() as usize,
            Index::UpdateDynamicSize(v) => *v - self.max_value() as usize,
            Index::ValueLen { value, .. } => *value - self.max_value() as usize,
        }
    }

    pub fn write_to(&self, writer: &mut Writer) -> Result<bool, BufferError> {
        match self {
            Index::Indexed(v) => {
                let max = self.max_value();
                match *v >= max as usize {
                    true => {
                        writer.write_u8(0b1000_0000 | max)?;
                        Ok(false)
                    }
                    false => {
                        writer.write_u8(0b1000_0000 | *v as u8)?;
                        Ok(true)
                    }
                }
            }
            Index::NoIndexAdd => {
                writer.write_u8(0b0100_0000)?;
                Ok(true)
            }
            Index::NoIndexOnce => {
                writer.write_u8(0)?;
                Ok(true)
            }
            Index::NoIndexNever => {
                writer.write_u8(0b0001_0000)?;
                Ok(true)
            }
            Index::NameIndexedAdd(v) => {
                let max = self.max_value();
                match *v >= max as usize {
                    true => {
                        writer.write_u8(0b0100_0000 | max)?;
                        Ok(false)
                    }
                    false => {
                        writer.write_u8(0b0100_0000 | *v as u8)?;
                        Ok(true)
                    }
                }
            }
            Index::NameIndexedOnce(v) => {
                let max = self.max_value();
                match *v >= max as usize {
                    true => {
                        writer.write_u8(max)?;
                        Ok(false)
                    }
                    false => {
                        writer.write_u8(*v as u8)?;
                        Ok(true)
                    }
                }
            }
            Index::NameIndexedNever(v) => {
                let max = self.max_value();
                match *v >= max as usize {
                    true => {
                        writer.write_u8(0b0001_0000 | max)?;
                        Ok(false)
                    }
                    false => {
                        writer.write_u8(0b0001_0000 | *v as u8)?;
                        Ok(true)
                    }
                }
            }
            Index::UpdateDynamicSize(v) => {
                let max = self.max_value();
                match *v >= max as usize {
                    true => {
                        writer.write_u8(0b0010_0000 | max)?;
                        Ok(false)
                    }
                    false => {
                        writer.write_u8(0b0010_0000 | *v as u8)?;
                        Ok(true)
                    }
                }
            }
            Index::ValueLen { huffman, value } => {
                let max = self.max_value();
                match *value >= max as usize {
                    true => {
                        writer.write_u8(if *huffman { 0b1000_0000 } else { 0b0000_0000 } | max)?;
                        Ok(false)
                    }
                    false => {
                        writer.write_u8(if *huffman { 0b1000_0000 } else { 0b0000_0000 } | *value as u8)?;
                        Ok(true)
                    }
                }
            }
        }
    }

    pub fn into_inner(self) -> usize {
        match self {
            Index::Indexed(v) => v,
            Index::NoIndexAdd => 0,
            Index::NoIndexOnce => 0,
            Index::NoIndexNever => 0,
            Index::NameIndexedAdd(v) => v,
            Index::NameIndexedOnce(v) => v,
            Index::NameIndexedNever(v) => v,
            Index::UpdateDynamicSize(v) => v,
            Index::ValueLen { value, .. } => value,
        }
    }

    pub fn inner(&self) -> usize {
        match self {
            Index::Indexed(v) => *v,
            Index::NoIndexAdd => 0,
            Index::NoIndexOnce => 0,
            Index::NoIndexNever => 0,
            Index::NameIndexedAdd(v) => *v,
            Index::NameIndexedOnce(v) => *v,
            Index::NameIndexedNever(v) => *v,
            Index::UpdateDynamicSize(v) => *v,
            Index::ValueLen { value, .. } => *value,
        }
    }

    pub fn read_index(buf: &mut HPackDecodeBuf<'_>) -> Result<(Self, bool), PackError> {
        let byte = buf.read().ok_or(PackError::BufferTooSmall)?;
        if byte & 0b1000_0000 == 0b1000_0000 { //indexed
            let value = (byte & 0b0111_1111) as usize;
            Ok((Index::Indexed(value), value != 0b0111_1111))
        } else if byte & 0b0100_0000 == 0b0100_0000 {
            let value = (byte & 0b0011_1111) as usize;
            match value {
                0 => Ok((Index::NoIndexAdd, true)),
                _ => Ok((Index::NameIndexedAdd(value), value != 0b0011_1111)),
            }
        } else if byte & 0b0010_0000 == 0b0010_0000 {
            let value = (byte & 0b0001_1111) as usize;
            Ok((Index::UpdateDynamicSize(value), value != 0b0001_1111))
        } else if byte & 0b0001_0000 == 0b0001_0000 {
            let value = (byte & 0b0000_1111) as usize;
            match value {
                0 => Ok((Index::NoIndexNever, true)),
                _ => Ok((Index::NameIndexedNever(value), value != 0b0000_1111)),
            }
        } else if byte >> 4 == 0 {
            let value = (byte & 0b0000_1111) as usize;
            match value {
                0 => Ok((Index::NoIndexOnce, true)),
                _ => Ok((Index::NameIndexedOnce(value), value != 0b0000_1111)),
            }
        } else { Err(PackError::InvalidIndexType(*byte)) }
    }

    pub fn read_len(buf: &mut HPackDecodeBuf<'_>) -> Result<(Index, bool), PackError> {
        let byte = buf.read().ok_or(PackError::BufferTooSmall)?;
        let value = (byte & 0b0111_1111) as usize;
        Ok((Index::ValueLen { huffman: byte & 0b1000_0000 == 0b1000_0000, value }, value != 0b0111_1111))
    }
}

impl AsRef<Index> for Index {
    fn as_ref(&self) -> &Index {
        self
    }
}

impl AddAssign<usize> for Index {
    fn add_assign(&mut self, rhs: usize) {
        match self {
            Index::Indexed(v) => *v += rhs,
            Index::NoIndexAdd => {}
            Index::NoIndexOnce => {}
            Index::NoIndexNever => {}
            Index::NameIndexedAdd(v) => *v += rhs,
            Index::NameIndexedOnce(v) => *v += rhs,
            Index::NameIndexedNever(v) => *v += rhs,
            Index::UpdateDynamicSize(v) => *v += rhs,
            Index::ValueLen { value, .. } => *value += rhs,
        }
    }
}