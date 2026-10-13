use super::index::Index;
use super::table::Table;
use crate::error::HlsResult;
use crate::pack::error::PackError;
use crate::pack::{PackItem, huffman};
use crate::stream::StreamMessage;
use std::mem;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

pub struct HPackDecodeBuf<'a> {
    remain: Vec<u8>,
    buf: &'a [u8],
    //已读取的长度
    read: usize,
    //已使用的长度
    used: usize,
}

impl<'a> HPackDecodeBuf<'a> {
    pub fn new(remain: Vec<u8>, buf: &[u8]) -> HPackDecodeBuf<'_> {
        HPackDecodeBuf {
            remain,
            buf,
            read: 0,
            used: 0,
        }
    }
    pub fn into_vec(self) -> Vec<u8> {
        match self.used >= self.remain.len() {
            true => self.buf[self.used - self.remain.len()..].to_vec(),
            false => [&self.remain[self.used..], self.buf].concat()
        }
    }
    pub fn read(&mut self) -> Option<&u8> {
        let res = match self.read >= self.remain.len() {
            true => self.buf.get(self.read),
            false => self.remain.get(self.read),
        };
        if res.is_some() { self.read += 1; }
        res
    }

    pub fn read_size(&mut self, size: usize) -> Result<Vec<u8>, PackError> {
        if self.remain.len() + self.buf.len() - self.read < size { return Err(PackError::BufferTooSmall); };
        let res = match self.read >= self.remain.len() {
            true => self.buf[self.read - self.remain.len()..self.read - self.remain.len() + size].to_vec(),
            false => [&self.remain[self.read..], &self.buf[..self.read + size - self.remain.len()]].concat()
        };
        self.read += size;
        Ok(res)
    }

    pub fn flush(&mut self) {
        self.used = self.read;
    }

    pub fn is_empty(&self) -> bool {
        self.remain.len() + self.buf.len() - self.used == 0
    }
}

pub struct HPackDecode {
    table: Table,
    remain: Vec<u8>,
}

impl Default for HPackDecode {
    fn default() -> Self {
        HPackDecode::new(4096)
    }
}

impl HPackDecode {
    pub fn new(max_size: usize) -> Self {
        HPackDecode {
            table: Table::new(max_size),
            remain: vec![],
        }
    }

    pub fn decode_integer(&self, buf: &mut HPackDecodeBuf<'_>) -> Result<usize, PackError> {
        let mut res = 0;
        let mut shift = 0;
        loop {
            let byte = buf.read().ok_or(PackError::BufferTooSmall)?;
            res |= ((byte & 0b0111_1111) as usize) << shift;
            shift += 7;
            if byte >> 7 == 0 { break; }
        }
        Ok(res)
    }

    pub fn decode_index(&self, buf: &mut HPackDecodeBuf<'_>) -> Result<Index, PackError> {
        let (mut index, finish) = Index::read_index(buf)?;
        if !finish { index += self.decode_integer(buf)?; }
        Ok(index)
    }

    pub fn decode_string(&self, buf: &mut HPackDecodeBuf<'_>) -> Result<String, PackError> {
        let (mut index, finish) = Index::read_len(buf)?;
        if !finish { index += self.decode_integer(buf)? }
        if let Index::ValueLen { huffman, value } = index {
            let value = buf.read_size(value)?;
            match huffman {
                true => Ok(String::from_utf8(huffman::decode(value)?).or(Err(PackError::Currently("invild utf8 pack".to_string())))?),
                false => Ok(String::from_utf8(value).or(Err(PackError::Currently("invild utf8 pack".to_string())))?)
            }
        } else { Err(PackError::InvalidLenIndex) }
    }

    pub fn decode_next(&mut self, buf: &mut HPackDecodeBuf<'_>) -> Result<PackItem, PackError> {
        let index = self.decode_index(buf)?;
        let res = match index {
            Index::Indexed(index) => Ok(self.table.get(index - 1).ok_or(PackError::IndexedItemNone)?.clone()),
            Index::NoIndexAdd => {
                let name = self.decode_string(buf)?;
                let value = self.decode_string(buf)?;
                let item = PackItem::new(name, value);
                self.table.insert(item.clone());
                Ok(item)
            }
            Index::NoIndexOnce | Index::NoIndexNever => {
                let name = self.decode_string(buf)?;
                let value = self.decode_string(buf)?;
                let item = PackItem::new(name, value);
                Ok(item)
            }
            Index::NameIndexedAdd(index) => {
                let mut item = self.table.get(index - 1).ok_or(PackError::NameIndexedItemNone)?.clone();
                let value = self.decode_string(buf)?;
                item.set_value(value);
                self.table.insert(item.clone());
                Ok(item)
            }
            Index::NameIndexedOnce(index) | Index::NameIndexedNever(index) => {
                let mut item = self.table.get(index - 1).ok_or(PackError::NameIndexedItemNone)?.clone();
                let value = self.decode_string(buf)?;
                item.set_value(value);
                Ok(item)
            }
            Index::UpdateDynamicSize(index) => {
                self.table.update_table_size(index);
                Ok(PackItem::new_table_size(index))
            }
            _ => Err(PackError::InvalidIndexType(index.into_inner() as u8))
        };
        buf.flush();
        res
    }

    pub fn decode_into(&mut self, buf: &[u8], header: &mut StreamMessage) -> HlsResult<()> {
        let mut buf = HPackDecodeBuf {
            remain: mem::take(&mut self.remain),
            buf,
            read: 0,
            used: 0,
        };
        loop {
            if buf.is_empty() { break; }
            match self.decode_next(&mut buf) {
                Ok(item) => header.push_pack_item(&item)?,
                Err(e) => if e.to_string() == "buffer too small" {
                    self.remain = buf.into_vec();
                    break;
                }
            }
        }
        Ok(())
    }

    pub fn decode(&mut self, buf: &[u8]) -> HlsResult<Vec<PackItem>> {
        let mut buf = HPackDecodeBuf {
            remain: mem::take(&mut self.remain),
            buf,
            read: 0,
            used: 0,
        };
        let mut res = vec![];
        loop {
            if buf.is_empty() { break; }
            match self.decode_next(&mut buf) {
                Ok(item) => res.push(item),
                Err(e) => if e.to_string() == "buffer too small" {
                    self.remain = buf.into_vec();
                    break;
                }
            }
        }
        Ok(res)
    }

    pub fn update_table_size(&mut self, max_size: usize) {
        self.table.update_table_size(max_size);
    }

    pub fn table_size(&self) -> &Arc<AtomicUsize> {
        self.table.max_size()
    }
}


#[cfg(test)]
mod tests {
    use crate::pack::HPackDecode;
    use crate::pack::hpack::decode::HPackDecodeBuf;
    use crate::stream::StreamMessage;

    #[test]
    fn test_index_integer_decode() {
        let buffer = [161, 255, 107, 255, 131, 6, 255, 207, 245, 135, 32];
        let decode = HPackDecode::new(1024);
        let mut buf = HPackDecodeBuf { remain: vec![], buf: &buffer, read: 0, used: 0 };
        let index = decode.decode_index(&mut buf).unwrap();
        assert_eq!(index.into_inner(), 33);
        let index = decode.decode_index(&mut buf).unwrap();
        assert_eq!(index.into_inner(), 234);
        let index = decode.decode_index(&mut buf).unwrap();
        assert_eq!(index.into_inner(), 898);
        let index = decode.decode_index(&mut buf).unwrap();
        assert_eq!(index.into_inner(), 67238734);
        buf.flush();
        assert!(buf.into_vec().is_empty());

        let mut buf = HPackDecodeBuf { remain: vec![], buf: &[97, 127, 171, 1, 127, 195, 6, 127, 143, 246, 135, 32], read: 0, used: 0 };
        let index = decode.decode_index(&mut buf).unwrap();
        assert_eq!(index.into_inner(), 33);
        let index = decode.decode_index(&mut buf).unwrap();
        assert_eq!(index.into_inner(), 234);
        let index = decode.decode_index(&mut buf).unwrap();
        assert_eq!(index.into_inner(), 898);
        let index = decode.decode_index(&mut buf).unwrap();
        assert_eq!(index.into_inner(), 67238734);
        buf.flush();
        assert!(buf.into_vec().is_empty());

        let mut buf = HPackDecodeBuf { remain: vec![], buf: &[15, 18, 15, 219, 1, 15, 243, 6, 15, 191, 246, 135, 32], read: 0, used: 0 };
        let index = decode.decode_index(&mut buf).unwrap();
        assert_eq!(index.into_inner(), 33);
        let index = decode.decode_index(&mut buf).unwrap();
        assert_eq!(index.into_inner(), 234);
        let index = decode.decode_index(&mut buf).unwrap();
        assert_eq!(index.into_inner(), 898);
        let index = decode.decode_index(&mut buf).unwrap();
        assert_eq!(index.into_inner(), 67238734);
        buf.flush();
        assert!(buf.into_vec().is_empty());

        let mut buf = HPackDecodeBuf { remain: vec![], buf: &[0x3f, 0xe1, 0x1f], read: 0, used: 0 };
        let index = decode.decode_index(&mut buf).unwrap();
        assert_eq!(index.into_inner(), 4096)
    }

    #[test]
    fn test_decode_string() {
        let mut buf = HPackDecodeBuf { remain: vec![], buf: &[130, 148, 231], read: 0, used: 0 };
        let decode = HPackDecode::new(1024);
        //huffman
        let value = decode.decode_string(&mut buf).unwrap();
        assert_eq!(value, "foo");
        let mut buf = HPackDecodeBuf { remain: vec![], buf: &[6, 68, 69, 76, 69, 84, 69], read: 0, used: 0 };
        let value = decode.decode_string(&mut buf).unwrap();
        assert_eq!(value, "DELETE");
        buf.flush();
        assert!(buf.into_vec().is_empty());
    }

    #[test]
    fn test_hpack_decode() {
        let mut decode = HPackDecode::new(1024);
        let mut resp = StreamMessage::new(0);
        decode.decode_into(&[130, 64, 134, 168, 190, 20, 168, 116, 151, 136, 168, 190, 20, 66, 108, 53, 83, 127], &mut resp).unwrap();
        assert_eq!(resp.header.to_string(), ":method: GET\r\nnew name: new string");
        let mut decode = HPackDecode::new(1024);
        let mut resp = StreamMessage::new(0);
        decode.decode_into(&[66, 6, 68, 69, 76, 69, 84, 69], &mut resp).unwrap();
        assert_eq!(resp.header.to_string(), ":method: DELETE")
    }
}