use super::index::Index;
use super::table::Table;
use crate::pack::{huffman, PackItem};
use reqtls::{BufferError, Writer};
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

pub struct HPackEncode {
    table: Table,
}

impl Default for HPackEncode {
    fn default() -> Self {
        HPackEncode::new(4096)
    }
}

impl HPackEncode {
    pub fn new(max_table_size: usize) -> Self {
        HPackEncode {
            table: Table::new(max_table_size),
        }
    }

    fn encode_index(&self, index: impl AsRef<Index>, writer: &mut Writer) -> Result<(), BufferError> {
        let index = index.as_ref();
        let finish = index.write_to(writer)?;
        if finish { return Ok(()); }
        super::super::encode_integer(writer, index.remain())
    }

    fn encode_string(&self, value: impl AsRef<[u8]>, writer: &mut Writer) -> Result<(), BufferError> {
        let huffman_encoded = huffman::encode(value.as_ref());
        let huffman = huffman_encoded.len() < value.as_ref().len();
        let value = if huffman { huffman_encoded.as_slice() } else { value.as_ref() };
        let index = Index::ValueLen { huffman, value: value.len() };
        let finish = index.write_to(writer)?;
        if !finish { super::super::encode_integer(writer, index.remain())?; }
        writer.write_slice(value.as_ref())
    }

    pub fn encode_one(&mut self, name: impl AsRef<str>, value: impl AsRef<str>, writer: &mut Writer) -> Result<(), BufferError> {
        let name = name.as_ref();
        let value = value.as_ref();
        let item = self.table.get_by_name_value(name, value);
        let index_excludes = [":path"];
        match item {
            None => match self.table.get_by_name(name) {
                None => {
                    let index = if name.contains("password") {
                        Index::NoIndexNever
                    } else { Index::NoIndexAdd };
                    self.encode_index(index, writer)?;
                    self.encode_string(name, writer)?;
                    self.encode_string(value, writer)?;
                    let item = PackItem::new(name.to_string(), value.to_string());
                    self.table.insert(item);
                    Ok(())
                }
                Some(index) => {
                    let vl = value.to_ascii_lowercase();
                    let index = if index_excludes.contains(&name) {
                        Index::NameIndexedOnce(index.into_inner())
                    } else if (name == "cookie" && (value.starts_with("_") || vl.contains("session") || vl.contains("auth"))) || name == "password" {
                        Index::NameIndexedNever(index.into_inner())
                    } else { index };
                    self.encode_index(&index, writer)?;
                    self.encode_string(value, writer)?;
                    if let Index::NameIndexedAdd(_) = index {
                        let item = PackItem::new(name.to_string(), value.to_string());
                        self.table.insert(item);
                    }
                    Ok(())
                }
            }
            Some(index) => self.encode_index(index, writer),
        }
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
    use crate::pack::hpack::index::Index;
    use crate::pack::HPackEncode;
    use crate::Writer;

    #[test]
    fn test_index_encode() {
        let encoder = HPackEncode::default();
        //test-indexed
        let mut buffer = Writer::with_capacity(1024);
        encoder.encode_index(Index::Indexed(33), &mut buffer).unwrap();
        encoder.encode_index(Index::Indexed(234), &mut buffer).unwrap();
        encoder.encode_index(Index::Indexed(898), &mut buffer).unwrap();
        encoder.encode_index(Index::Indexed(67238734), &mut buffer).unwrap();
        assert_eq!(buffer.filled(), [161, 255, 107, 255, 131, 6, 255, 207, 245, 135, 32]);
        buffer.reset();
        //test-name-indexed
        encoder.encode_index(Index::NameIndexedAdd(33), &mut buffer).unwrap();
        encoder.encode_index(Index::NameIndexedAdd(234), &mut buffer).unwrap();
        encoder.encode_index(Index::NameIndexedAdd(898), &mut buffer).unwrap();
        encoder.encode_index(Index::NameIndexedAdd(67238734), &mut buffer).unwrap();
        assert_eq!(buffer.filled(), [97, 127, 171, 1, 127, 195, 6, 127, 143, 246, 135, 32]);
        buffer.reset();
        //test-name-indexed-never
        encoder.encode_index(Index::NameIndexedOnce(33), &mut buffer).unwrap();
        encoder.encode_index(Index::NameIndexedOnce(234), &mut buffer).unwrap();
        encoder.encode_index(Index::NameIndexedOnce(898), &mut buffer).unwrap();
        encoder.encode_index(Index::NameIndexedOnce(67238734), &mut buffer).unwrap();
        assert_eq!(buffer.filled(), [15, 18, 15, 219, 1, 15, 243, 6, 15, 191, 246, 135, 32])
    }

    #[test]
    fn test_string_encode() {
        let encoder = HPackEncode::default();
        let mut buffer = Writer::with_capacity(1024);
        encoder.encode_string("foo".as_bytes(), &mut buffer).unwrap();
        assert_eq!(buffer.filled(), [130, 148, 231]);
        buffer.reset();
        encoder.encode_string("foo".as_bytes(), &mut buffer).unwrap();
        assert_eq!(buffer.filled(), [130, 148, 231]);
    }

    #[test]
    fn test_hpack_encode() {
        let mut buffer = Writer::with_capacity(1024);
        let mut encode = HPackEncode::default();
        //static table indexed
        encode.encode_one(":method", "GET", &mut buffer).unwrap();
        assert_eq!(buffer.filled(), [130]);
        buffer.reset();
        //name indexed
        encode.encode_one(":method", "DELETE", &mut buffer).unwrap(); //not used huffman
        assert_eq!(buffer.filled(), [66, 6, 68, 69, 76, 69, 84, 69]);
        buffer.reset();
        //dynamic indexed
        encode.encode_one(":method", "DELETE", &mut buffer).unwrap();
        assert_eq!(buffer.filled(), [190]);
        buffer.reset();
        encode.encode_one("new name", "new string", &mut buffer).unwrap();
        assert_eq!(buffer.filled(), [64, 134, 168, 190, 20, 168, 116, 151, 136, 168, 190, 20, 66, 108, 53, 83, 127]);
    }
}