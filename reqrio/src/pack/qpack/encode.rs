use super::index::Index;
use super::table::Table;
use super::QPackType;
use crate::pack::{huffman, PackItem};
use reqtls::{BufferError, Writer};

pub struct QPackEncode {
    table: Table,
    huffman: bool,
    base: usize,
}

impl QPackEncode {
    pub fn new(max_size: usize) -> QPackEncode {
        QPackEncode {
            table: Table::new(max_size),
            huffman: false,
            base: 0,
        }
    }

    pub fn set_huffman(&mut self, huffman: bool) {
        self.huffman = huffman;
    }

    pub fn set_base(&mut self, base: usize) {
        self.base = base;
    }

    pub fn encode_head(&mut self, writer: &mut Writer) -> Result<(), BufferError> {
        let delta_base = if self.base < self.table.dynamic_table().item_count() {
            self.table.dynamic_table().item_count() - self.base - 1
        } else { self.base - self.table.dynamic_table().item_count() };
        let index = Index::EncodedHead {
            req_enc_count: self.table.dynamic_table().en_req_count(),
            delta_base,
            sign: self.base < self.table.dynamic_table().item_count(),
        };
        index.write_to(writer)
    }
    fn encode_literal(&mut self, value: &str, writer: &mut Writer) -> Result<(), BufferError> {
        let value_len = if value.len() >= 0x7F { 0x7F } else { value.len() };
        //使用huffman编码
        writer.write_u8(value_len as u8 | if self.huffman { 0x80 } else { 0 })?;
        if value_len == 0x7F { super::super::encode_integer(writer, value.len() - value_len)? };
        match self.huffman {
            true => writer.write_slice(&huffman::encode(value.as_bytes())),
            false => writer.write_slice(value.as_bytes())
        }
    }

    pub fn encode_one(&mut self, typ: QPackType, name: impl AsRef<str>, value: impl AsRef<str>, sid: &u64, writer: &mut Writer) -> Result<(), BufferError> {
        let name = name.as_ref();
        let value = value.as_ref();
        let item = self.table.get_by_name_value(name, value, sid, true);
        match item {
            None => match self.table.get_by_name(name, typ) {
                Some((index, item)) => {
                    if matches!(index, Index::IndexedName {..}) {
                        let mut item = item.clone();
                        item.set_value(value.to_string());
                        self.table.insert(item, sid, false);
                    }
                    index.write_to(writer)?;
                    self.encode_literal(value, writer)?;
                    Ok(())
                }
                None => {
                    let (index, req_insert) = match typ {
                        QPackType::Stream => (Index::LiteralNameValue {
                            req_insert: false,
                            name_len: name.len(),
                            huffman: self.huffman,
                        }, false),
                        QPackType::StreamEncoder => (Index::NewName {
                            name_len: name.len(),
                            huffman: self.huffman,
                        }, true),
                        QPackType::StreamDecoder => unreachable!(),
                    };
                    index.write_to(writer)?;
                    match self.huffman {
                        true => writer.write_slice(&huffman::encode(name.as_bytes()))?,
                        false => writer.write_slice(name.as_bytes())?
                    }
                    self.encode_literal(value, writer)?;
                    if req_insert {
                        let item = PackItem::new(name.to_string(), value.to_string());
                        self.table.insert(item, sid, false);
                    }
                    Ok(())
                }
            }
            Some(index) => index.with_base(self.base).write_to(writer)
        }
    }

    pub fn update_table_size(&mut self, max_size: usize) {
        self.table.update_table_size(max_size)
    }
}

#[cfg(test)]
mod tests {
    use crate::hex;
    use crate::pack::qpack::encode::QPackEncode;
    use crate::pack::qpack::index::Index;
    use crate::pack::qpack::QPackType;
    use reqtls::Writer;

    #[test]
    fn test_qpack_encode1() {
        let mut writer = Writer::with_capacity(1024);
        let mut encoder = QPackEncode::new(4096);
        encoder.set_huffman(false);
        encoder.encode_head(&mut writer).unwrap();
        encoder.encode_one(QPackType::Stream, ":path", "/index.html", &0, &mut writer).unwrap();
        assert_eq!(hex::encode(writer.filled()), "0000510b2f696e6465782e68746d6c");
    }

    #[test]
    fn test_qpack_encode2() {
        let mut writer = Writer::with_capacity(1024);
        let mut encoder = QPackEncode::new(4096);
        Index::DynamicTableCapacity(220).write_to(&mut writer).unwrap();
        encoder.encode_one(QPackType::StreamEncoder, ":authority", "www.example.com", &1, &mut writer).unwrap();
        encoder.encode_one(QPackType::StreamEncoder, ":path", "/sample/path", &0, &mut writer).unwrap();
        assert_eq!(hex::encode(writer.filled()), "3fbd01c00f7777772e6578616d706c652e636f6dc10c2f73616d706c652f70617468");

        writer.reset();
        let base = 0;
        encoder.set_base(base);
        encoder.encode_head(&mut writer).unwrap();
        encoder.encode_one(QPackType::Stream, ":authority", "www.example.com", &4, &mut writer).unwrap();
        encoder.encode_one(QPackType::Stream, ":path", "/sample/path", &4, &mut writer).unwrap();
        assert_eq!(hex::encode(writer.filled()), "03811011");

        writer.reset();
        encoder.encode_one(QPackType::StreamEncoder, "custom-key", "custom-value", &1, &mut writer).unwrap();
        assert_eq!(hex::encode(writer.filled()), "4a637573746f6d2d6b65790c637573746f6d2d76616c7565");
        encoder.table.dynamic_table_mut().set_increment(3);

        writer.reset();
        let duplicate = 0;
        let index = Index::Duplicate(encoder.table.dynamic_table().item_count() - 1 - duplicate);
        index.write_to(&mut writer).unwrap();
        encoder.table.dynamic_table_mut().duplicate(duplicate).unwrap();
        assert_eq!(hex::encode(writer.filled()), "02");
        encoder.table.dynamic_table_mut().set_increment(4);

        writer.reset();
        let base = 4;
        encoder.set_base(base);
        encoder.encode_head(&mut writer).unwrap();
        encoder.encode_one(QPackType::Stream, ":authority", "www.example.com", &8, &mut writer).unwrap();
        encoder.encode_one(QPackType::Stream, ":path", "/", &8, &mut writer).unwrap();
        encoder.encode_one(QPackType::Stream, "custom-key", "custom-value", &1, &mut writer).unwrap();
        assert_eq!(hex::encode(writer.filled()), "050080c181");
    }
}