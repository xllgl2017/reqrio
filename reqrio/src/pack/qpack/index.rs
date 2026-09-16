use crate::pack::qpack::QPackType;
use reqtls::{BufferError, Reader, Writer};

#[derive(Debug)]
#[cfg_attr(debug_assertions, derive(PartialEq))]
pub enum Index {
    //--------------------------->encoder<---------------------------
    ///更新动态表大小
    /// ```text
    ///  0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 0 | 1 |   Capacity (5+)   |
    /// +---+---+---+-------------------+
    /// ```
    DynamicTableCapacity(usize),
    ///name在编/解码表内存在，但value不存在，应追加到动态表中
    /// ```text
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 1 | T |    Name Index (6+)    |
    /// +---+---+-----------------------+
    /// | H |     Value Length (7+)     |
    /// +---+---------------------------+
    /// |  Value String (Length bytes)  |
    /// +-------------------------------+
    /// ```
    IndexedName {
        idx_dyn: bool,
        index: usize,
    },
    /// name和value在编/解码表内不存在，应追加到动态表中
    /// ```text
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 1 | H | Name Length (5+)  |
    /// +---+---+---+-------------------+
    /// |  Name String (Length bytes)   |
    /// +---+---------------------------+
    /// | H |     Value Length (7+)     |
    /// +---+---------------------------+
    /// |  Value String (Length bytes)  |
    /// +-------------------------------+
    /// ```
    NewName {
        huffman: bool,
        name_len: usize,
    },
    /// 复制动态表中已存在的条目
    /// ```text
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 0 | 0 |    Index (5+)     |
    /// +---+---+---+-------------------+
    ///```
    Duplicate(usize),
    //----------------------------->decoder<----------------------------
    ///Section Acknowledgment
    /// ```text
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 1 |      Stream ID (7+)       |
    /// +---+---------------------------+
    ///```
    Acknowledgment(u64),
    /// stream reset or reading is abandoned
    /// ```text
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 1 |     Stream ID (6+)    |
    /// +---+---+-----------------------+
    ///```
    StreamCancellation(u64),
    /// 已经收到并处理到第x个动态表插入
    ///```text
    ///  0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 0 |     Increment (6+)    |
    /// +---+---+-----------------------+
    ///```
    Increment(usize),
    //---------------------------->stream<----------------------------
    ///所需插入计数
    /// ```text
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// |   Required Insert Count (8+)  |
    /// +---+---------------------------+
    /// | S |      Delta Base (7+)      |
    /// +---+---------------------------+
    /// |      Encoded Field Lines    ...
    /// +-------------------------------+
    ///  if Sign == 0:
    ///       Base = ReqInsertCount + DeltaBase
    ///    else:
    ///       Base = ReqInsertCount - DeltaBase - 1
    /// ```
    EncodedHead {
        req_enc_count: usize,
        delta_base: usize,
        sign: bool,
    },
    ///name-value均能在表内找到
    /// ```text
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 1 | T |      Index (6+)       |
    /// +---+---+-----------------------+
    /// ```
    Indexed {
        idx_dyn: bool,
        index: usize,
    },
    ///Indexed Field Line with Post-Base Index
    ///```text
    ///  0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 0 | 0 | 1 |  Index (4+)   |
    /// +---+---+---+---+---------------+
    /// ```
    PostBase(usize),
    ///name在编/解码表内存在，但value不存在，应追加到动态表中，N表示是否插入到动态表
    /// ```text
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 1 | N | T |Name Index (4+)|
    /// +---+---+---+---+---------------+
    /// | H |     Value Length (7+)     |
    /// +---+---------------------------+
    /// |  Value String (Length bytes)  |
    /// +-------------------------------+
    ///```
    NamedIndexed {
        req_insert: bool,
        idx_dyn: bool,
        index: usize,

    },
    ///Literal Field Line with Post-Base Name Reference
    /// ```text
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 0 | 0 | 0 | N |NameIdx(3+)|
    /// +---+---+---+---+---+-----------+
    /// | H |     Value Length (7+)     |
    /// +---+---------------------------+
    /// |  Value String (Length bytes)  |
    /// +-------------------------------+
    /// ```
    NamePostBase {
        req_insert: bool,
        index: usize,
    },
    ///Literal Field Line with Literal Name
    /// ```text
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 0 | 1 | N | H |NameLen(3+)|
    /// +---+---+---+---+---+-----------+
    /// |  Name String (Length bytes)   |
    /// +---+---------------------------+
    /// | H |     Value Length (7+)     |
    /// +---+---------------------------+
    /// |  Value String (Length bytes)  |
    /// +-------------------------------+
    /// ```
    LiteralNameValue {
        req_insert: bool,
        name_len: usize,
        huffman: bool,
    },

}

impl Index {
    ///stream decode
    pub fn from_reader(typ: QPackType, read: bool, reader: &mut Reader) -> Result<Index, BufferError> {
        match typ {
            QPackType::Stream => {
                let typ = reader.read_u8()?;
                if !read {
                    let mut insert = typ as usize & 0xFF;
                    if typ == 0xff {
                        insert += super::super::decode_integer(reader)?
                    }
                    let base = reader.read_u8()? as usize;
                    let sign = base & 0x80 == 0x80;
                    let mut base = base & 0x7F;
                    if base & 0x7F == 0x7F {
                        base += super::super::decode_integer(reader)?;
                    }
                    return Ok(Index::EncodedHead {
                        req_enc_count: insert,
                        delta_base: base,
                        sign,
                    });
                }
                if typ & 0x80 == 0x80 {
                    let mut value = typ as usize & 0x3F;
                    if value == 0x3F {
                        value += super::super::decode_integer(reader)?;
                    }
                    Ok(Index::Indexed {
                        idx_dyn: typ & 0x40 != 0x40,
                        index: value,
                    })
                } else if typ & 0x40 == 0x40 {
                    let mut value = typ as usize & 0xF;
                    if value == 0xF {
                        value += super::super::decode_integer(reader)?;
                    };
                    Ok(Index::NamedIndexed {
                        req_insert: typ & 0x20 == 0x20,
                        idx_dyn: typ & 0x10 != 0x10,
                        index: value,
                    })
                } else if typ & 0x10 == 0x10 {
                    let mut value = typ as usize & 0xF;
                    if value == 0xF {
                        value += super::super::decode_integer(reader)?;
                    }
                    Ok(Index::PostBase(value))
                } else if typ & 0x20 == 0x20 {
                    let mut value = typ as usize & 0x7;
                    if value == 0x7 {
                        value += super::super::decode_integer(reader)?;
                    }
                    Ok(Index::LiteralNameValue {
                        req_insert: typ & 0x10 == 0x10,
                        name_len: value,
                        huffman: typ & 0x8 == 0x8,
                    })
                } else if typ >> 4 == 0 {
                    let mut value = typ as usize & 0x7;
                    if value == 0x7 {
                        value += super::super::decode_integer(reader)?;
                    }
                    Ok(Index::NamePostBase {
                        req_insert: typ & 0x8 == 0x8,
                        index: value,
                    })
                } else { unreachable!() }
            }
            QPackType::StreamEncoder => {
                let typ = reader.read_u8()?;
                if typ >> 5 == 1 {
                    let mut value = typ as usize & 0x1F;
                    if value == 0x1F {
                        value += super::super::decode_integer(reader)?;
                    }
                    Ok(Index::DynamicTableCapacity(value))
                } else if typ & 0x80 == 0x80 {
                    let mut value = typ as usize & 0x3F;
                    if value == 0x3F {
                        value += super::super::decode_integer(reader)?;
                    }
                    Ok(Index::IndexedName {
                        idx_dyn: typ & 0x40 != 0x40,
                        index: value,
                    })
                } else if typ >> 6 == 1 {
                    let mut value = typ as usize & 0x1F;
                    if value == 0x1F {
                        value += super::super::decode_integer(reader)?;
                    }
                    Ok(Index::NewName {
                        huffman: typ & 0x20 == 0x20,
                        name_len: value,
                    })
                } else if typ >> 5 == 0 {
                    let mut value = typ as usize & 0x1F;
                    if value == 0x1F {
                        value += super::super::decode_integer(reader)?;
                    }
                    Ok(Index::Duplicate(value))
                } else { unreachable!() }
            }
            QPackType::StreamDecoder => {
                let typ = reader.read_u8()?;
                if typ & 0x80 == 0x80 {
                    let mut value = typ as usize & 0x7F;
                    if value == 0x7F {
                        value += super::super::decode_integer(reader)?;
                    }
                    Ok(Index::Acknowledgment(value as u64))
                } else if typ & 0x40 == 0x40 {
                    let mut value = typ as u64 & 0x3F;
                    if value == 0x3F {
                        value += super::super::decode_integer(reader)? as u64;
                    }
                    Ok(Index::StreamCancellation(value))
                } else if typ >> 6 == 0 {
                    let mut value = typ as usize & 0x3F;
                    if value == 0x3F {
                        value += super::super::decode_integer(reader)?;
                    }
                    Ok(Index::Increment(value))
                } else { unreachable!() }
            }
        }
    }

    pub fn write_to(self, writer: &mut Writer) -> Result<(), BufferError> {
        match self {
            Index::DynamicTableCapacity(size) => {
                let value = if size >= 0x1F { 0x1F } else { size };
                writer.write_u8(value as u8 | 0x20)?;
                if value == 0x1F { super::super::encode_integer(writer, size - value)?; }
            }
            Index::IndexedName {
                idx_dyn,
                index,
            } => {
                let value = if index >= 0x3F { 0x3F } else { index };
                writer.write_u8(value as u8 | 0x80 | if !idx_dyn { 0x40 } else { 0 })?;
                if value == 0x3F { super::super::encode_integer(writer, index - value)?; }
            }
            Index::NewName {
                name_len,
                huffman
            } => {
                let value = if name_len >= 0x1F { 0x1F } else { name_len };
                writer.write_u8(value as u8 | 0x40 | if huffman { 0x20 } else { 0 })?;
                if value == 0x1F { super::super::encode_integer(writer, name_len - value)?; }
            }
            Index::Duplicate(size) => {
                let value = if size >= 0x1F { 0x1F } else { size };
                writer.write_u8(value as u8)?;
                if value == 0x1F { super::super::encode_integer(writer, size - value)?; }
            }
            Index::Acknowledgment(size) => {
                let value = if size >= 0x7F { 0x7F } else { size };
                writer.write_u8(value as u8 | 0x80)?;
                if value == 0x7F { super::super::encode_integer(writer, (size - value) as usize)?; }
            }
            Index::StreamCancellation(size) => {
                let value = if size >= 0x3F { 0x3F } else { size };
                writer.write_u8(value as u8 | 0x40)?;
                if value == 0x3F { super::super::encode_integer(writer, (size - value) as usize)?; }
            }
            Index::Increment(size) => {
                let value = if size >= 0x3F { 0x3F } else { size };
                writer.write_u8(value as u8)?;
                if value == 0x3F { super::super::encode_integer(writer, size - value)?; }
            }
            Index::EncodedHead {
                req_enc_count: enc_count,
                delta_base: base,
                sign
            } => {
                let value = if enc_count >= 0xFF { 0xFF } else { enc_count };
                writer.write_u8(value as u8)?;
                if value == 0xFF { super::super::encode_integer(writer, enc_count - value)?; }
                let value = if base >= 0x7F { 0x7F } else { base };
                writer.write_u8(value as u8 | if sign { 0x80 } else { 0 })?;
                if value == 0x7F { super::super::encode_integer(writer, enc_count - value)?; }
            }
            Index::Indexed {
                index,
                idx_dyn,
            } => {
                let value = if index >= 0x3F { 0x3F } else { index };
                writer.write_u8(value as u8 | 0x80 | if !idx_dyn { 0x40 } else { 0 })?;
                if value == 0x3F { super::super::encode_integer(writer, index - value)?; }
            }
            Index::PostBase(size) => {
                let value = if size >= 0xF { 0xF } else { size };
                writer.write_u8(value as u8 | 0x10)?;
                if value == 0xF { super::super::encode_integer(writer, size - value)?; }
            }
            Index::NamedIndexed {
                req_insert,
                idx_dyn,
                index
            } => {
                let value = if index >= 0xF { 0xF } else { index };
                writer.write_u8(value as u8 | 0x40 | if req_insert { 0x20 } else { 0 } | if !idx_dyn { 0x10 } else { 0 })?;
                if value == 0xF { super::super::encode_integer(writer, index - value)?; }
            }
            Index::NamePostBase {
                req_insert,
                index
            } => {
                let value = if index >= 0x7 { 0x7 } else { index };
                writer.write_u8(value as u8 | if req_insert { 0x80 } else { 0 })?;
                if value == 0x7 { super::super::encode_integer(writer, index - value)?; }
            }
            Index::LiteralNameValue {
                req_insert,
                name_len,
                huffman
            } => {
                let value = if name_len >= 0x7 { 0x7 } else { name_len };
                writer.write_u8(value as u8 | 0x20 | if req_insert { 0x10 } else { 0 } | if huffman { 0x8 } else { 0 })?;
                if value == 0x7 { super::super::encode_integer(writer, name_len - value)?; }
            }
        }
        Ok(())
    }

    pub fn with_base(mut self, base: usize) -> Self {
        match &mut self {
            Index::DynamicTableCapacity(_) => {}
            Index::IndexedName { .. } => {}
            Index::NewName { .. } => {}
            Index::Duplicate(_) => {}
            Index::Acknowledgment(_) => {}
            Index::StreamCancellation(_) => {}
            Index::Increment(_) => {}
            Index::EncodedHead { .. } => {}
            Index::Indexed { index, idx_dyn } => if *idx_dyn { *index = base - *index - 1 }
            Index::PostBase(index) => *index -= base,
            Index::NamedIndexed { .. } => {}
            Index::NamePostBase { index, .. } => { *index -= base }
            Index::LiteralNameValue { .. } => {}
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use crate::hex;
    use crate::pack::qpack::index::Index;
    use crate::pack::qpack::QPackType;
    use reqtls::{Writer, Reader};

    #[test]
    fn test_qpack_index1() {
        let data = hex::decode("000051").unwrap();
        let mut read = false;
        let mut reader = Reader::from_slice(&data);
        let index = Index::from_reader(QPackType::Stream, read, &mut reader).unwrap();
        assert_eq!(index, Index::EncodedHead { req_enc_count: 0, delta_base: 0, sign: false });
        read = true;
        let index = Index::from_reader(QPackType::Stream, read, &mut reader).unwrap();
        assert_eq!(index, Index::NamedIndexed {
            req_insert: false,
            idx_dyn: false,
            index: 1
        });
    }

    #[test]
    fn test_qpack_index2() {
        let data = hex::decode("3fbd01c0c14a02").unwrap();
        let mut read = false;
        let mut reader = Reader::from_slice(&data);
        let index = Index::from_reader(QPackType::StreamEncoder, read, &mut reader).unwrap();
        assert_eq!(index, Index::DynamicTableCapacity(220));
        read = true;
        let index = Index::from_reader(QPackType::StreamEncoder, read, &mut reader).unwrap();
        assert_eq!(index, Index::IndexedName { idx_dyn: false, index: 0 });
        let index = Index::from_reader(QPackType::StreamEncoder, read, &mut reader).unwrap();
        assert_eq!(index, Index::IndexedName { idx_dyn: false, index: 1 });
        let index = Index::from_reader(QPackType::StreamEncoder, read, &mut reader).unwrap();
        let Index::NewName { huffman, name_len } = index else { panic!("index decode error") };
        assert!(!huffman);
        assert_eq!(name_len, 10);
        let index = Index::from_reader(QPackType::StreamEncoder, read, &mut reader).unwrap();
        assert_eq!(index, Index::Duplicate(2))
    }

    #[test]
    fn test_qpack_index3() {
        let data = hex::decode("480184").unwrap();
        let mut reader = Reader::from_slice(&data);
        let index = Index::from_reader(QPackType::StreamDecoder, false, &mut reader).unwrap();
        assert_eq!(index, Index::StreamCancellation(8));
        let index = Index::from_reader(QPackType::StreamDecoder, false, &mut reader).unwrap();
        assert_eq!(index, Index::Increment(1));
        let index = Index::from_reader(QPackType::StreamDecoder, false, &mut reader).unwrap();
        assert_eq!(index, Index::Acknowledgment(4))
    }

    #[test]
    fn test_qpack_encode1() {
        let mut writer = Writer::with_capacity(1024);
        Index::StreamCancellation(8).write_to(&mut writer).unwrap();
        Index::Increment(1).write_to(&mut writer).unwrap();
        Index::Acknowledgment(4).write_to(&mut writer).unwrap();
        assert_eq!("480184", hex::encode(writer.filled()));

        writer.reset();
        Index::DynamicTableCapacity(220).write_to(&mut writer).unwrap();
        Index::IndexedName { idx_dyn: false, index: 0 }.write_to(&mut writer).unwrap();
        Index::IndexedName { idx_dyn: false, index: 1 }.write_to(&mut writer).unwrap();
        Index::NewName { huffman: false, name_len: 10 }.write_to(&mut writer).unwrap();
        Index::Duplicate(2).write_to(&mut writer).unwrap();
        assert_eq!(hex::encode(writer.filled()), "3fbd01c0c14a02");

        writer.reset();
        Index::EncodedHead { req_enc_count: 0, delta_base: 0, sign: false }.write_to(&mut writer).unwrap();
        Index::NamedIndexed { req_insert: false, idx_dyn: false, index: 1 }.write_to(&mut writer).unwrap();
        assert_eq!(hex::encode(writer.filled()), "000051");
    }
}