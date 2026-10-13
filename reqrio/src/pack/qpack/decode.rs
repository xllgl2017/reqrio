use super::QPackType;
use super::index::Index;
use super::table::Table;
use crate::error::HlsResult;
use crate::pack::{PackError, PackItem, huffman};
use crate::stream::StreamMessage;
use crate::*;
use std::borrow::Cow;
use std::collections::HashSet;

pub struct QPackDecode {
    table: Table,
    sid_read: HashSet<u64>,
    base: usize,
}

impl QPackDecode {
    pub fn new(max_size: usize) -> QPackDecode {
        QPackDecode {
            table: Table::new(max_size),
            sid_read: HashSet::new(),
            base: 0,
        }
    }

    fn decode_literal(&self, reader: &mut Reader) -> HlsResult<String> {
        let mut len = reader.read_u8()? as usize;
        let huffman = len & 0x80 == 0x80;
        len &= 0x7F;
        if len == 0x7F {
            len += super::super::decode_integer(reader)?;
        }
        match huffman {
            true => Ok(String::from_utf8(huffman::decode(reader.read_slice(len)?)?)?),
            false => Ok(reader.read_str(len)?.to_string())
        }
    }

    fn decode_new_item(&mut self, name_len: usize, huffman: bool, sid: &u64, req_insert: bool, reader: &mut Reader) -> HlsResult<Cow<'_, PackItem>> {
        let name = match huffman {
            true => String::from_utf8(huffman::decode(reader.read_slice(name_len)?)?)?,
            false => reader.read_str(name_len)?.to_string()
        };
        let value = self.decode_literal(reader)?;
        let item = PackItem::new(name, value);
        let item = match req_insert {
            true => self.table.insert(item, sid, false),
            false => Cow::Owned(item)
        };
        if matches!(item, Cow::Owned(_)) && req_insert { return Err("insert fail".into()); }
        Ok(item)
    }

    pub fn decode_next(&mut self, typ: QPackType, sid: &u64, reader: &mut Reader) -> HlsResult<Cow<'_, PackItem>> {
        let index = Index::from_reader(typ, self.sid_read.contains(sid), reader)?;
        match index {
            Index::DynamicTableCapacity(size) => {
                self.table.update_table_size(size);
                Ok(Cow::Owned(PackItem::new_table_size(size)))
            }
            Index::IndexedName {
                idx_dyn,
                index
            } => {
                let index = if idx_dyn { self.table.dynamic_table().item_count() - index - 1 } else { index };
                let mut item = self.table.get(index, sid, idx_dyn, false).ok_or("indexed name fail")?.clone();
                let value = self.decode_literal(reader)?;
                item.set_value(value);
                let item = self.table.insert(item, sid, false);
                if matches!(item,Cow::Owned(_)) { return Err("insert fail".into()); }
                Ok(item)
            }
            Index::NewName { huffman, name_len } => self.decode_new_item(name_len, huffman, sid, true, reader),
            Index::Duplicate(index) => {
                let index = self.table.dynamic_table().item_count() - index - 1;
                self.table.dynamic_table_mut().duplicate(index)?;
                Ok(Cow::Owned(PackItem::new("duplicate", index.to_string())))
            }
            Index::Acknowledgment(sid) => {
                self.table.dynamic_table_mut().section_ack(sid);
                Ok(Cow::Owned(PackItem::new("acknowledgment", sid.to_string())))
            }
            Index::StreamCancellation(sid) => {
                self.table.dynamic_table_mut().section_ack(sid);
                Ok(Cow::Owned(PackItem::new("stream-cancellation", sid.to_string())))
            }
            Index::Increment(count) => {
                self.table.dynamic_table_mut().set_increment(count);
                Ok(Cow::Owned(PackItem::new("increment", sid.to_string())))
            }
            Index::EncodedHead { req_enc_count: enc_count, delta_base: base, sign } => {
                let req_count = self.table.dynamic_table().cal_req_count(enc_count)?;
                self.base = if !sign { base + req_count } else { req_count - base - 1 };
                if self.table.dynamic_table().item_count() < req_count { return Err(PackError::BlockedStream(req_count).into()); }
                Ok(Cow::Owned(PackItem::new("encoded-head", format!("req: {}; base: {}", req_count, self.base))))
            }
            Index::Indexed {
                idx_dyn,
                index
            } => {
                let index = if idx_dyn { self.base - index - 1 } else { index };
                let item = self.table.get(index, sid, idx_dyn, false).ok_or("indexed name fail")?;
                Ok(Cow::Borrowed(item))
            }
            Index::PostBase(index) => {
                let index = self.base + index;
                let item = self.table.get(index, sid, true, false).ok_or("post base indexed fail")?;
                Ok(Cow::Borrowed(item))
            }
            Index::NamedIndexed {
                req_insert,
                idx_dyn,
                index
            } => {
                let index = if idx_dyn { self.base - index - 1 } else { index };
                let mut item = self.table.get(index, sid, idx_dyn, false).ok_or("named index fail")?.clone();
                let value = self.decode_literal(reader)?;
                item.set_value(value);
                let item = match req_insert {
                    true => self.table.insert(item, sid, false),
                    false => Cow::Owned(item)
                };
                if matches!(item, Cow::Owned(_)) && req_insert { return Err("insert fail".into()); }
                Ok(item)
            }
            Index::NamePostBase { req_insert, index } => {
                let index = self.base + index;
                let mut item = self.table.get(index, sid, true, false).ok_or("named index fail")?.clone();
                let value = self.decode_literal(reader)?;
                item.set_value(value);
                let item = match req_insert {
                    true => self.table.insert(item, sid, false),
                    false => Cow::Owned(item)
                };
                if matches!(item, Cow::Owned(_)) && req_insert { return Err("insert fail".into()); }
                Ok(item)
            }
            Index::LiteralNameValue {
                req_insert,
                name_len,
                huffman,
            } => self.decode_new_item(name_len, huffman, sid, req_insert, reader),
        }
    }

    pub fn decode_into(&mut self, buf: &[u8], header: &mut StreamMessage, typ: QPackType, sid: &u64) -> HlsResult<usize> {
        let mut reader = Reader::from_slice(buf);
        while reader.unread_len() > 0 {
            let mut pos = reader.position();
            match self.decode_next(typ, sid, &mut reader) {
                Ok(item) => {
                    pos = reader.position();
                    header.push_pack_item(item.as_ref())?;
                    self.sid_read.insert(*sid);
                }
                Err(HlsError::HPack(PackError::BlockedStream(req))) => return Err(PackError::BlockedStream(req).into()),
                Err(_e) => {
                    #[cfg(feature = "log")]
                    warn!("[QPackDecode] {}",_e);
                    reader.set_position(pos);
                    break;
                }
            }
        }
        Ok(reader.position())
    }

    pub fn update_table_size(&mut self, max_size: usize) {
        self.table.update_table_size(max_size)
    }
}

#[cfg(test)]
mod tests {
    use crate::pack::qpack::QPackType;
    use crate::pack::qpack::decode::QPackDecode;
    use crate::stream::StreamMessage;
    use crate::{HttpStatus, Method, hex};
    use reqtls::Reader;

    #[test]
    fn test_qpack_decode1() {
        let data = hex::decode("0000510b2f696e6465782e68746d6c").unwrap();
        let mut reader = Reader::from_slice(&data);
        let mut decoder = QPackDecode::new(4096);
        let item = decoder.decode_next(QPackType::Stream, &0, &mut reader).unwrap();
        assert_eq!(item.name, "encoded-head");
        assert_eq!(item.value, "req: 0; base: 0");
        decoder.sid_read.insert(0);
        let item = decoder.decode_next(QPackType::Stream, &0, &mut reader).unwrap();
        assert_eq!(item.name, ":path");
        assert_eq!(item.value, "/index.html");
        assert_eq!(reader.unread_len(), 0);
    }

    #[test]
    fn test_qpack_decode2() {
        let data = hex::decode("3fbd01c00f7777772e6578616d706c652e636f6dc10c2f73616d706c652f706174684a637573746f6d2d6b65790c637573746f6d2d76616c756502").unwrap();
        let mut reader = Reader::from_slice(&data);
        let mut decoder = QPackDecode::new(4096);
        let item = decoder.decode_next(QPackType::StreamEncoder, &1, &mut reader).unwrap();
        assert_eq!(item.name, "update-table-size");
        assert_eq!(item.value, "220");
        let item = decoder.decode_next(QPackType::StreamEncoder, &1, &mut reader).unwrap();
        assert_eq!(item.name, ":authority");
        assert_eq!(item.value, "www.example.com");
        let item = decoder.decode_next(QPackType::StreamEncoder, &1, &mut reader).unwrap();
        assert_eq!(item.name, ":path");
        assert_eq!(item.value, "/sample/path");
        let item = decoder.decode_next(QPackType::StreamEncoder, &1, &mut reader).unwrap();
        assert_eq!(item.name, "custom-key");
        assert_eq!(item.value, "custom-value");
        let item = decoder.decode_next(QPackType::StreamEncoder, &1, &mut reader).unwrap();
        assert_eq!(item.name, "duplicate");
        assert_eq!(item.value, "0");
        assert_eq!(decoder.table.dynamic_table().item_count(), 4);


        let data = hex::decode("03811011").unwrap();
        let mut reader = Reader::from_slice(&data);
        let item = decoder.decode_next(QPackType::Stream, &4, &mut reader).unwrap();
        assert_eq!(item.name, "encoded-head");
        assert_eq!(item.value, "req: 2; base: 0");
        decoder.sid_read.insert(4);
        let item = decoder.decode_next(QPackType::Stream, &4, &mut reader).unwrap();
        assert_eq!(item.name, ":authority");
        assert_eq!(item.value, "www.example.com");
        let item = decoder.decode_next(QPackType::Stream, &4, &mut reader).unwrap();
        assert_eq!(item.name, ":path");
        assert_eq!(item.value, "/sample/path");


        let data = hex::decode("050080c181").unwrap();
        let mut reader = Reader::from_slice(&data);
        let item = decoder.decode_next(QPackType::Stream, &8, &mut reader).unwrap();
        assert_eq!(item.name, "encoded-head");
        assert_eq!(item.value, "req: 4; base: 4");
        decoder.sid_read.insert(8);
        let item = decoder.decode_next(QPackType::Stream, &8, &mut reader).unwrap();
        assert_eq!(item.name, ":authority");
        assert_eq!(item.value, "www.example.com");
        let item = decoder.decode_next(QPackType::Stream, &8, &mut reader).unwrap();
        assert_eq!(item.name, ":path");
        assert_eq!(item.value, "/");
        let item = decoder.decode_next(QPackType::Stream, &8, &mut reader).unwrap();
        assert_eq!(item.name, "custom-key");
        assert_eq!(item.value, "custom-value");
    }

    #[test]
    fn test_qpack_decode3() {
        let data = hex::decode("480184").unwrap();
        let mut reader = Reader::from_slice(&data);
        let mut decoder = QPackDecode::new(4096);
        let item = decoder.decode_next(QPackType::StreamDecoder, &1, &mut reader).unwrap();
        assert_eq!(item.name, "stream-cancellation");
        assert_eq!(item.value, "8");
        let item = decoder.decode_next(QPackType::StreamDecoder, &1, &mut reader).unwrap();
        assert_eq!(item.name, "increment");
        assert_eq!(item.value, "1");
        let item = decoder.decode_next(QPackType::StreamDecoder, &1, &mut reader).unwrap();
        assert_eq!(item.name, "acknowledgment");
        assert_eq!(item.value, "4");
    }


    #[test]
    fn test_qpack_decode4() {
        let data = hex::decode("0000d1508d4a195d245e9a578cd54cbd454fd751b96133b06918d57f0af5d53db85ba51ceff298b9f9e341b3ef34dfe7881917c4f0322f8ed42607dbf8ac94412cb2cb28fe0f039f159a4802b8bf2f064148b1275ad1ad5d034ca7b29f88fe791aa90fe11fcf5f50dfd07f66a281b0dae053fae46aa43f8429a77a8102e0fb5391aa71afb53cb8d7f6a435d74179163cc64b0db2eaecb8a7f59b1efd19fe94a0dd4aa62293a9ffb52f4f61e92b0169e5c0b817029b8728ec330db2eaecb8a60926602d3cb81702e02f004148b1275ad1ffb9fe6f4f61e935b4ff3f7de0fe42d3dfcfd29fce8312c3a0f2a54c124c5fe7efbc1fc85a7bf9fa53f9d274b10ff776c1d527f3f7de0fe5f7ff9f2f044148b1275ad1ad49e33505023f305f0eb1352398ac0fb9a5fa352398ac782c75fd1a91cc56075d537d1a91cc5611de6ff7e69a3e8d48e62b1f3f5f2c7cfdf6800bbd2f034148b4a549275906497f872587421641925f2f034148b4a549275a93c85f85a8eb10f6232f034148b4a549275a42a13f84352398bf2f094148b4a5492759093d8398ab0c842a118419126ee55d8f9d29ad171860952f19aa99721e963f5f10929bd9abfa5242cb40d25fa523b3e94f684c9f5f39a6f73ad7b4fd7b9fefb4005dffa2d5f7da002ef7d16a5b15dfbed001777e8b52dc377df6800bb92eaec31ec327d70169").unwrap();
        let mut decoder = QPackDecode::new(4096);
        let mut resp = StreamMessage::default();
        decoder.decode_into(&data, &mut resp, QPackType::Stream, &0).unwrap();
        assert!(matches!(resp.method, Method::GET));
        let data = hex::decode("0000d9f22df2b10649cb86df7b5c58f26f2f049d29ac8324e51c66a0c9f50134e3ff0c5f3d90c5837fd29af56edff4a6ad7bf26ad3bbff1e2f00b0b59ec4ac93ffedfffdfccd61edaff9b9fcd454f83d9d562d961ec47f3f5fcd23f310e62ff371c034f001f5fc96a92b39aa4a3f9b9ffbfffdfcdb651fcdcfe674a6b45c6181965917a8b4585acf6250bd454b03accc585acf627fc20d30466aa64cff15484d63b074c150e41a4c7fe7ffdffe7ffb236e656ccbfffdfcd85acf626249ff9b9fcd454f83d9d562d961ec47f3f5fcd23f310e62ff371c034f001f5fca2d210a84452d83224c7abf9b805c000fd7f328cd45b616296c191263d5fcdc0ae0fff72f02f2b567f05b0b22d1fa868776b5f4e0df2e19085ad2b127ff01dc522d7b1adc215a1b093fd29b8a45af635b842b5d326a2a11f4a6e2916bd8d6e10ad86da285b896c418f57d29b8a45af635b842b61b68a16e25b1063d4b673213f4a6e2916bd8d6e10ada0f19a82fd29b8a45af635b842b683c85a3e94dc522d7b1adc215b5d034ca7b29fa537148b5ec6b70856d740d329eca56e25b1063d52f02f2b5282c93156b0b2fc5da595486e28fdfbad3adb6cdf6850b4e3a286f0705fbae0aedfbd75dc17efa9b4b2a976e298f362100206c220be06da53696552f5c5040138b01e580def086e36ddc699fdf5f4d8bde5a885a9382498baaa2ffc25f1591aed8e8313e94a47e561cc5804dbe20001f5482101fe05696dc34fd28079486d9941004e2807ee04371a1298b46ff5f44d69d983f9b8d34cff3f6a523804dbe20001f53b2b09f83f9b8d34cff3f6a523804dbe20001f53b2b6c036083f9b8d34cff3f6a523804dbe20001f5dad3120fe6e34d33fcfda948e0136f880007da9de0fe5a73e9a67f9f2f0129d6a0f32d6da6938e79f71a134db4d3ee080e36fbae0b2f0329d620c9395642469b5103484954").unwrap();
        let mut resp = StreamMessage::default();
        decoder.decode_into(&data, &mut resp, QPackType::Stream, &8).unwrap();
        assert_eq!(resp.status, HttpStatus::OK);

        let data = hex::decode("65f2b10649cb86df7b5c58f26fff0d90c5837fd29af56edff4a6ad7bf26ad3bb67b0b59ec4ac93ffedfffdfccd61edaff9b9fcd454f83d9d562d961ec47f3f5fcd23f310e62ff371c034f001f5fc96a92b39aa4a3f9b9ffbfffdfcdb651fcdcfe674a6b45c6181965917a8b4585acf6250bd454b03accc585acf627fc20d30466aa64cff15484d63b074c150e41a4c7fe7ffdffe7ffb436e656c006619085ad2b127ff01dc522d7b1adc215a1b093fd29b8a45af635b842b5d326a2a11f4a6e2916bd8d6e10ad86da285b896c418f57d29b8a45af635b842b61b68a16e25b1063d4b673213f4a6e2916bd8d6e10ada0f19a82fd29b8a45af635b842b683c85a3e94dc522d7b1adc215b5d034ca7b29fa537148b5ec6b70856d740d329eca56e25b1063d569f2b5282c93156b0b2f00ff1d8bde5a885a9382498baaa2ffe491aed8e8313e94a47e561cc5804dbe20001fc696dc34fd28079486d9941004e2807ee04371a1298b46ffff14d69d983f9b8d34cff3f6a523804dbe20001f53b2b09f83f9b8d34cff3f6a523804dbe20001f53b2b6c036083f9b8d34cff3f6a523804dbe20001f5dad3120fe6e34d33fcfda948e0136f880007da9de0fe5a73e9a67f9f6829d6a0f32d6da693006a29d620c9395642469b5103484954").unwrap();
        let mut reader = Reader::from_slice(data.as_slice());
        while decoder.decode_next(QPackType::StreamEncoder, &11, &mut reader).is_ok() {
            decoder.sid_read.insert(11);
        }
        assert_eq!(decoder.table.dynamic_table().item_count(), 12);

        let data = hex::decode("0d8bd9f210ff0c11e3ff1e1203cafffdfcd85acf626249ff9b9fcd454f83d9d562d961ec47f3f5fcd23f310e62ff371c034f001f5fca2d210a84452d83224c7abf9b805c000fd7f328cd45b616296c191263d5fcdc0fffbf2f03416cee5b1649a935537f96a4759bee42a0907f251a1234187fcfdc96d903225d9f2f03f2b523accb58598c7abf8528d091a0c31405c4da595486e28d61060730e0136f4381a7216debcd842db6066eb6e437efe053696552edc531e6c420040d8442001a129b4b2a97ae282009c580f2c06f7819b8d86e322fdf16c21754820be0e0181907038e13e175f03cfb62640e34db400bbf1b").unwrap();
        let mut resp = StreamMessage::default();
        decoder.decode_into(&data, &mut resp, QPackType::Stream, &12).unwrap();
        assert_eq!(resp.status, HttpStatus::OK);
    }
}