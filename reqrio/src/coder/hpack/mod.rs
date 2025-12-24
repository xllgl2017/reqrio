pub use table::HPack;

use encode::HackEncode;
use decode::HackDecode;
use table::HPackTable;

use crate::error::HlsResult;
use crate::packet::HeaderKey;

mod decode;
mod encode;
mod table;

pub enum HPackType {
    Send,
    Recv,
}

pub struct HPackCoding {
    send_table: HPackTable,
    recv_table: HPackTable,
    decoder: HackDecode,
    encoder: HackEncode,
    decode_type: HPackType,
    encode_type: HPackType,
}

impl HPackCoding {
    pub fn new() -> HPackCoding {
        HPackCoding {
            send_table: HPackTable::new(),
            recv_table: HPackTable::new(),
            decoder: HackDecode::new(),
            encoder: HackEncode::new(),
            decode_type: HPackType::Recv,
            encode_type: HPackType::Send,
        }
    }

    pub fn decode(&mut self, context: impl AsRef<[u8]>) -> HlsResult<Vec<HPack>> {
        let table=match self.decode_type {
            HPackType::Send => &mut self.send_table,
            HPackType::Recv => &mut self.recv_table,
        };
        self.decoder.decode(context.as_ref(), table)
    }

    pub fn encode(&mut self, headers: Vec<HeaderKey>) -> HlsResult<Vec<u8>> {
        self.encoder.encode(headers, &mut self.send_table)
    }

    pub fn set_decode_type(&mut self, decode_type: HPackType) {
        self.decode_type = decode_type;
    }

    pub fn set_encode_type(&mut self, encode_type: HPackType) {
        self.encode_type = encode_type;
    }
}