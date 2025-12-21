pub use table::HPack;

use encode::HackEncode;
use decode::HackDecode;
use table::HPackTable;

use crate::error::HlsResult;
use crate::packet::HeaderKey;

mod decode;
mod encode;
mod table;

#[derive(Clone)]
pub struct HPackCoding {
    req_table: HPackTable,
    res_table: HPackTable,
    decoder: HackDecode,
    encoder: HackEncode,
}

impl HPackCoding {
    pub fn new() -> HPackCoding {
        HPackCoding {
            req_table: HPackTable::new(),
            res_table: HPackTable::new(),
            decoder: HackDecode::new(),
            encoder: HackEncode::new(),
        }
    }

    pub fn decode(&mut self, context: impl AsRef<[u8]>, req: bool) -> HlsResult<Vec<HPack>> {
        self.decoder.decode(context.as_ref(), if req { &mut self.req_table } else { &mut self.res_table })
    }

    pub fn encode(&mut self, headers: Vec<HeaderKey>) -> HlsResult<Vec<u8>> {
        self.encoder.encode(headers, &mut self.req_table)
    }
}