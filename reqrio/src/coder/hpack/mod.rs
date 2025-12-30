pub use table::HPack;
pub use encode::HackEncode;
pub use decode::HackDecode;

use table::HPackTable;

use crate::error::HlsResult;
use crate::packet::HeaderKey;

mod decode;
mod encode;
mod table;

pub struct HPackCoding {
    decoder: HackDecode,
    encoder: HackEncode,
}

impl HPackCoding {
    pub fn new() -> HPackCoding {
        HPackCoding {
            decoder: HackDecode::new(),
            encoder: HackEncode::new(),
        }
    }

    pub fn decode(&mut self, context: impl AsRef<[u8]>) -> HlsResult<Vec<HPack>> {
        self.decoder.decode(context.as_ref())
    }

    pub fn encode(&mut self, headers: Vec<HeaderKey>) -> HlsResult<Vec<u8>> {
        self.encoder.encode(headers)
    }

    pub fn decoder(&mut self) -> &mut HackDecode { &mut self.decoder }
}