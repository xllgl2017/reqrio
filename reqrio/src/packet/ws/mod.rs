pub use payload::WsPayload;
use reqtls::coder::TZCoder;
use reqtls::Reader;
pub use typ::{WsFrameType, WsOpcode};


mod payload;
mod typ;

use crate::error::HlsResult;
use crate::Writer;

///```text
///     0    1   2   3   4   5   6   7
/// +------+---+---+---+---+---+---+---+
/// | mask |        len/code           |
/// +------+---------------------------+
/// ```
pub struct Marker {
    mask: bool,
    len_code: u8,
}

impl Marker {
    pub fn new(mask: bool, len: usize) -> Marker {
        Marker {
            mask,
            len_code: match len {
                0..126 => len as u8,
                126..0xFFFF => 126,
                0xFFFF.. => 127,
            },
        }
    }

    pub fn from_u8(value: u8) -> Marker {
        Marker {
            mask: value & 0x80 == 0x80,
            len_code: value & 0x7f,
        }
    }

    pub fn encode(&self) -> u8 {
        match self.mask {
            true => self.len_code | 0x80,
            false => self.len_code
        }
    }

    pub fn mask(&self) -> bool {
        self.mask
    }

    pub fn len_code(&self) -> u8 {
        self.len_code
    }
}


pub struct WsFrame {
    typ: WsFrameType,
    masker: Marker,
    payload: WsPayload,
}


impl WsFrame {

    pub fn frame_len(&self) -> usize {
        let mut len = 2;
        if self.masker.mask {
            len += 4;
        }
        len += match self.masker.len_code {
            127 => 8,
            126 => 2,
            _ => 0
        };
        len += self.payload.len();
        len
    }

    pub fn from_reader(reader: &mut Reader, coder: Option<&mut TZCoder>, demask_buffer: &mut Writer) -> HlsResult<WsFrame> {
        let typ: WsFrameType = reader.read_u8()?.into();
        let masker = Marker::from_u8(reader.read_u8()?);
        let payload = WsPayload::from_reader(&masker, reader, coder, demask_buffer)?;
        Ok(WsFrame {
            typ,
            masker,
            payload,
        })
    }

    pub fn payload(&self) -> &WsPayload {
        &self.payload
    }

    pub fn frame_type(&self) -> &WsFrameType {
        &self.typ
    }
}