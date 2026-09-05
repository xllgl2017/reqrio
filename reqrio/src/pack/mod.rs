mod hpack;
mod item;
mod error;
pub mod huffman;
#[cfg(feature = "quic")]
mod qpack;

pub use hpack::{HPackCoding, HPackEncode, HPackDecode, HPackDecodeBuf};
#[cfg(feature = "quic")]
pub use qpack::{QPackType, QPackEncode, QPackDecode};
pub use item::PackItem;
pub use error::PackError;
use reqtls::{BufferError, Reader, WriteExt};

pub fn decode_integer(buf: &mut Reader) -> Result<usize, BufferError> {
    let mut res = 0;
    let mut shift = 0;
    loop {
        let byte = buf.read_u8()?;
        res |= ((byte & 0b0111_1111) as usize) << shift;
        shift += 7;
        if byte >> 7 == 0 { break; }
    }
    Ok(res)
}

pub fn encode_integer<W: WriteExt>(writer: &mut W, mut value: usize) -> Result<(), BufferError> {
    while value >= 128 {
        writer.write_u8(0b1000_0000 | value as u8)?;
        value >>= 7;
    }
    writer.write_u8(value as u8)
}