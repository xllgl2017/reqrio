mod hpack;
mod item;
mod error;
pub mod huffman;
#[cfg(feature = "quic")]
mod qpack;

pub use error::PackError;
pub use hpack::{HPackCoding, HPackDecode, HPackDecodeBuf, HPackEncode};
pub use item::PackItem;
#[cfg(feature = "quic")]
pub use qpack::{QPackDecode, QPackEncode, QPackType};
use reqtls::{BufferError, Reader, Writer};

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

pub fn encode_integer(writer: &mut Writer, mut value: usize) -> Result<(), BufferError> {
    while value >= 128 {
        writer.write_u8(0b1000_0000 | value as u8)?;
        value >>= 7;
    }
    writer.write_u8(value as u8)
}