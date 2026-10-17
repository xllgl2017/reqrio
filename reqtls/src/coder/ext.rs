use crate::{Reader, RlsError, Writer};
use crate::error::RlsResult;

pub trait StreamDecode {
    fn decompress(&mut self, reader: &mut Reader<'_>, out: &mut Writer) -> RlsResult<bool>;
    fn flush(&mut self, out: &mut Writer) -> RlsResult<bool>;
}

pub trait StreamEncode {
    fn compress(&mut self, reader: &mut Reader<'_>, out: &mut Writer) -> Result<bool, RlsError>;
    fn flush(&mut self, out: &mut Writer) -> Result<bool, RlsError>;
}
