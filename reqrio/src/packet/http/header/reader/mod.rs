#[cfg(feature = "quic")]
mod h3;

#[cfg(feature = "quic")]
use crate::error::HlsResult;
#[cfg(feature = "quic")]
use crate::pack::QPackEncode;
#[cfg(feature = "quic")]
use crate::reader::ReadExt;
use crate::Method;
#[cfg(feature = "quic")]
pub(super) use h3::H3HeaderReader;
use reqtls::*;

// #[deprecated]
pub struct HeaderParam<'a> {
    pub(crate) method: Method,
    pub(crate) url: &'a Url,
    #[cfg(feature = "quic")]
    pub(crate) q_sid: &'a u64,
    #[cfg(feature = "quic")]
    pub(crate) qpack_encoder: Option<&'a mut QPackEncode>,
    #[cfg(feature = "quic")]
    pub(crate) body_len: usize,
    pub(crate) weight: u8,
    pub(crate) priority: bool,
}

#[cfg(feature = "quic")]
pub enum HeaderReader<'a> {
    H3(H3HeaderReader<'a>),
}

#[cfg(feature = "quic")]
impl<'a> ReadExt for HeaderReader<'a> {
    fn wrote(&self) -> bool {
        match self {
            HeaderReader::H3(h3) => h3.wrote(),
        }
    }

    fn len(&self) -> usize {
        match self {
            HeaderReader::H3(h3) => h3.len(),
        }
    }

    fn read(&mut self, buf: &mut Writer) -> HlsResult<usize> {
        match self {
            HeaderReader::H3(h3) => h3.read(buf)
        }
    }
}

