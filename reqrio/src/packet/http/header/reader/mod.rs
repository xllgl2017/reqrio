mod h2;
#[cfg(feature = "quic")]
mod h3;

use crate::error::HlsResult;
use crate::pack::HPackEncode;
#[cfg(feature = "quic")]
use crate::pack::QPackEncode;
use crate::reader::ReadExt;
use crate::Method;
pub(super) use h2::H2HeaderReader;
#[cfg(feature = "quic")]
pub(super) use h3::H3HeaderReader;
use reqtls::{Url, Writer};

pub struct HeaderParam<'a> {
    pub(crate) method: Method,
    pub(crate) url: &'a Url,
    pub(crate) h_sid: &'a u32,
    pub(crate) hpack_encoder: Option<&'a mut HPackEncode>,
    #[cfg(feature = "quic")]
    pub(crate) q_sid: &'a u64,
    #[cfg(feature = "quic")]
    pub(crate) qpack_encoder: Option<&'a mut QPackEncode>,
    pub(crate) body_len: usize,
    pub(crate) weight: &'a u8,
    pub(crate) priority: &'a bool,
}

pub enum HeaderReader<'a> {
    H2(H2HeaderReader<'a>),
    #[cfg(feature = "quic")]
    H3(H3HeaderReader<'a>),
}

impl<'a> ReadExt for HeaderReader<'a> {
    fn wrote(&self) -> bool {
        match self {
            HeaderReader::H2(h2) => h2.wrote(),
            #[cfg(feature = "quic")]
            HeaderReader::H3(h3) => h3.wrote(),
        }
    }

    fn len(&self) -> usize {
        match self {
            HeaderReader::H2(h2) => h2.len(),
            #[cfg(feature = "quic")]
            HeaderReader::H3(h3) => h3.len(),
        }
    }

    fn read(&mut self, buf: &mut Writer) -> HlsResult<usize> {
        match self {
            HeaderReader::H2(h2) => h2.read(buf),
            #[cfg(feature = "quic")]
            HeaderReader::H3(h3) => h3.read(buf)
        }
    }
}

