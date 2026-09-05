#[cfg(feature = "zstd")]
mod zstd;
mod brotli;
mod deflate;
mod ext;
mod chunk;

use crate::error::RlsResult;
use crate::*;
pub use brotli::{BrotliDecoder, BrotliEncoder};
pub use chunk::ChunkDecoder;
pub use deflate::{DeflateState, DeflateStream};
pub use ext::{StreamDecode, StreamEncode};
use std::borrow::Cow;
use std::error::Error;
use std::fmt::Display;
use std::num::ParseIntError;
use std::str::Utf8Error;
#[cfg(feature = "zstd")]
pub use zstd::{ZstdDecoder, ZstdEncoder};

#[derive(Debug)]
pub enum CodingError {
    NewDeflateDecoder,
    DeflateDecompressFailed,
    DeflateCompressFailed,
    DeflateFlushFailed,
    DeflateError(DeflateState),
    NewZstdDecoderFail,
    ZstdDecodeError,
    NewZstdEncoderFail,
    ZstdEncodeError,
    ZstdFlushError,
    Buffer(BufferError),
    NewBrDecoderError,
    BrDecompressFail,
    NewBrEncoderError,
    BrCompressFail,
    BrFlushFail,
    Utf8(Utf8Error),
    ParseInt(ParseIntError),
}

impl Display for CodingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for CodingError {}

impl From<BufferError> for CodingError {
    fn from(value: BufferError) -> Self {
        CodingError::Buffer(value)
    }
}

impl From<Utf8Error> for CodingError {
    fn from(value: Utf8Error) -> Self {
        CodingError::Utf8(value)
    }
}

impl From<ParseIntError> for CodingError {
    fn from(value: ParseIntError) -> Self {
        CodingError::ParseInt(value)
    }
}

#[cfg(feature = "zstd")]
pub fn zstd_compress(data: impl AsRef<[u8]>) -> Result<Vec<u8>, CodingError> {
    let data = data.as_ref();
    let mut out = vec![0; data.len()];
    let mut encoder = ZstdEncoder::new()?;
    let len1 = encoder.compress(data, &mut out)?;
    let len2 = encoder.finalize(&mut out[len1..])?;
    out.truncate(len1 + len2);
    Ok(out)
}

#[cfg(feature = "zstd")]
pub fn zstd_decompress(data: impl AsRef<[u8]>) -> Result<Vec<u8>, CodingError> {
    let mut reader = Reader::from_slice(data.as_ref());
    let mut out = vec![0; reader.size() * 2];
    let mut decoder = ZstdDecoder::new()?;
    let mut wrote = 0;
    loop {
        let mut writer = Writer::from_ptr(out.as_mut());
        writer.add_len(wrote);
        let res = decoder.decompress(&mut reader, &mut writer);
        wrote = writer.filled().len();
        match res {
            Ok(_) => break,
            Err(CodingError::Buffer(BufferError::CapacityTooSmall { .. })) => {
                out.resize(out.len() + 1024, 0);
            }
            Err(e) => return Err(e)
        }
    }
    out.truncate(wrote);
    Ok(out)
}

pub fn url_encode<'a>(url: impl Into<Cow<'a, str>>) -> Cow<'a, str> {
    let url = url.into();
    match urlencoding::encode(url.as_ref()) {
        Cow::Borrowed(_) => url,
        Cow::Owned(v) => Cow::Owned(v),
    }
}

pub fn url_decode<'a>(url: impl Into<Cow<'a, str>>) -> Result<Cow<'a, str>, UrlError> {
    let url = url.into();
    match urlencoding::decode(url.as_ref())? {
        Cow::Borrowed(_) => Ok(url),
        Cow::Owned(v) => Ok(Cow::Owned(v)),
    }
}

pub fn br_decompress(buf: impl AsRef<[u8]>) -> Result<Vec<u8>, CodingError> {
    let mut reader = Reader::from_slice(buf.as_ref());
    let mut out = vec![0; reader.size() * 2];
    let mut decoder = BrotliDecoder::new()?;
    let len = loop {
        let mut writer = Writer::from_ptr(out.as_mut());
        match decoder.decompress(&mut reader, &mut writer) {
            Ok(_) => break writer.filled().len(),
            Err(CodingError::Buffer(BufferError::CapacityTooSmall { .. })) => {
                out.resize(out.len() + 1024, 0);
            }
            Err(e) => return Err(e)
        };
    };
    out.truncate(len);
    Ok(out)
}

pub fn br_compress(buf: impl AsRef<[u8]>) -> Result<Vec<u8>, CodingError> {
    let buf = buf.as_ref();
    let mut out = vec![0; buf.len()];
    let mut encoder = BrotliEncoder::new()?;
    let len1 = encoder.compress(buf, &mut out)?;
    let len2 = encoder.finalize(&mut out[len1..])?;
    out.truncate(len1 + len2);
    Ok(out)
}


pub fn chunk_decode(mut raw: Vec<u8>) -> RlsResult<Vec<u8>> {
    let mut res = Vec::with_capacity(raw.len());
    while let Some(pos) = raw.windows(2).position(|w| w == b"\r\n") {
        let len_bs = raw.drain(..pos).collect();
        let len_str = String::from_utf8(len_bs)?;
        //删除\r\n
        raw.drain(..2);
        let chunk_len = usize::from_str_radix(len_str.as_str(), 16)?;
        res.extend(raw.drain(..chunk_len).collect::<Vec<_>>());
        //删除\r\n
        raw.drain(..2);
    }
    Ok(res)
}

pub fn deflate_compress(buf: impl AsRef<[u8]>) -> Result<Vec<u8>, CodingError> {
    let mut stream = DeflateStream::new_compress(DeflateStream::DEFLATE)?;
    let buf = buf.as_ref();
    let mut out = vec![0; buf.len()];
    let len1 = stream.compress(buf, &mut out)?;
    let len2 = stream.finalize(&mut out[len1..])?;
    out.truncate(len1 + len2);
    Ok(out)
}

pub fn deflate_decompress(buf: impl AsRef<[u8]>) -> Result<Vec<u8>, CodingError> {
    let mut reader = Reader::from_slice(buf.as_ref());
    let mut out = vec![0; reader.size() * 2];
    let mut decoder = DeflateStream::new_decompress(DeflateStream::DEFLATE)?;
    let len = decoder.decompress_once(&mut reader, &mut out, false)?;
    out.truncate(len);
    Ok(out)
}

pub fn gzip_compress(buf: impl AsRef<[u8]>) -> Result<Vec<u8>, CodingError> {
    let mut stream = DeflateStream::new_compress(DeflateStream::GZIP)?;
    let buf = buf.as_ref();
    let mut out = vec![0; buf.len()];
    let len1 = stream.compress(buf, &mut out)?;
    let len2 = stream.finalize(&mut out[len1..])?;
    out.truncate(len1 + len2);
    Ok(out)
}

pub fn gzip_decompress(buf: impl AsRef<[u8]>) -> Result<Vec<u8>, CodingError> {
    let mut reader = Reader::from_slice(buf.as_ref());
    if reader.unread_len() == 0 { return Ok(vec![]); }
    let mut out = vec![0; reader.size() * 2];
    let mut decoder = DeflateStream::new_decompress(DeflateStream::GZIP)?;
    let len = decoder.decompress_once(&mut reader, &mut out, false)?;
    out.truncate(len);
    Ok(out)
}
