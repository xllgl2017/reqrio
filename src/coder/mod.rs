use crate::error::HlsResult;
use flate2::read::{DeflateDecoder, GzDecoder};
pub use hpack::*;
use std::io::{BufReader, Read};

mod hpack;


pub fn url_encode(url: impl AsRef<str>) -> String {
    urlencoding::encode(url.as_ref()).to_string()
}

pub fn url_decode(url: impl AsRef<str>) -> HlsResult<String> {
    Ok(urlencoding::decode(url.as_ref())?.to_string())
}

pub fn br_decode(brd: impl AsRef<[u8]>) -> HlsResult<Vec<u8>> {
    let mut buffer = BufReader::new(brd.as_ref());
    let mut out = vec![];
    brotli::BrotliDecompress(&mut buffer, &mut out)?;
    Ok(out)
}


// pub fn br_encode(brd: impl AsRef<[u8]>) -> HlsResult<Vec<u8>> {
//     let params = brotli::enc::BrotliEncoderParams::default();
//     let mut bufread = BufReader::new(brd.as_ref());
//     let mut out = vec![];
//     brotli::BrotliCompress(&mut bufread, &mut out, &params)?;
//     Ok(out)
// }

// pub fn deflate_encode(ded: impl AsRef<[u8]>) -> HlsResult<Vec<u8>> {
//     let mut de = DeflateEncoder::new(ded.as_ref(), Compression::default());
//     let mut out = vec![];
//     de.read_to_end(&mut out)?;
//     Ok(out)
// }

pub fn deflate_decode(ded: impl AsRef<[u8]>) -> HlsResult<Vec<u8>> {
    let mut de = DeflateDecoder::new(ded.as_ref());
    let mut out = vec![];
    de.read_to_end(&mut out)?;
    Ok(out)
}

// pub fn gzip_encode(ded: impl AsRef<[u8]>) -> HlsResult<Vec<u8>> {
//     let mut ge = GzEncoder::new(ded.as_ref(), Compression::default());
//     let mut out = vec![];
//     ge.read_to_end(&mut out)?;
//     Ok(out)
// }

pub fn gzip_decode(ded: impl AsRef<[u8]>) -> HlsResult<Vec<u8>> {
    if ded.as_ref().len() == 0 { return Ok(vec![]); }
    let mut gd = GzDecoder::new(ded.as_ref());
    let mut out = vec![];
    gd.read_to_end(&mut out)?;
    Ok(out)
}

// pub fn zstd_encode(zst: impl AsRef<[u8]>) -> HlsResult<Vec<u8>> {
//     Ok(zstd::encode_all(zst.as_ref(), zstd::DEFAULT_COMPRESSION_LEVEL)?)
// }

pub fn zstd_decode(zst: impl AsRef<[u8]>) -> HlsResult<Vec<u8>> {
    Ok(zstd::decode_all(zst.as_ref())?)
}

// pub fn md5(content: impl AsRef<[u8]>) -> String {
//     let res = md5::compute(content.as_ref()).to_vec();
//     hex::encode(&res)
// }