mod ext;
mod chunk;

use crate::error::RlsResult;
use crate::*;
use std::borrow::Cow;
pub use chunk::ChunkDecoder;
use crate::boring::BoringResExt;
use crate::ffi::c_struct_free;
use std::os::raw::{c_int, c_void};
use std::ptr::null_mut;
pub use ext::{StreamEncode, StreamDecode};

#[inline]
pub fn zstd_compress(data: impl AsRef<[u8]>) -> RlsResult<Buffer> {
    compress(data.as_ref(), CodeType::Zstd)
}

#[inline]
pub fn zstd_decompress(data: impl AsRef<[u8]>) -> RlsResult<Buffer> {
    decompress(data.as_ref(), CodeType::Zstd)
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

#[inline]
pub fn br_decompress(buf: impl AsRef<[u8]>) -> RlsResult<Buffer> {
    decompress(buf.as_ref(), CodeType::Brotli)
}

#[inline]
pub fn br_compress(buf: impl AsRef<[u8]>) -> RlsResult<Buffer> {
    compress(buf.as_ref(), CodeType::Brotli)
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

#[inline]
pub fn deflate_compress(buf: impl AsRef<[u8]>) -> RlsResult<Buffer> {
    compress(buf.as_ref(), CodeType::Deflate)
}

#[inline]
pub fn deflate_decompress(buf: impl AsRef<[u8]>) -> RlsResult<Buffer> {
    decompress(buf.as_ref(), CodeType::Deflate)
}

#[inline]
pub fn gzip_compress(buf: impl AsRef<[u8]>) -> RlsResult<Buffer> {
    compress(buf.as_ref(), CodeType::Gzip)
}

#[inline]
pub fn gzip_decompress(buf: impl AsRef<[u8]>) -> RlsResult<Buffer> {
    decompress(buf.as_ref(), CodeType::Gzip)
}

fn compress(buf: &[u8], typ: CodeType) -> RlsResult<Buffer> {
    let mut coder = TZCoder::new_compress(typ)?;
    let mut reader = Reader::from_slice(buf);
    let mut out = Writer::with_capacity(reader.size());
    coder.update(&mut reader, &mut out)?;
    coder._flush(&mut out)?;
    Ok(out)
}

fn decompress(buf: &[u8], typ: CodeType) -> RlsResult<Buffer> {
    let mut reader = Reader::from_slice(buf);
    if reader.unread_len() == 0 { return Ok(Buffer::none()); }
    let mut out = Writer::with_capacity(reader.size() * 2);
    let mut coder = TZCoder::new_decompress(typ)?;
    coder.update(&mut reader, &mut out)?;
    coder._flush(&mut out)?;
    Ok(out)
}

unsafe extern "C" {
    fn TZCode_init(coder: *mut TZCoder) -> c_int;
    fn TZCode_free(coder: *mut TZCoder);
    fn TZCode_update(coder: *const TZCoder, in_ptr: *const u8, in_len: *mut usize, out: *mut u8, out_len: *mut usize) -> CodeState;
    fn TZCode_flush(coder: *const TZCoder, out: *mut u8, out_len: *mut usize) -> CodeState;
}

#[repr(u8)]
pub enum CodeType {
    Gzip = 0,
    Deflate = 1,
    Brotli = 2,
    Zlib = 3,
    Zstd = 4,
    Null = 5,
}

#[repr(u8)]
#[derive(Debug)]
pub enum CodeState {
    ProcessOk = 0,
    StreamEnd = 1,
    BufferTooSmall = 2,
    Error = 3,
    InitError = 0xff,
}


c_struct_free!(TZCoder, TZCode_free);
#[repr(C)]
pub struct TZCoder {
    typ: CodeType,
    enc: u8,
    _rsv1: *mut c_void,
    _rsv2: *mut c_void,
    _rsv3: *mut c_void,
    _rsv4: *mut c_void,
    _rsv5: *mut c_void,
}

impl TZCoder {
    fn new(typ: CodeType, enc: u8) -> RlsResult<TZCoder> {
        let mut coder = TZCoder {
            typ,
            enc,
            _rsv1: null_mut(),
            _rsv2: null_mut(),
            _rsv3: null_mut(),
            _rsv4: null_mut(),
            _rsv5: null_mut(),
        };
        unsafe { TZCode_init(&mut coder) }.ok(CodeState::InitError)?;
        Ok(coder)
    }

    pub fn new_compress(typ: CodeType) -> RlsResult<TZCoder> {
        TZCoder::new(typ, 1)
    }

    pub fn new_decompress(typ: CodeType) -> RlsResult<TZCoder> {
        TZCoder::new(typ, 0)
    }


    fn update(&mut self, reader: &mut Reader<'_>, out: &mut Writer) -> RlsResult<bool> {
        if reader.unread_len() == 0 { return Ok(false); }
        loop {
            let mut read_len = reader.unread_len();
            let mut out_len = out.unfilled_len();
            let state = unsafe {
                TZCode_update(
                    self,
                    reader.unread_ptr(),
                    &mut read_len,
                    out.unfilled_ptr(),
                    &mut out_len,
                )
            };
            reader.add_len(read_len);
            out.add_len(out_len);
            match state {
                CodeState::StreamEnd => return Ok(true),
                CodeState::BufferTooSmall => out.resize(out.capacity() + reader.unread_len())?,
                CodeState::Error => return Err(state.into()),
                CodeState::ProcessOk => if reader.unread_len() == 0 { break; },
                CodeState::InitError => unreachable!()
            }
        }
        Ok(false)
    }

    fn _flush(&mut self, out: &mut Writer) -> RlsResult<bool> {
        loop {
            let mut out_len = out.unfilled_len();
            let state = unsafe {
                TZCode_flush(
                    self,
                    out.unfilled_ptr(),
                    &mut out_len,
                )
            };
            out.add_len(out_len);
            match state {
                CodeState::BufferTooSmall => out.resize(out.capacity() * 2)?,
                CodeState::Error => break Ok(true),
                CodeState::StreamEnd => break Ok(true),
                CodeState::ProcessOk => unreachable!(),
                CodeState::InitError => unreachable!()
            }
        }
    }
}

impl StreamDecode for TZCoder {
    fn decompress(&mut self, reader: &mut Reader<'_>, out: &mut Writer) -> RlsResult<bool> {
        self.update(reader, out)
    }

    fn flush(&mut self, out: &mut Writer) -> RlsResult<bool> {
        self._flush(out)
    }
}

impl StreamEncode for TZCoder {
    fn compress(&mut self, reader: &mut Reader<'_>, out: &mut Writer) -> Result<bool, RlsError> {
        self.update(reader, out)
    }

    fn flush(&mut self, out: &mut Writer) -> Result<bool, RlsError> {
        self._flush(out)
    }
}

#[cfg(test)]
mod tests {
    use crate::coder::{CodeType, TZCoder};
    use crate::{Buffer, Reader, Writer, coder, rand};
    use crate::coder::ext::StreamDecode;

    #[test]
    fn test_br_decompress() {
        let mut coder = TZCoder::new_decompress(CodeType::Brotli).unwrap();
        let compressed = [27, 59, 0, 248, 197, 109, 108, 188, 35, 42, 217, 147, 70, 37, 10, 74, 145, 67, 2, 167, 136, 88, 56, 154, 148, 111, 44, 175, 176, 152, 63, 84, 220, 226, 158, 42, 46, 44, 40, 152, 60, 14];
        let chunk_size = rand::random::<usize>() % 5 + 3;
        let mut out = Writer::with_capacity(1);
        for chunk in compressed.chunks(chunk_size) {
            let mut reader = Reader::from_slice(chunk);
            coder.update(&mut reader, &mut out).unwrap();
        }
        let finish = coder.flush(&mut out).unwrap();
        assert!(finish);
        assert_eq!(&out.filled(), b"dfjsdkgfsdhkgjksfyhdlfusdhgfkyudsgflsduyfgsdukfsdfgdhfgjhjhk");
        let de = coder::br_decompress(compressed).unwrap();
        assert_eq!(de.filled(), b"dfjsdkgfsdhkgjksfyhdlfusdhgfkyudsgflsduyfgsdukfsdfgdhfgjhjhk");
    }

    #[test]
    fn test_gzip_decompress() {
        let compressed = [31, 139, 8, 0, 0, 0, 0, 0, 0, 255, 109, 137, 177, 13, 0, 32, 12, 195, 206, 226, 161, 16, 85, 45, 19, 129, 129, 239, 169, 212, 181, 150, 23, 203, 2, 5, 198, 106, 112, 213, 51, 33, 104, 21, 233, 59, 227, 186, 246, 252, 93, 161, 13, 5, 58, 0, 0, 0];
        let mut coder = TZCoder::new_decompress(CodeType::Gzip).unwrap();
        let mut out = Buffer::with_capacity(1);
        let mut reader = Reader::from_slice(&compressed);
        let finish = coder.update(&mut reader, &mut out).unwrap();
        assert!(finish);
        coder.flush(&mut out).unwrap();
        assert_eq!(out.filled(), b"sdfsdfklllllllllllllllllllljsdfsdfkhsdkfhsdfsdfsdfyt7ujsre");
    }

    #[test]
    fn test_deflate_decompress() {
        let compressed = [109, 137, 177, 13, 0, 32, 12, 195, 206, 226, 161, 16, 85, 45, 19, 129, 129, 239, 169, 212, 181, 150, 23, 203, 2, 5, 198, 106, 112, 213, 51, 33, 104, 21, 233, 59, 227, 186, 246, 252];
        let mut decoder = TZCoder::new_decompress(CodeType::Deflate).unwrap();
        let mut out = Writer::with_capacity(1024);
        let mut reader = Reader::from_slice(&compressed);
        decoder.update(&mut reader, &mut out).unwrap();
        assert_eq!(out.filled(), b"sdfsdfklllllllllllllllllllljsdfsdfkhsdkfhsdfsdfsdfyt7ujsre");
    }

    #[test]
    fn test_zstd_decompress() {
        let compressed = [40, 181, 47, 253, 32, 37, 41, 1, 0, 115, 100, 102, 104, 115, 100, 102, 115, 100, 103, 103, 106, 121, 117, 116, 101, 114, 100, 102, 116, 116, 104, 102, 103, 98, 104, 106, 104, 104, 103, 115, 100, 102, 103, 100, 103, 102];
        let mut coder = TZCoder::new_decompress(CodeType::Zstd).unwrap();
        let mut out = Buffer::with_capacity(20);
        let mut reader = Reader::from_slice(&compressed);
        let finish = coder.update(&mut reader, &mut out).unwrap();
        assert!(finish);
        let finish = coder.flush(&mut out).unwrap();
        assert!(finish);
        assert_eq!(out.filled(), b"sdfhsdfsdggjyuterdftthfgbhjhhgsdfgdgf");
    }

    #[test]
    fn test_br_compress() {
        let text = "dfjsdkgfsdhkgjksfyhdlfusdhgfkyudsgflsduyfgsdukfsdfgdhfgjhjhk";
        let mut encoder = TZCoder::new_compress(CodeType::Brotli).unwrap();
        let mut compressed = Buffer::with_capacity(1024);
        let mut reader = Reader::from_slice(text.as_bytes());
        encoder.update(&mut reader, &mut compressed).unwrap();
        encoder.flush(&mut compressed).unwrap();
        assert_eq!(compressed.len(), 42);
        assert_eq!(compressed.filled(), [27, 59, 0, 248, 197, 109, 108, 188, 35, 42, 217, 147, 70, 37, 10, 74, 145, 67, 2, 167, 136, 88, 56, 154, 148, 111, 44, 175, 176, 152, 63, 84, 220, 226, 158, 42, 46, 44, 40, 152, 60, 14]);
        assert_eq!(coder::br_compress(text).unwrap().filled(), [27, 59, 0, 248, 197, 109, 108, 188, 35, 42, 217, 147, 70, 37, 10, 74, 145, 67, 2, 167, 136, 88, 56, 154, 148, 111, 44, 175, 176, 152, 63, 84, 220, 226, 158, 42, 46, 44, 40, 152, 60, 14]);
    }


    #[test]
    fn test_gzip_compress() {
        let mut coder = TZCoder::new_compress(CodeType::Gzip).unwrap();
        let mut out = Buffer::with_capacity(1024);
        let mut reader = Reader::from_slice(b"sdfsdfklllllllllllllllllllljsdfsdfkhsdkfhsdfsdfsdfyt7ujsre");
        coder.update(&mut reader, &mut out).unwrap();
        let finish = coder.flush(&mut out).unwrap();
        assert!(finish);
        assert_eq!(out.filled(), [31, 139, 8, 0, 0, 0, 0, 0, 0, 10, 43, 78, 73, 43, 78, 73, 203, 206, 193, 2, 178, 138, 33, 114, 25, 197, 41, 217, 105, 25, 16, 78, 113, 74, 90, 101, 137, 121, 105, 86, 113, 81, 42, 0, 93, 161, 13, 5, 58, 0, 0, 0]);
    }

    #[test]
    fn test_deflate_compress() {
        let mut encoder = TZCoder::new_compress(CodeType::Deflate).unwrap();
        let mut out = Buffer::with_capacity(1024);
        let mut reader = Reader::from_slice(b"sdfsdfklllllllllllllllllllljsdfsdfkhsdkfhsdfsdfsdfyt7ujsre");
        encoder.update(&mut reader, &mut out).unwrap();
        let finish = encoder.flush(&mut out).unwrap();
        assert!(finish);
        assert_eq!(out.filled(), [43, 78, 73, 43, 78, 73, 203, 206, 193, 2, 178, 138, 33, 114, 25, 197, 41, 217, 105, 25, 16, 78, 113, 74, 90, 101, 137, 121, 105, 86, 113, 81, 42, 0]);
    }

    #[test]
    fn test_zstd_compress() {
        let mut encoder = TZCoder::new_compress(CodeType::Zstd).unwrap();
        let mut out = Buffer::with_capacity(1024);
        let mut reader = Reader::from_slice("sdfhsdfsdggjyuterdftthfgbhjhhgsdfgdgf".as_bytes());
        encoder.update(&mut reader, &mut out).unwrap();
        encoder.flush(&mut out).unwrap();
        assert_eq!(out.filled(), [40, 181, 47, 253, 0, 88, 41, 1, 0, 115, 100, 102, 104, 115, 100, 102, 115, 100, 103, 103, 106, 121, 117, 116, 101, 114, 100, 102, 116, 116, 104, 102, 103, 98, 104, 106, 104, 104, 103, 115, 100, 102, 103, 100, 103, 102]);
    }

    #[test]
    fn test_code_null() {
        let mut coder = TZCoder::new_decompress(CodeType::Null).unwrap();
        let mut reader = Reader::from_slice("sdfhsdfsdggjyuterdftthfgbhjhhgsdfgdgf".as_bytes());
        let mut out = Writer::with_capacity(reader.size());
        coder.update(&mut reader, &mut out).unwrap();
        let finish = coder.flush(&mut out).unwrap();
        assert!(finish);
        assert_eq!(out.filled(), b"sdfhsdfsdggjyuterdftthfgbhjhhgsdfgdgf")
    }
}