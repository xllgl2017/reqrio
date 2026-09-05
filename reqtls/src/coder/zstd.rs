use crate::boring::BoringResExt;
use crate::coder::ext::{StreamDecode, StreamEncode};
use crate::coder::CodingError;
use crate::ffi::{self, CPointer};
use crate::{BufferError, Reader, WriteExt};
use std::os::raw::c_int;

#[repr(C)]
#[allow(non_camel_case_types)]
struct ZSTD_DECODER {
    _unused: [u8; 0],
}
ffi::c_pointer_free!(ZSTD_DECODER, ZSTD_DECODER_free);
#[repr(C)]
#[allow(non_camel_case_types)]
struct ZSTD_ENCODER {
    _unused: [u8; 0],
}
ffi::c_pointer_free!(ZSTD_ENCODER, ZSTD_ENCODER_free);

unsafe extern "C" {
    fn ZSTD_DECODER_new() -> *mut ZSTD_DECODER;
    fn ZSTD_DECODER_free(decoder: *mut ZSTD_ENCODER);
    fn ZSTD_DECODER_decompress(
        decoder: *const ZSTD_DECODER,
        data: *const u8,
        data_len: *mut usize,
        out: *mut u8,
        out_len: *mut usize,
    ) -> c_int;

    fn ZSTD_ENCODER_new(level: i32) -> *mut ZSTD_ENCODER;
    fn ZSTD_ENCODER_free(encoder: *mut ZSTD_ENCODER);
    fn ZSTD_ENCODER_compress(
        encoder: *const ZSTD_ENCODER,
        data: *const u8,
        data_len: *mut usize,
        out: *mut u8,
        out_len: *mut usize,
    ) -> c_int;
    fn ZSTD_ENCODER_flush(encoder: *const ZSTD_ENCODER, out: *mut u8, out_len: *mut usize) -> c_int;
}


pub struct ZstdDecoder(CPointer<ZSTD_DECODER>);

impl ZstdDecoder {
    pub fn new() -> Result<ZstdDecoder, CodingError> {
        let ptr = unsafe { ZSTD_DECODER_new() };
        let ptr = CPointer::new_checked(ptr, CodingError::NewZstdDecoderFail)?;
        Ok(ZstdDecoder(ptr))
    }
}

impl<W: WriteExt> StreamDecode<W> for ZstdDecoder {
    fn decompress(&mut self, reader: &mut Reader<'_>, out: &mut W) -> Result<(), CodingError> {
        let mut out_len = out.unfilled_len();
        let mut used_in = reader.unread_len();
        unsafe {
            ZSTD_DECODER_decompress(
                self.0.as_ptr(),
                reader.unread_ptr(),
                &mut used_in,
                out.unfilled_ptr(),
                &mut out_len,
            )
        }.ok(CodingError::ZstdDecodeError)?;
        reader.add_len(used_in);
        out.add_len(out_len);
        if out.unfilled_len() == 0 {
            return Err(CodingError::Buffer(BufferError::CapacityTooSmall {
                current: out.capacity(),
                file: file!(),
                needed: out.capacity() + 1024,
                line: line!(),
            }));
        }
        Ok(())
    }

    fn flush(&mut self, out: &mut W) -> Result<(), CodingError> {
        self.decompress(&mut Reader::from_slice(&[]), out)
    }

    fn finish(&self) -> bool {
        false
    }
}

pub struct ZstdEncoder(CPointer<ZSTD_ENCODER>);

impl ZstdEncoder {
    pub fn new() -> Result<ZstdEncoder, CodingError> {
        let ptr = unsafe { ZSTD_ENCODER_new(3) };
        let ptr = CPointer::new_checked(ptr, CodingError::NewZstdEncoderFail)?;
        Ok(ZstdEncoder(ptr))
    }
}

impl StreamEncode for ZstdEncoder {
    fn compress(&mut self, data: &[u8], out: &mut [u8]) -> Result<usize, CodingError> {
        let mut out_len = out.len();
        let mut remaining = data.len();
        unsafe {
            ZSTD_ENCODER_compress(
                self.0.as_ptr(),
                data.as_ptr(),
                &mut remaining,
                out.as_mut_ptr(),
                &mut out_len,
            )
        }.ok(CodingError::ZstdEncodeError)?;
        Ok(out_len)
    }

    fn finalize(&mut self, out: &mut [u8]) -> Result<usize, CodingError> {
        let mut out_len = out.len();
        unsafe {
            ZSTD_ENCODER_flush(
                self.0.as_ptr(),
                out.as_mut_ptr(),
                &mut out_len,
            )
        }.ok(CodingError::ZstdFlushError)?;
        Ok(out_len)
    }
}

#[cfg(test)]
mod zstd_tests {
    use crate::coder::ext::{StreamDecode, StreamEncode};
    use crate::coder::zstd::{ZstdDecoder, ZstdEncoder};
    use crate::{coder, Buffer, Reader, WriteExt};

    #[test]
    fn test_zstd() {
        let compressed = [40, 181, 47, 253, 32, 37, 41, 1, 0, 115, 100, 102, 104, 115, 100, 102, 115, 100, 103, 103, 106, 121, 117, 116, 101, 114, 100, 102, 116, 116, 104, 102, 103, 98, 104, 106, 104, 104, 103, 115, 100, 102, 103, 100, 103, 102];
        let mut decoder = ZstdDecoder::new().unwrap();
        let mut out = vec![0; 1];
        let mut writer = Buffer::from_ptr(out.as_mut());
        let mut reader = Reader::from_slice(&compressed);
        let res = decoder.decompress(&mut reader, &mut writer);
        assert!(res.is_err());

        out.resize(1024, 0);
        let wrote = writer.filled().len();
        let mut writer = Buffer::from_ptr(out.as_mut());
        writer.add_len(wrote);
        decoder.flush(&mut writer).unwrap();
        assert_eq!(writer.filled(), b"sdfhsdfsdggjyuterdftthfgbhjhhgsdfgdgf");


        let mut encoder = ZstdEncoder::new().unwrap();
        let mut out = [0; 1024];
        let len1 = encoder.compress(b"sdfhsdfsdggjyuterdftthfgbhjhhgsdfgdgf", &mut out).unwrap();
        let len2 = encoder.finalize(&mut out[len1..]).unwrap();
        assert_eq!(coder::zstd_decompress(&out[..len1 + len2]).unwrap(), b"sdfhsdfsdggjyuterdftthfgbhjhhgsdfgdgf");
    }
}
