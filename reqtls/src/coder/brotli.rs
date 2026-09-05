use crate::coder::ext::{StreamDecode, StreamEncode};
use crate::coder::CodingError;
use crate::ffi::CPointer;
use crate::{ffi, BufferError, Reader, Writer};
use std::ffi::c_int;

#[repr(C)]
#[allow(non_camel_case_types)]
struct BROTLI_DECODER {
    _unused: [u8; 0],
}
ffi::c_pointer_free!(BROTLI_DECODER, BROTLI_DECODER_free);

#[repr(C)]
#[allow(non_camel_case_types)]
struct BROTLI_ENCODER {
    _unused: [u8; 0],
}
ffi::c_pointer_free!(BROTLI_ENCODER, BROTLI_ENCODER_free);

unsafe extern "C" {
    fn BROTLI_DECODER_new() -> *mut BROTLI_DECODER;
    fn BROTLI_DECODER_free(decoder: *mut BROTLI_DECODER);
    fn BROTLI_DECODER_decompress(
        decoder: *const BROTLI_DECODER,
        in_: *const u8,
        in_len: *mut usize,
        out: *mut u8,
        out_len: *mut usize,
        total: *mut usize,
    ) -> BrotliState;
    fn BROTLI_ENCODER_new(quality: u32, lg_win: u32) -> *mut BROTLI_ENCODER;
    fn BROTLI_ENCODER_free(encoder: *mut BROTLI_ENCODER);
    fn BROTLI_ENCODER_compress(
        encoder: *const BROTLI_ENCODER,
        in_: *const u8,
        in_len: *mut usize,
        out: *mut u8,
        out_len: *mut usize,
        total: *mut usize,
    ) -> c_int;
    fn BROTLI_ENCODER_flush(
        encoder: *const BROTLI_ENCODER,
        out: *mut u8,
        out_len: *mut usize,
        total: *mut usize,
    ) -> c_int;
}

#[repr(C)]
#[derive(Debug, PartialEq)]
#[allow(unused)]
enum BrotliState {
    Error = 0,
    Finish = 1,
    Continue = 2,
    BufferTooSmall = 3,
}


pub struct BrotliDecoder {
    ptr: CPointer<BROTLI_DECODER>,
    total_len: usize,
    need_buffer: bool,
    finish: bool,
}

impl BrotliDecoder {
    pub fn new() -> Result<BrotliDecoder, CodingError> {
        let ptr = unsafe { BROTLI_DECODER_new() };
        let ptr = CPointer::new_checked(ptr, CodingError::NewBrDecoderError)?;
        Ok(BrotliDecoder {
            ptr,
            total_len: 0,
            need_buffer: false,
            finish: false,
        })
    }
}

impl StreamDecode for BrotliDecoder {
    fn decompress(&mut self, reader: &mut Reader<'_>, out: &mut Writer) -> Result<(), CodingError> {
        let mut unread_len = reader.unread_len();
        let mut remain_buffer_size = out.unfilled_len();
        while self.need_buffer || unread_len > 0 {
            self.need_buffer = false;
            let res = unsafe {
                BROTLI_DECODER_decompress(
                    self.ptr.as_ptr(),
                    reader.unread_ptr(),
                    &mut unread_len,
                    out.unfilled_ptr(),
                    &mut remain_buffer_size,
                    &mut self.total_len,
                )
            };
            reader.add_len(reader.unread_len() - unread_len);
            out.add_len(out.unfilled_len() - remain_buffer_size);
            assert_eq!(out.unfilled_len(), remain_buffer_size);
            self.finish = matches!(res, BrotliState::Finish);
            match res {
                BrotliState::Error => return Err(CodingError::BrDecompressFail),
                BrotliState::Finish => break,
                BrotliState::Continue => continue,
                BrotliState::BufferTooSmall => {
                    self.need_buffer = true;
                    return Err(BufferError::CapacityTooSmall {
                        needed: out.len() + unread_len,
                        current: out.len(),
                        file: file!(),
                        line: line!(),
                    }.into());
                }
            }
        }
        assert_eq!(unread_len, 0);
        out.add_len(out.unfilled_len() - remain_buffer_size);
        Ok(())
    }

    fn flush(&mut self, out: &mut Writer) -> Result<(), CodingError> {
        self.decompress(&mut Reader::from_slice(&[]), out)
    }

    fn finish(&self) -> bool {
        self.finish
    }
}

pub struct BrotliEncoder {
    ptr: CPointer<BROTLI_ENCODER>,
    total_len: usize,
}

impl BrotliEncoder {
    pub fn new() -> Result<BrotliEncoder, CodingError> {
        let ptr = unsafe { BROTLI_ENCODER_new(11, 22) };
        let ptr = CPointer::new_checked(ptr, CodingError::NewBrEncoderError)?;
        Ok(BrotliEncoder {
            ptr,
            total_len: 0,
        })
    }
}


impl StreamEncode for BrotliEncoder {
    fn compress(&mut self, buf: &[u8], out: &mut [u8]) -> Result<usize, CodingError> {
        let mut remain_in_size = buf.len();
        let mut remain_buffer_size = out.len();
        let ret = unsafe {
            BROTLI_ENCODER_compress(
                self.ptr.as_ptr(),
                buf.as_ptr(),
                &mut remain_in_size,
                out.as_mut_ptr(),
                &mut remain_buffer_size,
                &mut self.total_len,
            )
        };
        if ret != 1 { return Err(CodingError::BrCompressFail); }
        assert_eq!(remain_in_size, 0);
        Ok(out.len() - remain_buffer_size)
    }

    fn finalize(&mut self, out: &mut [u8]) -> Result<usize, CodingError> {
        let mut remain_buffer_size = out.len();
        let ret = unsafe {
            BROTLI_ENCODER_flush(
                self.ptr.as_ptr(),
                out.as_mut_ptr(),
                &mut remain_buffer_size,
                &mut self.total_len,
            )
        };
        if ret != 1 { return Err(CodingError::BrFlushFail); }
        Ok(out.len() - remain_buffer_size)
    }
}

#[cfg(test)]
mod brotli_test {
    use crate::coder::brotli::{BrotliDecoder, BrotliEncoder};
    use crate::coder::ext::{StreamDecode, StreamEncode};
    use crate::{coder, Writer, Reader};

    #[test]
    fn test_brotli_decoder() {
        let mut decode = BrotliDecoder::new().unwrap();
        let mut out = vec![0; 1];
        let mut decompressed = Writer::from_ptr(out.as_mut());
        let compressed = [27, 59, 0, 248, 197, 109, 108, 188, 35, 42, 217, 147, 70, 37, 10, 74, 145, 67, 2, 167, 136, 88, 56, 154, 148, 111, 44, 175, 176, 152, 63, 84, 220, 226, 158, 42, 46, 44, 40, 152, 60, 14];
        let mut reader = Reader::from_slice(&compressed);
        let res = decode.decompress(&mut reader, &mut decompressed);
        assert!(res.is_err());
        out.resize(1024, 0);
        let wrote = decompressed.filled().len();
        let mut decompressed = Writer::from_ptr(out.as_mut());
        decompressed.add_len(wrote);
        decode.flush(&mut decompressed).unwrap();
        // decode.decompress(&mut reader, &mut decompressed).unwrap();
        assert_eq!(&decompressed.filled(), b"dfjsdkgfsdhkgjksfyhdlfusdhgfkyudsgflsduyfgsdukfsdfgdhfgjhjhk");
        let de = coder::br_decompress(compressed).unwrap();
        assert_eq!(de, b"dfjsdkgfsdhkgjksfyhdlfusdhgfkyudsgflsduyfgsdukfsdfgdhfgjhjhk");
    }

    #[test]
    fn test_brotli_encoder() {
        let text = "dfjsdkgfsdhkgjksfyhdlfusdhgfkyudsgflsduyfgsdukfsdfgdhfgjhjhk";
        let mut encoder = BrotliEncoder::new().unwrap();
        let mut compressed = vec![0; 1024];
        let len1 = encoder.compress(text.as_bytes(), compressed.as_mut()).unwrap();
        let len2 = encoder.finalize(&mut compressed[len1..]).unwrap();
        assert_eq!(len1 + len2, 42);
        assert_eq!(&compressed[..len1 + len2], [27, 59, 0, 248, 197, 109, 108, 188, 35, 42, 217, 147, 70, 37, 10, 74, 145, 67, 2, 167, 136, 88, 56, 154, 148, 111, 44, 175, 176, 152, 63, 84, 220, 226, 158, 42, 46, 44, 40, 152, 60, 14]);
        assert_eq!(coder::br_compress(text).unwrap(), [27, 59, 0, 248, 197, 109, 108, 188, 35, 42, 217, 147, 70, 37, 10, 74, 145, 67, 2, 167, 136, 88, 56, 154, 148, 111, 44, 175, 176, 152, 63, 84, 220, 226, 158, 42, 46, 44, 40, 152, 60, 14]);


        let mut decompressed = Writer::with_capacity(1024);
        let mut decode = BrotliDecoder::new().unwrap();
        let mut reader = Reader::from_slice(&compressed[..len1 + len2]);
        decode.decompress(&mut reader, &mut decompressed).unwrap();
        assert_eq!(decompressed.filled(), b"dfjsdkgfsdhkgjksfyhdlfusdhgfkyudsgflsduyfgsdukfsdfgdhfgjhjhk");
    }
}