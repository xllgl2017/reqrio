use crate::coder::ext::StreamDecode;
use crate::coder::{CodeType, TZCoder};
use crate::error::RlsResult;
use crate::{BufferError, Reader, RlsError, Writer};
use std::cmp::min;
use std::mem;

pub struct ChunkDecoder {
    coder: TZCoder,
    /// Size required for the current data block.
    want_size: usize,
    /// Number of bytes already read from the current data block.
    read_size: usize,
    /// trim end
    trim_end: bool,
    finish: bool,
    remain: Vec<u8>,
}

impl ChunkDecoder {
    pub fn new(typ: CodeType) -> RlsResult<Self> {
        Ok(ChunkDecoder {
            coder: TZCoder::new_decompress(typ)?,
            want_size: 0,
            read_size: 0,
            trim_end: true,
            finish: false,
            remain: Vec::with_capacity(6),
        })
    }

    pub fn finish(&self) -> bool { self.finish }

    fn handle_decomp(&mut self, except: usize, reader: &mut Reader<'_>, out: &mut Writer) -> RlsResult<()> {
        let handle_size = min(except, reader.unread_len());
        let mut chunk_reader = reader.read_reader(handle_size)?;
        self.coder.update(&mut chunk_reader, out)?;
        self.read_size += handle_size;
        if handle_size < except { return Err(BufferError::Insufficient.into()); }
        if reader.unread_len() >= 2 {
            reader.read_slice(2)?;
            self.trim_end = true;
        }
        Ok(())
    }

    fn handle_chunk<'a>(&mut self, reader: &mut Reader<'a>, out: &mut Writer) -> Result<(), RlsError> {
        while reader.unread_len() > 0 {
            let len = reader.read_to(b"\r\n").ok_or(BufferError::Insufficient)?;
            self.finish = len == [48];
            let len = usize::from_str_radix(std::str::from_utf8(len)?, 16)?;
            self.want_size = len;
            self.read_size = 0;
            self.trim_end = false;
            reader.read_slice(2)?;
            if self.finish {
                reader.read_slice(2)?;
                self.trim_end = true;
                break;
            }
            self.handle_decomp(len, reader, out)?
        }
        Ok(())
    }
}

impl ChunkDecoder {
    fn _decompress(&mut self, reader: &mut Reader, out: &mut Writer) -> RlsResult<bool> {
        if self.want_size == self.read_size {
            if !self.trim_end {
                reader.read_slice(2)?;
                self.trim_end = true;
            }
        } else {
            let need = self.want_size - self.read_size;
            self.handle_decomp(need, reader, out)?;
        }
        self.handle_chunk(reader, out)?;
        Ok(self.finish && self.trim_end)
    }
}

impl StreamDecode for ChunkDecoder {
    fn decompress(&mut self, reader: &mut Reader<'_>, out: &mut Writer) -> RlsResult<bool> {
        let res = match self.remain.is_empty() {
            true => self._decompress(reader, out),
            false => {
                if self.remain.last() == Some(&13) {
                    self.remain.push(reader.read_u8()?);
                } else {
                    let other = reader.read_to(b"\r\n").ok_or(BufferError::Insufficient)?;
                    self.remain.extend_from_slice(other);
                    self.remain.extend_from_slice(reader.read_slice(2)?);
                }
                let remain = mem::take(&mut self.remain);
                let mut remain_reader = Reader::from_slice(&remain);
                match self._decompress(&mut remain_reader, out) {
                    Ok(_) => {}
                    Err(RlsError::Buffer(BufferError::Insufficient | BufferError::IndexOutBound { .. })) => {}
                    Err(e) => return Err(e)
                }
                self.remain = remain;
                self.remain.clear();
                self._decompress(reader, out)
            }
        };
        match res {
            Ok(_) => Ok(self.finish && self.trim_end),
            Err(RlsError::Buffer(BufferError::Insufficient)) |
            Err(RlsError::Buffer(BufferError::IndexOutBound { .. })) => {
                self.remain.extend_from_slice(reader.read_slice(reader.unread_len())?);
                Ok(false)
            }
            Err(e) => Err(e)
        }
    }

    fn flush(&mut self, writer: &mut Writer) -> Result<bool, RlsError> {
        self.coder.flush(writer)
    }
}

#[cfg(test)]
mod chunk_tests {
    use crate::coder::CodeType;
    use crate::coder::chunk::ChunkDecoder;
    use crate::coder::ext::StreamDecode;
    use crate::{Reader, Writer, rand};
    use std::fs;

    #[test]
    fn test_chunk_decode() {
        let mut decoder = ChunkDecoder::new(CodeType::Null).unwrap();
        let context = b"10\r";
        let mut out = Writer::with_capacity(1024);
        decoder.decompress(&mut Reader::from_slice(context), &mut out).unwrap();
        let context = b"\nfjksdfhjdsfjdskj\r\n0\r\n\r\n";
        decoder.decompress(&mut Reader::from_slice(context), &mut out).unwrap();
        assert_eq!(out.filled(), b"fjksdfhjdsfjdskj");
        assert!(decoder.finish);
    }

    #[test]
    fn test_chunk_gzip() {
        let data = fs::read("../data/coder/chunk_gzip.bin").unwrap();
        let mut decompressed = Writer::with_capacity(data.len() * 5);
        let mut coder = ChunkDecoder::new(CodeType::Gzip).unwrap();
        let chunk_size = rand::random::<usize>() % (data.len() / 20);
        for chunk in data.chunks(chunk_size) {
            let mut reader = Reader::from_slice(chunk);
            while reader.unread_len() > 0 {
                coder.decompress(&mut reader, &mut decompressed).unwrap();
            }
        }
        let finish = coder.flush(&mut decompressed).unwrap();
        assert!(finish);
        assert!(std::str::from_utf8(decompressed.filled()).is_ok())
    }

    #[test]
    fn test_chunk_brotli() {
        let data = fs::read("../data/coder/chunk_br.bin").unwrap();
        let mut decompressed = Writer::with_capacity(8192);
        let mut coder = ChunkDecoder::new(CodeType::Brotli).unwrap();
        let chunk_size = rand::random::<usize>() % (data.len() / 20);
        println!("{}", chunk_size);
        for chunk in data.chunks(chunk_size) {
            let mut reader = Reader::from_slice(chunk);
            coder.decompress(&mut reader, &mut decompressed).unwrap();
        }
        let finish = coder.flush(&mut decompressed).unwrap();
        assert!(finish);
        assert!(std::str::from_utf8(decompressed.filled()).is_ok())
    }
}