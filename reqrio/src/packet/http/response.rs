use crate::error::HlsResult;
use crate::json::JsonValue;
use crate::*;
use reqtls::coder::{BrotliDecoder, ChunkDecoder, CodingError, DeflateStream, StreamDecode, ZstdDecoder};
use std::mem;
use std::str::Utf8Error;

pub struct Response {
    #[cfg(feature = "export")]
    pub(crate) sid: u64,
    header: Header,
    pub(crate) raw: Writer,
    coder: Option<Box<dyn StreamDecode + Send + Sync>>,
    read_size: usize,
    h2_buffer: Writer,
}

impl Default for Response {
    fn default() -> Self {
        Response {
            #[cfg(feature = "export")]
            sid: 0,
            header: Header::default(),
            raw: Writer::with_capacity(8192),
            coder: None,
            read_size: 0,
            h2_buffer: Writer::with_capacity(8192),
        }
    }
}

impl Response {
    pub fn new() -> Response {
        Response::default()
    }

    #[cfg(feature = "export")]
    pub(crate) fn new_header(header: Header) -> Response {
        Response {
            sid: 0,
            header,
            raw: Writer::with_capacity(0),
            coder: None,
            read_size: 0,
            h2_buffer: Writer::with_capacity(0),
        }
    }

    fn write_buffer(buffer: &mut Writer, buf: &[u8]) -> Result<usize, BufferError> {
        loop {
            match buffer.write_slice(buf) {
                Ok(_) => break,
                Err(BufferError::CapacityTooSmall { .. }) => {
                    let size = buf.len() - buffer.unfilled_len();
                    buffer.resize(size)?
                }
                Err(e) => return Err(e),
            }
        }
        Ok(buf.len())
    }

    pub(crate) fn extend_body(&mut self, buf: &[u8]) -> HlsResult<(usize, bool)> {
        match self.coder {
            None => {
                let len = self.header.content_length().unwrap_or(self.raw.len() + buf.len());
                let read_len = if self.raw.len() + buf.len() >= len { len - self.raw.len() } else { buf.len() };
                let read_size = Response::write_buffer(&mut self.raw, &buf[..read_len])?;
                self.read_size += read_size;
                Ok((read_size, self.read_size >= len))
            }
            Some(ref mut coder) => {
                let mut reader = Reader::from_slice(buf);
                loop {
                    let res = if reader.unread_len() == 0 && reader.position() != 0 {
                        coder.flush(&mut self.raw)
                    } else {
                        let mut res = coder.decompress(&mut reader, &mut self.raw);
                        if coder.finish() { res = coder.flush(&mut self.raw); }
                        res
                    };
                    match res {
                        Ok(_) => break,
                        Err(CodingError::Buffer(BufferError::CapacityTooSmall { .. })) => {
                            self.raw.resize(self.raw.capacity() * 2)?;
                        }
                        Err(e) => return Err(e.into()),
                    }
                };
                self.read_size += reader.position();
                let len = self.header.content_length().unwrap_or(0);
                Ok((reader.position(), coder.finish() || (len != 0 && self.read_size >= len)))
            }
        }
    }

    pub(crate) fn make_coding(&mut self) -> HlsResult<()> {
        let chunked = self.header.get_str("transfer-encoding").unwrap_or("").trim();
        let encoding = self.header.content_encoding().unwrap_or("").trim();
        #[cfg(feature = "log")]
        debug!("[Response] make coding: chunk={}; encoding={}", chunked=="chunked", encoding);
        match (chunked, encoding) {
            ("chunked", "gzip") => {
                let gzip = DeflateStream::new_decompress(DeflateStream::GZIP)?;
                let coding = ChunkDecoder::new(gzip);
                self.coder = Some(Box::new(coding))
            }
            ("chunked", "deflate") => {
                let deflate = DeflateStream::new_decompress(DeflateStream::DEFLATE)?;
                let coding = ChunkDecoder::new(deflate);
                self.coder = Some(Box::new(coding))
            }
            ("chunked", "br") => {
                let coding = ChunkDecoder::new(BrotliDecoder::new()?);
                self.coder = Some(Box::new(coding))
            }
            ("chunked", "zstd") => {
                let coding = ChunkDecoder::new(ZstdDecoder::new()?);
                self.coder = Some(Box::new(coding))
            }
            ("chunked", "") => self.coder = Some(Box::new(ChunkDecoder::new(()))),
            (_, "gzip") => self.coder = Some(Box::new(DeflateStream::new_decompress(DeflateStream::GZIP)?)),
            (_, "deflate") => self.coder = Some(Box::new(DeflateStream::new_decompress(DeflateStream::DEFLATE)?)),
            (_, "br") => self.coder = Some(Box::new(BrotliDecoder::new()?)),
            (_, "zstd") => self.coder = Some(Box::new(ZstdDecoder::new()?)),
            (_, _) => {}
        }
        Ok(())
    }

    pub fn extend_buffer(&mut self, buffer: &mut Writer) -> HlsResult<bool> {
        if self.header.is_empty() {
            let pos = buffer.filled().windows(HTTP_GAP.len()).position(|w| w == HTTP_GAP);
            let Some(pos) = pos else { return Ok(false) };
            let hdr_str = std::str::from_utf8(&buffer.filled()[..pos])?;
            self.header = Header::try_from(hdr_str)?;
            buffer.used_empty(pos + HTTP_GAP.len());
            self.make_coding()?;
        }
        let (size, finish) = self.extend_body(buffer.filled())?;
        buffer.used_empty(size);
        Ok(finish)
    }

    pub fn push_raw_slice(&mut self, raw: &[u8]) -> HlsResult<()> {
        if self.header.is_empty() {
            Response::write_buffer(&mut self.h2_buffer, raw)?;
            Ok(())
        } else {
            let mut buffer = mem::replace(&mut self.h2_buffer, Writer::with_capacity(0));
            let _ = buffer.check_move(raw.len());
            Response::write_buffer(&mut buffer, raw)?;
            let (size, _) = self.extend_body(buffer.filled())?;
            buffer.used_empty(size);
            drop(mem::replace(&mut self.h2_buffer, buffer));
            Ok(())
        }
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn header_mut(&mut self) -> &mut Header { &mut self.header }

    pub fn set_header(&mut self, header: Header) -> HlsResult<()> {
        self.header = header;
        self.make_coding()
    }

    pub fn raw_string(&self) -> String {
        let mut header = self.header.to_string();
        let body = self.as_text().unwrap_or("(二进制数据)");
        header += "\r\n\r\n";
        header + body
    }


    pub fn json(self) -> HlsResult<JsonValue> {
        Ok(json::from_bytes(self.raw.filled())?)
    }

    pub fn as_text(&self) -> Result<&str, Utf8Error> {
        std::str::from_utf8(self.raw.filled())
    }

    pub fn text(self) -> Result<String, Utf8Error> {
        Ok(self.as_text()?.to_owned())
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.raw.filled()
    }

    pub fn bytes(self) -> Vec<u8> {
        self.raw.filled().to_vec()
    }
}