use crate::error::HlsResult;
use crate::json::JsonValue;
use crate::pack::PackItem;
use crate::*;
use reqtls::coder::{BrotliDecoder, ChunkDecoder, CodingError, DeflateStream, StreamDecode, ZstdDecoder};
use std::borrow::Cow;
use std::fmt::{Display, Formatter};
use std::mem;
use std::str::Utf8Error;

#[repr(C)]
pub struct Response {
    //share c
    #[cfg(feature = "export")]
    pub(crate) sid: u64,
    #[deprecated]
    pub(crate) method: Method,
    status: HttpStatus,
    alpn: ALPN,
    pub(crate) raw: Writer,
    //rust owned
    #[deprecated]
    pub(crate) uri: Uri,
    pub(crate) header: Header,
    #[deprecated]
    coder: Option<Box<dyn StreamDecode + Send + Sync>>,
    read_size: usize,
    h2_buffer: Writer,
}

impl Default for Response {
    fn default() -> Self {
        Response {
            method: Method::GET,
            alpn: Default::default(),
            uri: Default::default(),
            status: HttpStatus::None,
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

    pub fn make_coding(&mut self) -> HlsResult<()> {
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

    pub fn push_pack_item(&mut self, item: &PackItem) -> HlsResult<()> {
        self.header.insert(item.name(), HeaderValue::String(Cow::Owned(item.value().to_string())));
        match item.name() {
            ":method" => self.method = Method::try_from(item.value())?,
            ":path" => self.uri = Uri::try_from(item.value())?,
            ":status" => self.status = HttpStatus::new(item.value().parse::<u16>()?),
            _ => {}
        }
        Ok(())
    }

    fn parse_header(&mut self, hdr: &str) -> HlsResult<()> {
        for (index, line) in hdr.lines().enumerate() {
            if index == 0 {
                match line.starts_with("HTTP/1") {
                    true => {
                        let mut items = line.split(" ");
                        self.alpn = ALPN::from_slice(items.next().unwrap_or("").to_lowercase().as_bytes());
                        let status = items.next().and_then(|x| x.parse().ok()).unwrap_or(0);
                        self.status = HttpStatus::new(status);
                    }
                    false => {
                        let mut items = line.split(" ");
                        self.method = Method::try_from(items.next().unwrap_or("GET")).unwrap_or(Method::GET);
                        self.uri = Uri::try_from(items.next().unwrap_or(""))?;
                        self.alpn = ALPN::from_slice(items.next().unwrap_or("").to_lowercase().as_bytes());
                    }
                }
                continue;
            }
            let pos = line.find(':').unwrap_or(line.len());
            let name = &line[..pos];
            let value = if pos == line.len() { "" } else { line[pos + 1..].trim() };
            self.header.insert(name, value)
        }
        Ok(())
    }

    pub fn extend_buffer(&mut self, buffer: &mut Writer) -> HlsResult<bool> {
        if self.alpn.is_empty() {
            let pos = buffer.filled().windows(HTTP_GAP.len()).position(|w| w == HTTP_GAP);
            let Some(pos) = pos else { return Ok(false) };
            self.parse_header(std::str::from_utf8(&buffer.filled()[..pos])?)?;
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

    pub fn parse_raw(raw: impl AsRef<[u8]>) -> HlsResult<Response> {
        let raw = raw.as_ref();
        let mut resp = Response::default();
        let mut buffer = Buffer::from_ptr(raw.as_ptr().cast_mut(), raw.len());
        resp.extend_buffer(&mut buffer)?;
        assert!(buffer.is_empty());
        Ok(resp)
    }


    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn header_mut(&mut self) -> &mut Header { &mut self.header }

    pub fn set_header(&mut self, header: Header) -> HlsResult<()> {
        self.header = header;
        self.make_coding()
    }

    pub fn json(self) -> HlsResult<JsonValue> { Ok(json::from_bytes(self.raw.filled())?) }

    pub fn as_text(&self) -> Result<&str, Utf8Error> { std::str::from_utf8(self.raw.filled()) }

    pub fn text(self) -> Result<String, Utf8Error> { Ok(self.as_text()?.to_owned()) }

    pub fn as_bytes(&self) -> &[u8] { self.raw.filled() }

    pub fn bytes(self) -> Vec<u8> { self.raw.filled().to_vec() }

    ///only for resp
    pub fn status(&self) -> HttpStatus { self.status }

    #[deprecated]
    ///only for req
    pub fn method(&self) -> Method { self.method }

    #[deprecated]
    ///only for req
    pub fn uri(&self) -> &Uri { &self.uri }
}

impl Display for Response {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if !self.alpn.is_empty() {
            if self.uri.path().is_empty() {
                write!(f, "{} {} {}", self.alpn, self.status.code(), self.status.spec())?;
                write!(f, "\r\n")?;
            } else {
                write!(f, "{} {} {}", self.method, self.uri, self.alpn)?;
                write!(f, "\r\n")?;
            }
        }
        write!(f, "{}", self.header)?;
        let body = self.as_text().unwrap_or("(二进制数据)");
        if !body.is_empty() {
            write!(f, "\r\n\r\n")?;
            write!(f, "{}", body)?;
            write!(f, "\r\n")?;
        }
        Ok(())
    }
}