use std::borrow::Cow;
use std::cmp::min;
use reqtls::coder::*;
use crate::*;
use crate::error::HlsResult;
use crate::pack::PackItem;
use crate::packet::Request;

pub struct SendParam<'a> {
    pub method: Method,
    pub url: &'a Url,
    pub header: &'a Header,
    pub body: Body<'a>,
    pub priority: bool,
    pub weight: u8,
}

#[repr(C)]
pub struct StreamMessage {
    #[cfg(feature = "export")]
    pub sid: u64,
    pub status: HttpStatus,
    pub alpn: ALPN,
    pub body: Buffer,
    pub header: Header,

    pub method: Method,
    pub uri: Uri,
    pub remain: usize,
    pub coder: Option<Box<dyn StreamDecode + Send + Sync>>,
}

impl Default for StreamMessage {
    fn default() -> Self {
        StreamMessage {
            #[cfg(feature = "export")]
            sid: 0,
            coder: None,
            remain: 0,
            header: Default::default(),
            body: Writer::with_capacity(1024),
            alpn: Default::default(),
            uri: Default::default(),
            status: HttpStatus::None,
            method: Method::GET,
        }
    }
}


impl StreamMessage {
    pub fn new(_sid: u64) -> StreamMessage {
        StreamMessage {
            #[cfg(feature = "export")]
            sid: _sid,
            body: Writer::with_capacity(8192),
            ..Default::default()
        }
    }

    pub fn make_coding(&mut self) -> HlsResult<()> {
        let chunked = self.header.get_str("transfer-encoding").unwrap_or("").trim();
        let encoding = self.header.content_encoding().unwrap_or("").trim();
        let default = if self.alpn == ALPN::HTTP11 && chunked.is_empty() { 0 } else { usize::MAX };
        self.remain = self.header.content_length().unwrap_or(default);
        #[cfg(feature = "log")]
        debug!("[Response] make coding: chunk={}; encoding={}", chunked=="chunked", encoding);
        match (chunked, encoding) {
            ("chunked", "gzip") => {
                let coding = ChunkDecoder::new(CodeType::Gzip)?;
                self.coder = Some(Box::new(coding))
            }
            ("chunked", "deflate") => {
                let coding = ChunkDecoder::new(CodeType::Deflate)?;
                self.coder = Some(Box::new(coding))
            }
            ("chunked", "br") => {
                let coding = ChunkDecoder::new(CodeType::Brotli)?;
                self.coder = Some(Box::new(coding))
            }
            ("chunked", "zstd") => {
                let coding = ChunkDecoder::new(CodeType::Zstd)?;
                self.coder = Some(Box::new(coding))
            }
            ("chunked", "") => self.coder = Some(Box::new(ChunkDecoder::new(CodeType::Null)?)),
            (_, "gzip") => self.coder = Some(Box::new(TZCoder::new_decompress(CodeType::Gzip)?)),
            (_, "deflate") => self.coder = Some(Box::new(TZCoder::new_decompress(CodeType::Deflate)?)),
            (_, "br") => self.coder = Some(Box::new(TZCoder::new_decompress(CodeType::Brotli)?)),
            (_, "zstd") => self.coder = Some(Box::new(TZCoder::new_decompress(CodeType::Zstd)?)),
            (_, _) => {}
        }
        Ok(())
    }

    pub fn extend_body(&mut self, buf: &[u8]) -> HlsResult<(bool, usize)> {
        match self.coder {
            None => {
                let read_len = min(buf.len(), self.remain);
                self.body.extend_from_slice(&buf[..read_len])?;
                self.remain -= read_len;
                debug_assert_eq!(buf.len(), read_len);
                Ok((self.remain == 0, read_len))
            }
            Some(ref mut coder) => {
                let mut reader = Reader::from_slice(buf);
                let finish = coder.decompress(&mut reader, &mut self.body)?;
                debug_assert_eq!(buf.len(), reader.position(), "{} {}", finish, self.header);
                self.remain -= reader.position();
                Ok((finish || self.remain == 0, reader.position()))
            }
        }
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

    pub fn update_by_buffer(&mut self, buffer: &mut Buffer) -> HlsResult<bool> {
        if self.alpn.is_empty() {
            let pos = buffer.filled().windows(HTTP_GAP.len()).position(|w| w == HTTP_GAP);
            let Some(pos) = pos else { return Ok(false) };
            self.parse_header(std::str::from_utf8(&buffer.filled()[..pos])?)?;
            buffer.used_empty(pos + HTTP_GAP.len());
            self.make_coding()?;
        }
        let (finish, size) = self.extend_body(buffer.filled())?;
        buffer.used_empty(size);
        Ok(finish)
    }

    pub fn push_pack_item(&mut self, item: &PackItem) -> HlsResult<()> {
        match item.name() {
            ":method" => self.method = Method::try_from(item.value())?,
            ":path" => self.uri = Uri::try_from(item.value())?,
            ":status" => self.status = HttpStatus::new(item.value().parse::<u16>()?),
            "cookie" => {
                for cookie in Cookie::from_req(item.value()) {
                    self.header.add_cookie(cookie);
                }
                return Ok(());
            }
            _ => {}
        }
        self.header.insert(item.name(), HeaderValue::String(Cow::Owned(item.value().to_string())));
        Ok(())
    }

    pub fn final_request(self) -> Request {
        Request {
            #[cfg(feature = "export")]
            sid: self.sid,
            method: self.method,
            uri: self.uri,
            alpn: self.alpn,
            header: self.header,
            body: self.body,
        }
    }

    pub fn final_response(self) -> Response {
        Response {
            #[cfg(feature = "export")]
            sid: self.sid,
            status: self.status,
            alpn: self.alpn,
            header: self.header,
            body: self.body,
        }
    }
}