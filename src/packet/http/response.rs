use std::mem;
use json::JsonValue;
use crate::coder;
use crate::coder::HPackCoding;
use crate::error::HlsResult;
use crate::packet::{Frame, Header};
use crate::packet::h2c::{FrameFlag, FrameType};

pub struct Response {
    header: Header,
    body: Vec<u8>,
    raw: Vec<u8>,
    frames: Vec<Frame>,
}

impl Response {
    pub fn new() -> Response {
        Response {
            header: Header::new(),
            body: Vec::new(),
            raw: Vec::new(),
            frames: vec![],
        }
    }

    pub fn extend(&mut self, bytes: Vec<u8>) -> HlsResult<bool> {
        // if bytes.len() >= 7 { println!("{:?}", bytes[bytes.len() - 7..].to_vec()); }
        self.raw.extend(bytes);
        let pos = self.raw.windows(4).position(|w| w == b"\r\n\r\n");
        if let Some(pos) = pos && self.header.is_empty() {
            let hdr_bs = self.raw.drain(..pos).collect();
            let hdr_str = String::from_utf8(hdr_bs)?;
            self.header = Header::parse_res(hdr_str)?;
            self.raw.drain(..4);
        }
        match self.header.content_length() {
            None => Ok(self.raw.ends_with(&[13, 10, 48, 13, 10, 13, 10])),
            Some(len) => Ok(self.raw.len() >= len)
        }
    }

    pub fn extend_frame(&mut self, frame: Frame, hpack_coding: &mut HPackCoding) -> HlsResult<bool> {
        let ended = frame.flags().contains(&FrameFlag::EndStream) && (frame.frame_type() == &FrameType::Data || frame.frame_type() == &FrameType::Headers);
        match frame.frame_type() {
            FrameType::Data => self.raw.extend(frame.to_payload()),
            FrameType::Headers => {
                if frame.flags().contains(&FrameFlag::EndHeaders) {
                    let mut payload = self.frames.drain(..).map(|x| x.to_payload()).collect::<Vec<_>>();
                    payload.push(frame.to_payload());
                    let hdr_bs = payload.concat();
                    let res = hpack_coding.decode(hdr_bs, false)?;
                    self.header = Header::parse_h2(res)?;
                }
            }
            _ => {}
        }
        Ok(ended)
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn raw_string(&self) -> String {
        let header = self.header.to_string();
        let body = String::from_utf8_lossy(&self.raw).to_string();
        header + &body
    }

    pub fn decode_body(mut self) -> HlsResult<Vec<u8>> {
        let chucked = self.header.get("transfer-encoding");
        if let Some(chucked) = chucked && chucked.as_string().unwrap_or("") == "chunked" {
            while let Some(pos) = self.raw.windows(2).position(|w| w == b"\r\n") {
                let len_bs = self.raw.drain(..pos).collect();
                let len_str = String::from_utf8(len_bs)?;
                //删除\r\n
                self.raw.drain(..2);
                let chunk_len = usize::from_str_radix(len_str.as_str(), 16)?;
                self.body.extend(self.raw.drain(..chunk_len));
                //删除\r\n
                self.raw.drain(..2);
            }
        } else {
            self.body = mem::take(&mut self.raw);
        }
        Ok(self.decompress()?)
    }

    fn decompress(self) -> HlsResult<Vec<u8>> {
        let encoding = self.header.get("content-encoding");
        if let Some(encoding) = encoding {
            match encoding.as_string().unwrap_or("") {
                "gzip" => coder::gzip_decode(self.body),
                "deflate" => coder::deflate_decode(self.body),
                "br" => coder::br_decode(self.body),
                "zstd" => coder::zstd_decode(self.body),
                _ => Ok(self.body)
            }
        } else {
            Ok(self.body)
        }
    }

    pub fn to_json(self) -> HlsResult<JsonValue> {
        let decode = self.decode_body()?;
        Ok(json::from_bytes(&decode)?)
    }

    pub fn to_string(self) -> HlsResult<String> {
        let decode = self.decode_body()?;
        Ok(String::from_utf8(decode)?)
    }
}