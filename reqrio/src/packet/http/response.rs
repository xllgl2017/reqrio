use std::{mem, ptr};
use json::JsonValue;
use crate::{coder, HeaderValue};
use crate::buffer::Buffer;
use crate::coder::HPackCoding;
use crate::error::HlsResult;
use crate::packet::{Frame, Header};
use crate::packet::h2c::{FrameFlag, FrameType};
pub enum Body {
    Raw(Vec<u8>),
    Decoded(Vec<u8>),
    String(String),
    Json(JsonValue),
}

impl Body {
    fn extend(&mut self, buf: Vec<u8>) {
        match self {
            Body::Raw(raw) => raw.extend(buf),
            Body::Decoded(decoded) => decoded.extend(buf),
            Body::String(_) => {}
            Body::Json(_) => {}
        }
    }

    fn decompress(&mut self, encoding: Option<&HeaderValue>) -> HlsResult<()> {
        if let Body::Raw(raw) = self {
            let decoded = if let Some(encoding) = encoding {
                match encoding.as_string().unwrap_or("") {
                    "gzip" => coder::gzip_decode(mem::take(raw))?,
                    "deflate" => coder::deflate_decode(mem::take(raw))?,
                    "br" => coder::br_decode(mem::take(raw))?,
                    "zstd" => coder::zstd_decode(mem::take(raw))?,
                    _ => mem::take(raw),
                }
            } else {
                mem::take(raw)
            };
            *self = Body::Decoded(decoded);
        }
        Ok(())
    }

    pub fn as_json(&mut self) -> HlsResult<&JsonValue> {
        match self {
            Body::Decoded(decoded) => *self = Body::Json(json::from_bytes(decoded).or(Err("decode to json error"))?),
            Body::String(string) => *self = Body::Json(json::parse(string).or(Err("parse json error"))?),
            _ => {}
        };
        if let Body::Json(value) = self {
            Ok(value)
        } else { Err("not json body".into()).into() }
    }

    pub fn as_string(&mut self) -> HlsResult<&str> {
        match self {
            Body::Decoded(decoded) => *self = Body::String(String::from_utf8(mem::take(decoded)).or(Err("decode to string error"))?),
            Body::Json(j) => *self = Body::String(j.dump()),
            _ => {}
        };
        if let Body::String(value) = self {
            Ok(value)
        } else { Err("not json body".into()).into() }
    }

    fn to_string(self) -> HlsResult<String> {
        match self {
            Body::Raw(_) => Err("not decode".into()),
            Body::Decoded(decoded) => Ok(String::from_utf8(decoded)?),
            Body::String(value) => Ok(value),
            Body::Json(value) => Ok(value.dump())
        }
    }

    fn to_json(self) -> HlsResult<JsonValue> {
        match self {
            Body::Raw(_) => Err("not decode".into()),
            Body::Decoded(decoded) => Ok(json::from_bytes(&decoded).or(Err("decode to json error"))?),
            Body::String(value) => Ok(json::parse(value).or(Err("parse json error"))?),
            Body::Json(value) => Ok(value)
        }
    }

    fn is_raw(&self) -> bool {
        matches!(self, Body::Raw(_))
    }

    pub fn as_bytes(&self) -> HlsResult<&Vec<u8>> {
        match self {
            Body::Decoded(decoded) => Ok(decoded),
            _ => Err("not decode".into()),
        }
    }
}

pub struct Response {
    header: Header,
    body: Body,
    raw: Vec<u8>,
    frames: Vec<Frame>,
}

impl Response {
    pub fn new() -> Response {
        Response {
            header: Header::new_res(),
            body: Body::Raw(Vec::new()),
            raw: Vec::new(),
            frames: vec![],
        }
    }

    fn check_status(&self) -> Option<bool> {
        let chucked = self.header.get("transfer-encoding");
        if let Some(chucked) = chucked {
            if chucked.as_string()? != "chunked" {
                println!("have transfer-encoding, but unknow-{}", chucked.as_string()?);
                return None;
            }
            if self.raw.ends_with(&[48, 13, 10, 13, 10]) { return Some(true); }
            None
        } else {
            let len = self.header.content_length().unwrap_or(0);
            if self.raw.len() >= len { Some(true) } else { None }
        }
    }

    pub fn extend(&mut self, buffer: &Buffer) -> HlsResult<bool> {
        self.raw.reserve(buffer.len());
        unsafe {
            let dst = self.raw.as_mut_ptr().add(self.raw.len());
            ptr::copy_nonoverlapping(buffer.filled().as_ptr(), dst, buffer.len());
            self.raw.set_len(self.raw.len() + buffer.len());
        }
        match self.header.is_empty() {
            true => {
                let pos = self.raw.windows(4).position(|w| w == b"\r\n\r\n");
                if let Some(pos) = pos {
                    let hdr_bs = self.raw.drain(..pos).collect();
                    let hdr_str = String::from_utf8(hdr_bs)?;
                    // println!("{}", hdr_str);
                    self.header = Header::try_from(hdr_str)?;
                    self.raw.drain(..4);
                    Ok(self.check_status().unwrap_or(false))
                } else { Ok(false) }
            }
            false => Ok(self.check_status().unwrap_or(false))
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
                    let res = hpack_coding.decode(hdr_bs)?;
                    self.header = Header::parse_h2(res)?;
                } else {
                    self.frames.push(frame);
                }
            }
            _ => {}
        }
        Ok(ended)
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn header_mut(&mut self) -> &mut Header { &mut self.header }

    pub fn raw_string(&self) -> String {
        let header = self.header.to_string();
        let body = String::from_utf8_lossy(&self.raw).to_string();
        header + &body
    }

    pub fn decode_body(&mut self) -> HlsResult<&mut Body> {
        if !self.body.is_raw() { return Ok(&mut self.body); }
        let chucked = self.header.get("transfer-encoding");
        if let Some(chucked) = chucked && chucked.as_string().unwrap_or("") == "chunked" {
            self.body.extend(coder::chunk_decode(mem::take(&mut self.raw))?);
        } else {
            self.body.extend(mem::take(&mut self.raw));
        }
        let encoding = self.header.get("content-encoding");
        self.body.decompress(encoding)?;
        Ok(&mut self.body)
    }

    pub fn to_json(mut self) -> HlsResult<JsonValue> {
        self.decode_body()?;
        self.body.to_json()
    }

    pub fn to_string(mut self) -> HlsResult<String> {
        self.decode_body()?;
        self.body.to_string()
    }
}