pub use table::HPack;
// pub use encode::HackEncode;
// pub use decode::HackDecode;

// use table::HPackTable;

use crate::error::HlsResult;
use crate::HeaderValue;
use crate::packet::HeaderKey;

// mod decode;
// mod encode;
mod table;

pub struct HackEncode(httlib_hpack::Encoder<'static>);

impl HackEncode {
    pub fn new() -> HackEncode {
        HackEncode(httlib_hpack::Encoder::default())
    }

    pub fn encode_packs(&mut self, packs: &Vec<HPack>) -> HlsResult<Vec<u8>> {
        let mut res = vec![];
        for pack in packs {
            let mut dst = vec![];
            let value = (pack.name().as_bytes().to_vec(), pack.value().as_bytes().to_vec(), 0x2 | 0x4 | 0x10);
            self.0.encode(value, &mut dst)?;
            res.extend(dst);
        }
        Ok(res)
    }

    pub fn encode(&mut self, hks: Vec<HeaderKey>) -> HlsResult<Vec<u8>> {
        let mut res = vec![];
        for hk in hks {
            let name = hk.name().to_lowercase();
            match hk.value() {
                HeaderValue::Cookies(cookies) => {
                    for cookie in cookies {
                        let value = cookie.as_req();
                        let mut dst = vec![];
                        self.0.encode((name.as_bytes().to_vec(), value.into_bytes(), 0x2 | 0x4 | 0x10), &mut dst)?;
                        res.extend(dst);
                    }
                }
                _ => {
                    let value = hk.value().to_string();
                    let mut dst = vec![];
                    self.0.encode((name.into_bytes(), value.into_bytes(), 0x2 | 0x4 | 0x10), &mut dst)?;
                    res.extend(dst);
                }
            }
        }
        Ok(res)
    }
}

pub struct HackDecode(httlib_hpack::Decoder<'static>);

impl HackDecode {
    pub fn new() -> HackDecode {
        HackDecode(httlib_hpack::Decoder::default())
    }
    pub fn decode(&mut self, buf: &mut Vec<u8>) -> HlsResult<Vec<HPack>> {
        let mut dst = vec![];
        self.0.decode(buf, &mut dst)?;
        let mut res = vec![];
        for (name, value, flag) in dst {
            let name = String::from_utf8(name)?;
            let value = String::from_utf8(value)?;
            res.push(HPack::new_flag(name, value, flag));
        }
        Ok(res)
    }
}

pub struct HPackCoding {
    decoder: HackDecode,
    encoder: HackEncode,
}

impl HPackCoding {
    pub fn new() -> HPackCoding {
        HPackCoding {
            decoder: HackDecode::new(),
            encoder: HackEncode::new(),
        }
    }

    pub fn decode(&mut self, context: &mut Vec<u8>) -> HlsResult<Vec<HPack>> {
        Ok(self.decoder.decode(context)?)
    }

    pub fn encode(&mut self, headers: Vec<HeaderKey>) -> HlsResult<Vec<u8>> {
        self.encoder.encode(headers)
    }

    pub fn decoder(&mut self) -> &mut HackDecode { &mut self.decoder }
}