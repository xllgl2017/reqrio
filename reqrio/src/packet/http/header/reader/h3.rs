use crate::error::HlsResult;
use crate::pack::{QPackEncode, QPackType};
use crate::reader::{ReadExt, StrCow};
use reqtls::Writer;

pub struct H3HeaderReader<'a> {
    pub(crate) keys: Vec<(StrCow<'a>, StrCow<'a>)>,
    pub(crate) encoder: &'a mut QPackEncode,
    pub(crate) wrote: bool,
    pub(crate) sid: &'a u64,
}

impl<'a> ReadExt for H3HeaderReader<'a> {
    fn wrote(&self) -> bool { self.wrote }

    fn len(&self) -> usize { unreachable!() }

    fn read(&mut self, buf: &mut Writer) -> HlsResult<usize> {
        let len: usize = self.keys.iter().map(|(k, v)| k.len() + v.len()).sum();
        if buf.unfilled_len() < 59 + len { return Ok(0); }
        let offset = buf.offset();
        buf.write_u8(1)?;
        buf.write_u16(0)?;
        self.encoder.encode_head(buf)?;
        for (key, value) in self.keys.iter() {
            self.encoder.encode_one(QPackType::Stream, key, value, &self.sid, buf)?;
        }
        let len = buf.offset().end - offset.end - 3;
        assert!(len < 16384);
        buf.write_u16_in(offset.end + 1, len as u16 | 0x4000)?;
        self.wrote = true;
        Ok(len + 3)
    }
}

#[cfg(test)]
mod tests {
    use crate::pack::QPackEncode;
    use crate::packet::HeaderParam;
    use crate::reader::ReadExt;
    use crate::{json, ContentType, Header};
    use reqtls::Writer;

    #[test]
    fn test_h3_reader() {
        let mut header = Header::new_req_h2();
        header.set_by_json(json::object! {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
            "Accept": "*/*",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Dest": "document",
            "sec-fetch-user":"?1",
            "upgrade-insecure-requests":"1",
            "sec-ch-ua": "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Microsoft Edge\";v=\"120\"",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"Windows\"",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Accept-Encoding": "gzip,deflate,br,zstd",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        }).unwrap();
        let url = "https://img-s-msn-com.akamaized.net".try_into().unwrap();
        let mut encoder = QPackEncode::new(4096);
        let mut reader = header.as_h3_reader(HeaderParam {
            url: &url,
            qpack_encoder: Some(&mut encoder),
            q_sid: &0,
            hpack_encoder: None,
            h_sid: &0,
            body_len: 0,
            weight: &0,
            priority: &false,
        }, &ContentType::Null).unwrap();
        let mut buffer = Writer::with_capacity(4096);
        let len = reader.read(&mut buffer).unwrap();
        assert_eq!(len, 427);
        assert!(reader.wrote())
    }
}