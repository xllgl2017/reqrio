use crate::error::HlsResult;
use crate::pack::HPackEncode;
use crate::packet::H2EncodeFrame;
use crate::reader::{ReadExt, StrCow};
use crate::{ContentType, HeaderKey, Method};
use reqtls::{u24, Writer};

pub(crate) struct H2HeaderReader<'a> {
    pub(crate) keys: Vec<(StrCow<'a>, StrCow<'a>)>,
    pub(crate) encoder: &'a mut HPackEncode,
    pub(crate) stream_identifier: &'a u32,
    pub(crate) priority: &'a bool,
    pub(crate) weight: &'a u8,
    pub(crate) wrote: bool,
    pub(crate) pos: usize,
    pub(crate) body_len: usize,
}

impl<'a> H2HeaderReader<'a> {
    const INVALID_KEYS: [&'static str; 4] = ["connection", "host", "transfer-encoding", "upgrade"];
    pub(crate) fn skip_h2_key(key: &HeaderKey, ct: &ContentType, body: usize, method: &Method) -> bool {
        let is_ct = key.name().eq_ignore_ascii_case("content-type");
        if is_ct && !matches!(ct,ContentType::Null) { return false; }
        let is_len = key.name().eq_ignore_ascii_case("content-length");
        if is_len && body == 0 && method == &Method::GET { return true; }
        H2HeaderReader::INVALID_KEYS.contains(&key.name_lower().as_str()) || (key.value().is_empty() && key.is_reserved())
    }
}

impl<'a> ReadExt for H2HeaderReader<'a> {
    fn wrote(&self) -> bool {
        self.wrote
    }

    fn len(&self) -> usize {
        unreachable!()
    }

    fn read(&mut self, buf: &mut Writer) -> HlsResult<usize> {
        let len: usize = self.keys.iter().map(|(k, v)| k.len() + v.len()).sum();
        if buf.unfilled_len() < 59 + len { return Ok(0); }
        let offset = buf.offset();
        let mut header_frame = H2EncodeFrame::new_header(self.body_len, self.stream_identifier);
        if *self.priority { header_frame.set_priority(*self.weight) }
        header_frame.write_to(buf)?;
        for (i, (key, value)) in self.keys.iter().enumerate() {
            if i < self.pos { continue; }
            if buf.unfilled_len() < key.len() + value.len() { return Ok(buf.offset().end - offset.end); }
            self.encoder.encode_one(key, value, buf)?;
            self.pos += 1;
        }
        //有priority，payload长度需要frame.len-9
        buf.write_u24_in(offset.end, (buf.offset().end - offset.end - 9) as u24)?;
        self.wrote = true;
        Ok(buf.offset().end - offset.end)
    }
}


#[cfg(test)]
mod tests {
    use crate::pack::HPackEncode;
    use crate::packet::HeaderParam;
    use crate::reader::ReadExt;
    use crate::{ContentType, Header, Method, Writer};
    use reqtls::{Uri, Url};

    #[test]
    fn test_h2_reader() {
        let mut header = Header::new_req_h1();
        let uri = "/web/user/uias_login.do?appCode=hbzwfw&gotoUrl=http%3A%2F%2Fzwfw.hubei.gov.cn%2Fwebview%2Fgrkj%2Fwelcome.html&p01=";
        let uri = Uri::try_from(uri).unwrap();
        header.set_uri(uri);
        header.set_method(Method::POST);
        header.insert("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0").unwrap();
        header.insert("Accept", "*/*").unwrap();
        header.insert("Sec-Fetch-Site", "none").unwrap();
        header.insert("Sec-Fetch-Mode", "navigate").unwrap();
        header.insert("Sec-Fetch-Dest", "document").unwrap();
        header.insert("sec-fetch-user", "?1").unwrap();
        header.insert("upgrade-insecure-requests", "1").unwrap();
        header.insert("sec-ch-ua", "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Microsoft Edge\";v=\"120\"").unwrap();
        header.insert("sec-ch-ua-mobile", "?0").unwrap();
        header.insert("sec-ch-ua-platform", "\"Windows\"").unwrap();
        header.insert("Accept-Language", "zh-CN,zh;q=0.9").unwrap();
        header.insert("Accept-Encoding", "gzip,deflate,br,zstd").unwrap();
        header.insert("Cache-Control", "no-cache").unwrap();
        header.insert("Connection", "keep-alive").unwrap();
        header.insert("cookie", "_EDGE_V=1; MUIDB=184C10AD397866DF1A1607B038566708; MUID=184C10AD397866DF1A1607B038566708; _UR=QS=0&TQS=0&Pn=0; BFBUSR=BFBHP=0; MUIDB=184C10AD397866DF1A1607B038566708; SRCHD=AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF&AF=NOFORM; SRCHUID=V=2&GUID=EB7B9E5DE58F4D5690F6904732C24C7B&dmnchg=1; USRLOC=HS&ELOC=LAT=23.384721755981445|LON=113.44195556640625|N=%E7%99%BD%E4%BA%91%E5%8C%BA%EF%BC%8C%E5%B9%BF%E4%B8%9C%E7%9C%81|ELT=4|&HS=1; _RwBf=r&r&r&r&r=0&ilt=10&ihpd=5&ispd=3&rc=12&rb=0&rg=200&pc=12&mtu=0&rbb=0&clo=0&v=8&l=2026-03-15T07:00:00.0000000Z&lft=0001-01-01T00:00:00.0000000&aof=0&ard=0001-01-01T00:00:00.0000000&rwdbt=0&rwflt=0&rwaul2=0&g=&o=2&p=&c=&t=0&s=0001-01-01T00:00:00.0000000+00:00&ts=2026-03-15T14:03:35.7211444+00:00&rwred=0&wls=&wlb=&wle=&ccp=&cpt=&lka=0&lkt=0&aad=0&TH=&cid=0&gb=; SRCHUSR=DOB&DS&DS&DS&DS&DS=1&DOB=20260315; _EDGE_S=SID=357AA105805E678827ACB618817066E6; _SS=SID=357AA105805E678827ACB618817066E6; _HPVN=CS=eyJQbiI6eyJDbiI6MSwiU3QiOjAsIlFzIjowLCJQcm9kIjoiUCJ9LCJTYyI6eyJDbiI6MSwiU3QiOjAsIlFzIjowLCJQcm9kIjoiSCJ9LCJReiI6eyJDbiI6MSwiU3QiOjAsIlFzIjowLCJQcm9kIjoiVCJ9LCJBcCI6dHJ1ZSwiTXV0ZSI6dHJ1ZSwiTGFkIjoiMjAyNi0wMy0xNVQwMDowMDowMFoiLCJJb3RkIjowLCJHd2IiOjAsIlRucyI6MCwiRGZ0IjpudWxsLCJNdnMiOjAsIkZsdCI6MCwiSW1wIjozMCwiVG9ibiI6MH0=; SRCHHPGUSR=SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&V&SRCHLANG&SRCHLANG&SRCHLANG&V&SRCHLANG&SRCHLANG=zh-Hans&PREFCOL=0&BRW=NOTP&BRH=M&CW=150&CH=769&SCW=150&SCH=769&DPR=1.0&UTC=480&HV=1773588648&HVE=CfDJ8HAK7eZCYw5BifHFeUHnkJGC6_lT8f9GeruXx8zjPXuk-5GHkofYMoFErMkT8CTKKKsSt5O2HyGmjLyCEXbEREUmwCd8ZBlYMLSDZu1wZ-EI1LDuyIiI1tkP6Usyicm601qX3aJVYqVWUBn-t6h0ZWLiftm4aS627xFj1fE5PD-85i7BWTkhqG0uvaYzuSgB2A&BZA=0&PRVCW=150&PRVCH=769&B=0&EXLTT=7&V=CfDJ8HAK7eZCYw5BifHFeUHnkJGijeRjCoaCMaAnmznMvdEg2GXY8647Wb-7wnHNpePKXRO6KRQ_0cQc-onivd35uV-p-4g0MB0V_Z1ZpW-QSJe9zbPUG-Ks-kQMjzEl6GlLo6N0ciP51vkQdR-P-lCUH58&PR=1").unwrap();
        let mut res = [0; 3072];
        let url = Url::try_from("https://api.test.example.com:8222/web/user/uias_login.do?appCode=hbzwfw&gotoUrl=http%3A%2F%2Fzwfw.hubei.gov.cn%2Fwebview%2Fgrkj%2Fwelcome.html&p01=").unwrap();
        let mut encoder = HPackEncode::new(4096);
        let sid = 1;
        let mut reader = header.as_h2_reader(HeaderParam {
            url: &url,
            hpack_encoder: Some(&mut encoder),
            h_sid: &sid,
            #[cfg(feature = "quic")]
            q_sid: &0,
            #[cfg(feature = "quic")]
            qpack_encoder: None,
            body_len: 0,
            weight: &146,
            priority: &true,
        }, &ContentType::Null).unwrap();
        let mut writer = Writer::from_ptr(res.as_mut());
        let len = reader.read(&mut writer).unwrap();
        assert!(reader.wrote());
        let mut raw = Writer::with_capacity(3072);
        raw.write_u24(1957).unwrap(); //len
        raw.write_u8(1).unwrap(); //frame type
        raw.write_u8(37).unwrap(); //frame flag
        raw.write_slice(&[0, 0, 0, 1]).unwrap();
        raw.write_slice(&[128, 0, 0, 0]).unwrap();
        raw.write_u8(146).unwrap();
        let mut encoder = HPackEncode::new(4096);
        encoder.encode_one(":method", "POST", &mut raw).unwrap();
        encoder.encode_one(":authority", "api.test.example.com:8222", &mut raw).unwrap();
        encoder.encode_one(":scheme", "https", &mut raw).unwrap();
        encoder.encode_one(":path", "/web/user/uias_login.do?appCode=hbzwfw&gotoUrl=http%3A%2F%2Fzwfw.hubei.gov.cn%2Fwebview%2Fgrkj%2Fwelcome.html&p01=", &mut raw).unwrap();
        encoder.encode_one("cache-control", "no-cache", &mut raw).unwrap();
        encoder.encode_one("sec-ch-ua", "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Microsoft Edge\";v=\"120\"", &mut raw).unwrap();
        encoder.encode_one("sec-ch-ua-mobile", "?0", &mut raw).unwrap();
        encoder.encode_one("sec-ch-ua-platform", "\"Windows\"", &mut raw).unwrap();
        encoder.encode_one("upgrade-insecure-requests", "1", &mut raw).unwrap();
        encoder.encode_one("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0", &mut raw).unwrap();
        encoder.encode_one("accept", "*/*", &mut raw).unwrap();
        encoder.encode_one("sec-fetch-site", "none", &mut raw).unwrap();
        encoder.encode_one("sec-fetch-mode", "navigate", &mut raw).unwrap();
        encoder.encode_one("sec-fetch-user", "?1", &mut raw).unwrap();
        encoder.encode_one("sec-fetch-dest", "document", &mut raw).unwrap();
        encoder.encode_one("accept-encoding", "gzip,deflate,br,zstd", &mut raw).unwrap();
        encoder.encode_one("accept-language", "zh-CN,zh;q=0.9", &mut raw).unwrap();
        encoder.encode_one("cookie", "_EDGE_V=1", &mut raw).unwrap();
        encoder.encode_one("cookie", "MUIDB=184C10AD397866DF1A1607B038566708", &mut raw).unwrap();
        encoder.encode_one("cookie", "MUID=184C10AD397866DF1A1607B038566708", &mut raw).unwrap();
        encoder.encode_one("cookie", "_UR=QS=0&TQS=0&Pn=0", &mut raw).unwrap();
        encoder.encode_one("cookie", "BFBUSR=BFBHP=0", &mut raw).unwrap();
        encoder.encode_one("cookie", "MUIDB=184C10AD397866DF1A1607B038566708", &mut raw).unwrap();
        encoder.encode_one("cookie", "SRCHD=AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF&AF=NOFORM", &mut raw).unwrap();
        encoder.encode_one("cookie", "SRCHUID=V=2&GUID=EB7B9E5DE58F4D5690F6904732C24C7B&dmnchg=1", &mut raw).unwrap();
        encoder.encode_one("cookie", "USRLOC=HS&ELOC=LAT=23.384721755981445|LON=113.44195556640625|N=%E7%99%BD%E4%BA%91%E5%8C%BA%EF%BC%8C%E5%B9%BF%E4%B8%9C%E7%9C%81|ELT=4|&HS=1", &mut raw).unwrap();
        encoder.encode_one("cookie", "_RwBf=r&r&r&r&r=0&ilt=10&ihpd=5&ispd=3&rc=12&rb=0&rg=200&pc=12&mtu=0&rbb=0&clo=0&v=8&l=2026-03-15T07:00:00.0000000Z&lft=0001-01-01T00:00:00.0000000&aof=0&ard=0001-01-01T00:00:00.0000000&rwdbt=0&rwflt=0&rwaul2=0&g=&o=2&p=&c=&t=0&s=0001-01-01T00:00:00.0000000+00:00&ts=2026-03-15T14:03:35.7211444+00:00&rwred=0&wls=&wlb=&wle=&ccp=&cpt=&lka=0&lkt=0&aad=0&TH=&cid=0&gb=", &mut raw).unwrap();
        encoder.encode_one("cookie", "SRCHUSR=DOB&DS&DS&DS&DS&DS=1&DOB=20260315", &mut raw).unwrap();
        encoder.encode_one("cookie", "_EDGE_S=SID=357AA105805E678827ACB618817066E6", &mut raw).unwrap();
        encoder.encode_one("cookie", "_SS=SID=357AA105805E678827ACB618817066E6", &mut raw).unwrap();
        encoder.encode_one("cookie", "_HPVN=CS=eyJQbiI6eyJDbiI6MSwiU3QiOjAsIlFzIjowLCJQcm9kIjoiUCJ9LCJTYyI6eyJDbiI6MSwiU3QiOjAsIlFzIjowLCJQcm9kIjoiSCJ9LCJReiI6eyJDbiI6MSwiU3QiOjAsIlFzIjowLCJQcm9kIjoiVCJ9LCJBcCI6dHJ1ZSwiTXV0ZSI6dHJ1ZSwiTGFkIjoiMjAyNi0wMy0xNVQwMDowMDowMFoiLCJJb3RkIjowLCJHd2IiOjAsIlRucyI6MCwiRGZ0IjpudWxsLCJNdnMiOjAsIkZsdCI6MCwiSW1wIjozMCwiVG9ibiI6MH0=", &mut raw).unwrap();
        encoder.encode_one("cookie", "SRCHHPGUSR=SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&V&SRCHLANG&SRCHLANG&SRCHLANG&V&SRCHLANG&SRCHLANG=zh-Hans&PREFCOL=0&BRW=NOTP&BRH=M&CW=150&CH=769&SCW=150&SCH=769&DPR=1.0&UTC=480&HV=1773588648&HVE=CfDJ8HAK7eZCYw5BifHFeUHnkJGC6_lT8f9GeruXx8zjPXuk-5GHkofYMoFErMkT8CTKKKsSt5O2HyGmjLyCEXbEREUmwCd8ZBlYMLSDZu1wZ-EI1LDuyIiI1tkP6Usyicm601qX3aJVYqVWUBn-t6h0ZWLiftm4aS627xFj1fE5PD-85i7BWTkhqG0uvaYzuSgB2A&BZA=0&PRVCW=150&PRVCH=769&B=0&EXLTT=7&V=CfDJ8HAK7eZCYw5BifHFeUHnkJGijeRjCoaCMaAnmznMvdEg2GXY8647Wb-7wnHNpePKXRO6KRQ_0cQc-onivd35uV-p-4g0MB0V_Z1ZpW-QSJe9zbPUG-Ks-kQMjzEl6GlLo6N0ciP51vkQdR-P-lCUH58&PR=1", &mut raw).unwrap();
        assert_eq!(&res[..len], raw.filled())
    }
}