use crate::body::RawBodyReader;
use crate::error::HlsResult;
use crate::pack::{HPackDecode, HPackEncode};
use crate::reader::ReadExt;
use crate::stream::read::ChunkReading;
use crate::stream::{Stream, StreamMessage};
use crate::*;
use reqtls::{Buffer, Reader, Writer, u24};
use std::collections::HashMap;
use packet::H2PayloadValue;
use super::message::SendParam;

pub struct HTTP2Stream {
    encoder: HPackEncode,
    decoder: HPackDecode,
    sid: u32,
    stream: Stream,
    read_buffer: Writer,
    write_buffer: Writer,
    increment: u32,
    #[cfg(feature = "aync")]
    timeout: Timeout,
}

impl HTTP2Stream {
    pub fn new(buffer: Buffer, stream: Stream) -> HTTP2Stream {
        HTTP2Stream {
            #[cfg(feature = "aync")]
            timeout: stream.timeout().clone(),
            encoder: HPackEncode::new(65536),
            decoder: HPackDecode::new(65536),
            sid: 1,
            stream,
            read_buffer: buffer,
            write_buffer: Writer::with_capacity(16438),
            increment: 0,
        }
    }

    fn encode_hdr(&mut self, body_len: usize, param: &SendParam, mut index: usize) -> std::io::Result<usize> {
        let frame_type = if index == 0 { H2FrameType::Headers } else { H2FrameType::Continuation };
        let frame = self.build_frame(frame_type, param);
        let start = self.write_buffer.end();
        frame.write_to(&mut self.write_buffer)?;
        if index == 0 {
            self.encoder.encode_one(":method", param.method.spec(), &mut self.write_buffer)?;
            if param.url.addr().port() == 443 {
                self.encoder.encode_one(":authority", param.url.sni(), &mut self.write_buffer)?;
            } else {
                let authority = format!("{}:{}", param.url.sni(), param.url.addr().port());
                self.encoder.encode_one(":authority", authority, &mut self.write_buffer)?;
            }
            self.encoder.encode_one(":scheme", param.url.scheme().spec(), &mut self.write_buffer)?;
            if param.url.uri().path().is_empty() {
                self.encoder.encode_one(":path", "/", &mut self.write_buffer)?;
            } else {
                self.encoder.encode_one(":path", param.url.uri().to_string(), &mut self.write_buffer)?;
            }
        }
        for (i, key) in param.header.iter().enumerate() {
            if i < index { continue; }
            index = i;
            let key_start = self.write_buffer.end();
            match key.name() {
                "host" | "Host" | "Transfer-Encoding" | "transfer-encoding" |
                "Upgrade" | "upgrade" | "connection" | "Connection" => continue,
                "content-length" | "Content-Length" => {
                    if body_len == 0 && param.method == Method::GET { continue; }
                    self.encoder.encode_one(key.name(), body_len.to_string(), &mut self.write_buffer)?;
                }
                "content-type" | "Content-Type" => {
                    if matches!(param.body.context_type(), ContentType::Null) { continue; }
                    self.encoder.encode_one(key.name(), param.body.context_type().spec(), &mut self.write_buffer)?;
                }
                "cookie" | "Cookie" => {
                    let cookies = key.cookies().unwrap_or(&[]);
                    if cookies.is_empty() { continue; }
                    for cookie in cookies.iter() {
                        self.encoder.encode_one(key.name(), cookie.as_req(), &mut self.write_buffer)?;
                    }
                }
                _ => {
                    if key.value().is_empty() && key.is_reserved() { continue; }
                    match key.value() {
                        HeaderValue::String(v) => self.encoder.encode_one(key.name(), v, &mut self.write_buffer)?,
                        _ => self.encoder.encode_one(key.name(), key.value().to_string(), &mut self.write_buffer)?
                    }
                }
            };
            if self.write_buffer.end() - start > 8192 {
                self.write_buffer.reset_offset(self.write_buffer.start()..key_start);
                break;
            }
        }
        let len = self.write_buffer.end() - start - 9;
        self.write_buffer.write_u24_in(start, len as u24)?;
        self.write_buffer.filled_mut()[start + 4] |= H2FrameFlag::EndHeader.into_inner();
        if body_len == 0 { self.write_buffer.filled_mut()[start + 4] |= H2FrameFlag::EndStream.into_inner(); }
        Ok(index)
    }

    fn build_frame(&self, typ: H2FrameType, param: &SendParam) -> H2Frame<'static> {
        let mut frame = H2Frame::new(self.sid, typ);
        if param.priority && typ != H2FrameType::Data {
            frame.payload.weight = param.weight;
            frame.add_flag(H2FrameFlag::Priority);
        }
        frame
    }

    fn encode_body(&mut self, reader: &mut RawBodyReader, param: &SendParam) -> std::io::Result<()> {
        let start = self.write_buffer.end();
        let frame = self.build_frame(H2FrameType::Data, param);
        frame.write_to(&mut self.write_buffer)?;
        let mut writer = Writer::from_ptr(self.write_buffer.unfilled_ptr(), 8192);
        reader.read(&mut writer)?;
        match writer.is_empty() {
            true => self.write_buffer.reset_offset(self.write_buffer.start()..start),
            false => {
                self.write_buffer.add_len(writer.len());
                let len = self.write_buffer.end() - start - 9;
                self.write_buffer.write_u24_in(start, len as u24)?;
                if reader.wrote() {
                    self.write_buffer.filled_mut()[start + 4] |= H2FrameFlag::EndStream.into_inner();
                }
            }
        }
        Ok(())
    }

    pub fn send_sync(&mut self, param: SendParam) -> HlsResult<u64> {
        let mut body_reader = param.body.as_reader()?;
        let mut index = 0;
        while index + 1 < param.header.len() {
            index = self.encode_hdr(body_reader.len(), &param, index)?;
            self.stream.write(&mut self.write_buffer).wait()?;
        }
        while !body_reader.wrote() {
            self.encode_body(&mut body_reader, &param)?;
            self.stream.write(&mut self.write_buffer).wait()?;
        }
        let sid = self.sid;
        self.sid += 2;
        Ok(sid as u64)
    }

    #[cfg(feature = "aync")]
    pub async fn send_async(&mut self, param: SendParam<'_>) -> HlsResult<u64> {
        let mut body_reader = param.body.as_reader()?;
        let mut index = 0;
        while index + 1 < param.header.len() {
            index = self.encode_hdr(body_reader.len(), &param, index)?;
            self.stream.write(&mut self.write_buffer).await?;
        }
        while !body_reader.wrote() {
            self.encode_body(&mut body_reader, &param)?;
            self.stream.write(&mut self.write_buffer).await?;
        }
        let sid = self.sid;
        self.sid += 2;
        Ok(sid as u64)
    }

    fn read_next_frame(&mut self) -> ChunkReading<'_, Stream> {
        let _ = self.read_buffer.check_move(16438);
        ChunkReading {
            len_size: 5,
            func: Box::new(|filled| {
                let mut frame_len = u24::from_be_bytes([0, filled[0], filled[1], filled[2]]) as usize + 9;
                let priority = filled[4] & 0b0010_0000 == 0b0010_0000;
                if priority { frame_len += 5; }
                frame_len
            }),
            stream: &mut self.stream,
            buf: &mut self.read_buffer,
            #[cfg(feature = "aync")]
            timeout: &mut self.timeout,
        }
    }

    pub fn recv_sync(&mut self, responses: &mut HashMap<u64, StreamMessage>) -> HlsResult<Vec<u64>> {
        let frame_size = self.read_next_frame().wait()?;
        let res = self.handle_frame(frame_size, responses);
        self.stream.write(&mut self.write_buffer).wait()?;
        if self.read_buffer.used_empty(frame_size) { self.read_buffer.reset(); };
        res
    }

    #[cfg(feature = "aync")]
    pub async fn recv_async(&mut self, responses: &mut HashMap<u64, StreamMessage>) -> HlsResult<Vec<u64>> {
        let frame_size = self.read_next_frame().await?;
        let res = self.handle_frame(frame_size, responses);
        self.stream.write(&mut self.write_buffer).await?;
        if self.read_buffer.used_empty(frame_size) { self.read_buffer.reset(); };
        res
    }

    fn handle_frame(&mut self, frame_size: usize, responses: &mut HashMap<u64, StreamMessage>) -> HlsResult<Vec<u64>> {
        let reader = Reader::from_slice(&self.read_buffer.filled()[..frame_size]);
        let frame = H2Frame::from_reader(reader)?;
        let sid = frame.stream_identifier() as u64;
        let mut res = vec![];
        #[cfg(feature = "log")]
        trace!("[HTTP2] recv frame: sid: {}; typ={:?}; fin={}; keys={:?}", sid, frame.frame_type(), frame.flag().end_stream(), responses.keys());
        match (frame.frame_type(), &frame.payload.value) {
            (H2FrameType::Data, H2PayloadValue::Data(data)) => {
                let resp = responses.get_mut(&sid).ok_or("resp not inited")?;
                resp.extend_body(data.as_slice())?;
                if frame.flag().end_stream() { res.push(sid); }
            }
            (H2FrameType::Headers, H2PayloadValue::Data(data)) => {
                let resp = responses.get_mut(&sid).ok_or("resp not inited")?;
                self.decoder.decode_into(data.as_ref(), resp)?;
                if let Some(size) = resp.header.update_table_size() {
                    self.encoder.update_table_size(size);
                    self.decoder.update_table_size(size);
                }
                if frame.flag().end_header() { resp.make_coding()?; }
                if frame.flag().end_stream() { res.push(sid); }
            }
            (H2FrameType::Settings, H2PayloadValue::Settings(settings)) => {
                for setting in settings.iter() {
                    if let H2Setting::HeaderTableSize(size) = setting {
                        self.encoder.update_table_size(*size as usize);
                        self.decoder.update_table_size(*size as usize);
                    }
                }
                if frame.flag().end_stream() {
                    let mut ack_frame = H2Frame::new(0, H2FrameType::Settings);
                    ack_frame.set_flag(H2FrameFlag::EndStream);
                    ack_frame.write_to(&mut self.write_buffer)?;
                }
            }
            (H2FrameType::Goaway, _) => return Err(frame.frame_type().into()),
            (H2FrameType::WindowUpdate, H2PayloadValue::U32(val)) => self.increment = *val,
            (H2FrameType::RstStream, H2PayloadValue::U32(_err)) => {
                responses.remove(&sid);
                #[cfg(feature = "log")]
                debug!("[RstStream] sid={}; error={}", sid, _err);
                res.push(sid);
                return Err(HlsError::H2(frame.frame_type()));
            }
            _ => {
                #[cfg(feature = "log")]
                warn!("ignore h2 frame-{:?}",frame.frame_type());
            }
        }
        Ok(res)
    }


    pub fn stream(&self) -> &Stream {
        &self.stream
    }

    pub fn stream_mut(&mut self) -> &mut Stream {
        &mut self.stream
    }

    pub fn into_stream(self) -> Stream {
        self.stream
    }
}


#[cfg(test)]
mod tests {
    use crate::pack::{HPackDecode, HPackEncode};
    use super::super::message::SendParam;
    use crate::stream::http2::HTTP2Stream;
    use crate::*;

    #[test]
    fn test_hdr_encode() {
        let mut header = Header::new_req_h2();
        header.insert("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0");
        header.insert("Accept", "*/*");
        header.insert("Sec-Fetch-Site", "none");
        header.insert("Sec-Fetch-Mode", "navigate");
        header.insert("Sec-Fetch-Dest", "document");
        header.insert("sec-fetch-user", "?1");
        header.insert("upgrade-insecure-requests", "1");
        header.insert("sec-ch-ua", "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Microsoft Edge\";v=\"120\"");
        header.insert("sec-ch-ua-mobile", "?0");
        header.insert("sec-ch-ua-platform", "\"Windows\"");
        header.insert("Accept-Language", "zh-CN,zh;q=0.9");
        header.insert("Accept-Encoding", "gzip,deflate,br,zstd");
        header.insert("Cache-Control", "no-cache");
        header.insert("Connection", "keep-alive");
        header.insert("cookie", "_EDGE_V=1; MUIDB=184C10AD397866DF1A1607B038566708; MUID=184C10AD397866DF1A1607B038566708; _UR=QS=0&TQS=0&Pn=0; BFBUSR=BFBHP=0; MUIDB=184C10AD397866DF1A1607B038566708; SRCHD=AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF&AF=NOFORM; SRCHUID=V=2&GUID=EB7B9E5DE58F4D5690F6904732C24C7B&dmnchg=1; USRLOC=HS&ELOC=LAT=23.384721755981445|LON=113.44195556640625|N=%E7%99%BD%E4%BA%91%E5%8C%BA%EF%BC%8C%E5%B9%BF%E4%B8%9C%E7%9C%81|ELT=4|&HS=1; _RwBf=r&r&r&r&r=0&ilt=10&ihpd=5&ispd=3&rc=12&rb=0&rg=200&pc=12&mtu=0&rbb=0&clo=0&v=8&l=2026-03-15T07:00:00.0000000Z&lft=0001-01-01T00:00:00.0000000&aof=0&ard=0001-01-01T00:00:00.0000000&rwdbt=0&rwflt=0&rwaul2=0&g=&o=2&p=&c=&t=0&s=0001-01-01T00:00:00.0000000+00:00&ts=2026-03-15T14:03:35.7211444+00:00&rwred=0&wls=&wlb=&wle=&ccp=&cpt=&lka=0&lkt=0&aad=0&TH=&cid=0&gb=; SRCHUSR=DOB&DS&DS&DS&DS&DS=1&DOB=20260315; _EDGE_S=SID=357AA105805E678827ACB618817066E6; _SS=SID=357AA105805E678827ACB618817066E6; _HPVN=CS=eyJQbiI6eyJDbiI6MSwiU3QiOjAsIlFzIjowLCJQcm9kIjoiUCJ9LCJTYyI6eyJDbiI6MSwiU3QiOjAsIlFzIjowLCJQcm9kIjoiSCJ9LCJReiI6eyJDbiI6MSwiU3QiOjAsIlFzIjowLCJQcm9kIjoiVCJ9LCJBcCI6dHJ1ZSwiTXV0ZSI6dHJ1ZSwiTGFkIjoiMjAyNi0wMy0xNVQwMDowMDowMFoiLCJJb3RkIjowLCJHd2IiOjAsIlRucyI6MCwiRGZ0IjpudWxsLCJNdnMiOjAsIkZsdCI6MCwiSW1wIjozMCwiVG9ibiI6MH0=; SRCHHPGUSR=SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&V&SRCHLANG&SRCHLANG&SRCHLANG&V&SRCHLANG&SRCHLANG=zh-Hans&PREFCOL=0&BRW=NOTP&BRH=M&CW=150&CH=769&SCW=150&SCH=769&DPR=1.0&UTC=480&HV=1773588648&HVE=CfDJ8HAK7eZCYw5BifHFeUHnkJGC6_lT8f9GeruXx8zjPXuk-5GHkofYMoFErMkT8CTKKKsSt5O2HyGmjLyCEXbEREUmwCd8ZBlYMLSDZu1wZ-EI1LDuyIiI1tkP6Usyicm601qX3aJVYqVWUBn-t6h0ZWLiftm4aS627xFj1fE5PD-85i7BWTkhqG0uvaYzuSgB2A&BZA=0&PRVCW=150&PRVCH=769&B=0&EXLTT=7&V=CfDJ8HAK7eZCYw5BifHFeUHnkJGijeRjCoaCMaAnmznMvdEg2GXY8647Wb-7wnHNpePKXRO6KRQ_0cQc-onivd35uV-p-4g0MB0V_Z1ZpW-QSJe9zbPUG-Ks-kQMjzEl6GlLo6N0ciP51vkQdR-P-lCUH58&PR=1");
        let url = Url::try_from("https://api.test.example.com:8222/web/user/uias_login.do?appCode=hbzwfw&gotoUrl=http%3A%2F%2Fzwfw.hubei.gov.cn%2Fwebview%2Fgrkj%2Fwelcome.html&p01=").unwrap();
        let mut stream = HTTP2Stream {
            #[cfg(feature = "aync")]
            timeout: Timeout::longer(),
            encoder: HPackEncode::new(4096),
            decoder: HPackDecode::new(4096),
            sid: 1,
            stream: Stream::NonConnection,
            read_buffer: Buffer::none(),
            write_buffer: Buffer::with_capacity(3072),
            increment: 0,
        };
        stream.encode_hdr(0, &SendParam {
            method: Method::POST,
            url: &url,
            header: &header,
            body: Body::none(),
            priority: true,
            weight: 146,
        }, 0).unwrap();


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
        assert_eq!(stream.write_buffer.filled(), raw.filled())
    }
}