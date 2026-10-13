use crate::error::HlsResult;
use crate::reader::ReadExt;
use crate::stream::Stream;
use crate::{Body, ContentType, Header, Method, Response};
use reqtls::{Url, Writer};
use std::collections::HashMap;
use std::io::Write;

pub struct SendParam<'a> {
    pub method: Method,
    pub url: &'a Url,
    pub header: &'a Header,
    pub body: &'a Body<'a>,
}

pub struct HTTP1Stream {
    write_buffer: Writer,
    read_buffer: Writer,
    stream: Stream,
    send_sid: u64,
    recv_sid: u64,
}

impl HTTP1Stream {
    pub fn new(stream: Stream) -> HTTP1Stream {
        HTTP1Stream {
            write_buffer: Writer::with_capacity(16384),
            read_buffer: Writer::with_capacity(16438),
            stream,
            send_sid: 0,
            recv_sid: 0,
        }
    }

    fn encode_hdr(&mut self, body_len: usize, param: &SendParam) -> std::io::Result<()> {
        for key in param.header.iter() {
            match key.name() {
                "host" | "Host" => match param.url.addr().port() {
                    80 | 443 => write!(&mut self.write_buffer, "{}: {}\r\n", key.name(), param.url.sni())?,
                    _ => write!(&mut self.write_buffer, "{}: {}:{}\r\n", key.name(), param.url.sni(), param.url.addr().port())?,
                }
                "content-length" | "Content-Length" => {
                    if body_len == 0 && param.method == Method::GET { continue; }
                    write!(&mut self.write_buffer, "{}: {}\r\n", key.name(), body_len)?;
                }
                "content-type" | "Content-Type" => {
                    if matches!(param.body.context_type(), ContentType::Null) { continue; }
                    write!(&mut self.write_buffer, "{}: {}\r\n", key.name(), param.body.context_type().spec())?;
                }
                "cookie" | "Cookie" => {
                    let cookies = key.cookies().unwrap_or(&[]);
                    if cookies.is_empty() { continue; }
                    write!(&mut self.write_buffer, "{}: ", key.name())?;
                    for (index, cookie) in cookies.iter().enumerate() {
                        write!(&mut self.write_buffer, "{}{}{}", cookie.name(), if cookie.equal_sign() { "=" } else { "" }, cookie.value())?;
                        if index != cookies.len() - 1 { self.write_buffer.write_slice(b"; ")?; }
                    }
                    self.write_buffer.write_slice(b"\r\n")?;
                }
                _ => {
                    if key.value().is_empty() && key.is_reserved() { continue; }
                    write!(&mut self.write_buffer, "{}: {}\r\n", key.name(), key.value())?;
                }
            };
        }
        Ok(())
    }

    fn encode(&mut self, body_len: usize, param: &SendParam) -> std::io::Result<()> {
        match param.url.uri().path().is_empty() {
            true => write!(&mut self.write_buffer, "{} / HTTP/1.1\r\n", param.method)?,
            false => write!(&mut self.write_buffer, "{} {} HTTP/1.1\r\n", param.method, param.url.uri())?
        }
        self.encode_hdr(body_len, param)?;
        self.write_buffer.write_slice(b"\r\n")?;
        Ok(())
    }


    pub fn send_sync<'a>(&'a mut self, param: SendParam<'a>) -> std::io::Result<u64> {
        let mut body_reader = param.body.as_reader()?;
        self.encode(body_reader.len(), &param)?;
        self.stream.write(&mut self.write_buffer).wait()?;
        loop {
            let len = body_reader.read(&mut self.write_buffer)?;
            if len == 0 { break; }
            self.stream.write(&mut self.write_buffer).wait()?;
        }
        self.send_sid += 1;
        Ok(self.send_sid - 1)
    }

    pub async fn send_async<'a>(&'a mut self, param: SendParam<'a>) -> std::io::Result<u64> {
        let mut body_reader = param.body.as_reader()?;
        self.encode(body_reader.len(), &param)?;
        self.stream.write(&mut self.write_buffer).await?;
        loop {
            let len = body_reader.read(&mut self.write_buffer)?;
            if len == 0 { break; }
            self.stream.write(&mut self.write_buffer).await?;
        }
        self.send_sid += 1;
        Ok(self.send_sid - 1)
    }

    fn recv(&mut self, responses: &mut HashMap<u64, Response>) -> HlsResult<Vec<u64>> {
        let response = responses.get_mut(&self.recv_sid).ok_or("resp not initialized")?;
        let finish = response.extend_buffer(&mut self.read_buffer)?;
        if finish {
            let res = vec![self.recv_sid];
            self.recv_sid += 1;
            Ok(res)
        } else { Ok(vec![]) }
    }

    pub fn recv_sync(&mut self, responses: &mut HashMap<u64, Response>) -> HlsResult<Vec<u64>> {
        self.read_buffer.check_move(16384)?;
        self.stream.read(&mut self.read_buffer).wait()?;
        self.recv(responses)
    }

    pub async fn recv_async(&mut self, responses: &mut HashMap<u64, Response>) -> HlsResult<Vec<u64>> {
        self.read_buffer.check_move(16384)?;
        self.stream.read(&mut self.read_buffer).await?;
        self.recv(responses)
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
    use crate::body::BodyKind;
    use crate::reader::HCow;
    use crate::stream::Stream;
    use crate::stream::http1::SendParam;
    use crate::{Application, Body, ContentType, HTTP1Stream, Header, Method, json};
    use reqrio_json::JsonValue;
    use reqtls::Url;

    #[test]
    fn test_h1_hdr_encode() {
        let headers = json::object! {
            "Connection": "keep-alive",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 MicroMessenger/7.0.20.1781(0x6700143B) NetType/WIFI MiniProgramEnv/Windows WindowsWechat/WMPF WindowsWechat(0x63090a13) UnifiedPCWindowsWechat(0xf254181b) XWEB/20001",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "xweb_xhr": "1",
            "Host-Ip": "",
            "Sec-Fetch-Site": "cross-site",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Referer": "https://xxxxx/wx9e2927dd595b0473/99/page-frame.html",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "zh-CN,zh;q=0.9",
        };
        let mut header = Header::default();
        header.set_by_json(headers.clone());
        header.insert("host", "xxxxx");
        header.insert("content-length", "748");
        header.insert("cookie", "wzws_sid=xxx; sid=123455667");
        header.insert("Authorization", "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.xxx.hKMvQpkzp5YpEN_B2fjhIQ1VHyi6dkwhtH8pjrDNJWM");
        let url = Url::try_from("https://xxxxx/wx9e2927dd595b0473/99/page-frame.html").unwrap();
        let mut stream = HTTP1Stream::new(Stream::NonConnection);
        stream.encode_hdr(748, &SendParam {
            method: Method::GET,
            url: &url,
            body: &Body::new(BodyKind::Data(HCow::Owned(JsonValue::Null)), ContentType::Application(Application::Json)),
            header: &header,
        }).unwrap();
        assert_eq!(std::str::from_utf8(stream.write_buffer.filled()).unwrap(), r#"Connection: keep-alive
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 MicroMessenger/7.0.20.1781(0x6700143B) NetType/WIFI MiniProgramEnv/Windows WindowsWechat/WMPF WindowsWechat(0x63090a13) UnifiedPCWindowsWechat(0xf254181b) XWEB/20001
Accept: application/json
Content-Type: application/json
xweb_xhr: 1
Host-Ip:
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://xxxxx/wx9e2927dd595b0473/99/page-frame.html
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
host: xxxxx
content-length: 748
cookie: wzws_sid=xxx; sid=123455667
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.xxx.hKMvQpkzp5YpEN_B2fjhIQ1VHyi6dkwhtH8pjrDNJWM
"#
            .replace("\n", "\r\n").replace("Host-Ip:", "Host-Ip: "));
    }
}