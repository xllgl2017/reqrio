use crate::body::multi_form::HttpFileReader;
use crate::error::HlsResult;
use crate::reader::{ReadExt, RefReader, StrCow};
use crate::*;
#[cfg(feature = "quic")]
use std::cmp::min;

pub enum RawBodyReader<'a> {
    Data(RefReader<StrCow<'a>>),
    Bytes(RefReader<&'a [u8]>),
    File(HttpFileReader<'a>),
}

impl<'a> ReadExt for RawBodyReader<'a> {
    fn wrote(&self) -> bool {
        match self {
            RawBodyReader::Data(data) => data.wrote(),
            RawBodyReader::Bytes(bytes) => bytes.wrote(),
            RawBodyReader::File(file) => file.wrote(),
        }
    }

    fn len(&self) -> usize {
        match self {
            RawBodyReader::Data(data) => data.len(),
            RawBodyReader::Bytes(bytes) => bytes.len(),
            RawBodyReader::File(file) => file.len(),
        }
    }

    fn read(&mut self, buf: &mut Writer) -> HlsResult<usize> {
        match self {
            RawBodyReader::Data(data) => data.read(buf),
            RawBodyReader::Bytes(bytes) => bytes.read(buf),
            RawBodyReader::File(file) => file.read(buf),
        }
    }
}


#[cfg(feature = "quic")]
pub struct H3BodyReader<'a> {
    body: RawBodyReader<'a>,
    frame_size: usize,
    buf_num: usize,
    len_size: usize,
    pos: usize,
    current: usize,
    wrote_hdr: bool,
    wrote: bool,
}

#[cfg(feature = "quic")]
impl<'a> H3BodyReader<'a> {
    pub fn new_size(buffer_size: usize, body: RawBodyReader<'a>) -> H3BodyReader<'a> {
        let body_len = body.len();
        H3BodyReader {
            buf_num: if body_len.is_multiple_of(buffer_size) { body_len / buffer_size } else { body_len / buffer_size + 1 },
            body,
            len_size: quic::variant_len(buffer_size),
            pos: 0,
            current: 0,
            wrote_hdr: false,
            wrote: false,
            frame_size: buffer_size,
        }
    }
}

#[cfg(feature = "quic")]
impl<'a> ReadExt for H3BodyReader<'a> {
    fn wrote(&self) -> bool { self.wrote }
    fn len(&self) -> usize { (1 + self.len_size) * self.buf_num + self.body.len() }
    fn read(&mut self, buf: &mut Writer) -> HlsResult<usize> {
        let start = buf.offset().end;
        for i in 0..self.buf_num {
            if i < self.current { continue; }
            if !self.wrote_hdr {
                if buf.unfilled_len() < 1 + self.len_size { return Ok(buf.offset().end - start); }
                let mut len = self.frame_size;
                if self.current == self.buf_num - 1 && !self.body.len().is_multiple_of(self.frame_size) {
                    len = self.body.len() % self.frame_size
                }
                buf.write_u8(0)?;
                buf.write_u16(len as u16 | 0x4000)?;
                self.wrote_hdr = true
            }
            let size = min(self.frame_size - self.pos, buf.unfilled_len());
            let mut reader = Writer::from_ptr(buf.unfilled_ptr(), size);
            self.pos += self.body.read(&mut reader)?;
            buf.add_len(reader.len());
            if self.pos == self.frame_size || self.body.wrote() {
                self.current += 1;
                self.pos = 0;
                self.wrote = self.body.wrote();
                self.wrote_hdr = false
            }
            if buf.unfilled_len() == 0 { return Ok(buf.offset().end - start); }
        }
        self.wrote = true;
        Ok(buf.offset().end - start)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "quic")]
    use crate::body::reader::{H3BodyReader, RawBodyReader};
    use crate::reader::*;
    use crate::{json, Body, BodyData};
    use reqtls::Writer;

    #[test]
    fn test_h1_reader() {
        let data = json::object! {
            "a":1,
            "b":"收到反馈",
            "v":{k:1,b:true}
        };
        let body = data.form();
        let mut body_reader = body.as_reader().unwrap();
        let mut res = vec![0; 1024];
        let mut writer = Writer::from_ptr(res.as_mut_ptr(), res.len());
        let len = body_reader.read(&mut writer).unwrap();
        assert_eq!(&res[..len], b"a=1&b=%E6%94%B6%E5%88%B0%E5%8F%8D%E9%A6%88&v=%7B%22k%22%3A1%2C%22b%22%3Atrue%7D");
        let body = Body::from(data);
        let mut body_reader = body.as_reader().unwrap();
        writer.reset();
        let len = body_reader.read(&mut writer).unwrap();
        assert_eq!(&res[..len], b"{\"a\":1,\"b\":\"\xE6\x94\xB6\xE5\x88\xB0\xE5\x8F\x8D\xE9\xA6\x88\",\"v\":{\"k\":1,\"b\":true}}");

        let body = Body::from(&[1, 2, 3, 4, 5, 12, 3, 4, 56]);
        let mut body_reader = body.as_reader().unwrap();
        writer.reset();
        let len = body_reader.read(&mut writer).unwrap();
        assert_eq!(&res[..len], [1, 2, 3, 4, 5, 12, 3, 4, 56]);


        let body = Body::from("12345,2345fdgf");
        let mut body_reader = body.as_reader().unwrap();
        writer.reset();
        let len = body_reader.read(&mut writer).unwrap();
        assert_eq!(&res[..len], b"12345,2345fdgf");
    }

    #[cfg(feature = "quic")]
    #[test]
    fn test_h3_reader() {
        let data = (0..100).collect::<Vec<_>>();
        let body = RawBodyReader::Bytes(RefReader::new_buf(&data));
        let mut reader = H3BodyReader::new_size(50, body);
        let mut writer = Writer::with_capacity(40);
        let len = reader.read(&mut writer).unwrap();
        assert_eq!(writer.filled(), [0, 64, 50, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36]);
        assert_eq!(len, 40);
        writer.reset();
        let len = reader.read(&mut writer).unwrap();
        assert_eq!(len, 40);
        assert_eq!(writer.filled(), [37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 0, 64, 50, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73]);
        assert!(!reader.wrote());
    }
}