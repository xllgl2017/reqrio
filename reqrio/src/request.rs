use crate::body::*;
use crate::error::HlsResult;
use crate::packet::{HeaderParam, HeaderReader};
use crate::reader::ReadExt;
use crate::Header;
use reqtls::{Writer, ALPN};

pub struct RequestBuffer<'a> {
    hdr_reader: HeaderReader<'a>,
    header_wrote: bool,
    body_reader: BodyReader<'a>,
}

impl<'a> RequestBuffer<'a> {
    pub fn new(header: &'a Header, body: &'a Body, mut param: HeaderParam<'a>) -> HlsResult<RequestBuffer<'a>> {
        let body_reader = match header.alpn() {
            #[cfg(feature = "quic")]
            ALPN::Http30 => BodyReader::HTTP3(H3BodyReader::new_size(1024, body.as_reader()?)),
            ALPN::Http20 => BodyReader::HTTP2(H2BodyReader::new_size(8192, body.as_reader()?, param.h_sid)),
            _ => BodyReader::HTTP1(body.as_reader()?)
        };
        param.body_len = body_reader.len();
        let header = header.as_reader(param, body.context_type())?;
        Ok(RequestBuffer {
            hdr_reader: header,
            header_wrote: false,
            body_reader,
        })
    }
}

impl<'a> ReadExt for RequestBuffer<'a> {
    fn wrote(&self) -> bool {
        self.body_reader.wrote()
    }

    fn len(&self) -> usize {
        self.hdr_reader.len() + self.body_reader.len()
    }

    fn read(&mut self, buf: &mut Writer) -> HlsResult<usize> {
        let start = buf.offset().end;
        if !self.header_wrote {
            self.hdr_reader.read(buf)?;
            self.header_wrote = self.hdr_reader.wrote();
        }
        self.body_reader.read(buf)?;
        Ok(buf.offset().end - start)
    }
}