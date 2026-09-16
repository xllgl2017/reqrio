use crate::error::HlsResult;
use crate::packet::HeaderParam;
use crate::reader::ReadExt;
use crate::request::RequestBuffer;
use crate::stream::Stream;
use crate::{Body, Header, Response};
use reqtls::Writer;
use std::collections::HashMap;

pub struct HTTP1StreamS {
    write_buffer: Writer,
    read_buffer: Writer,
    stream: Stream,
    send_sid: u64,
    recv_sid: u64,
}


impl HTTP1StreamS {
    pub fn new(stream: Stream) -> HTTP1StreamS {
        HTTP1StreamS {
            write_buffer: Writer::with_capacity(16384),
            read_buffer: Writer::with_capacity(16438),
            stream,
            send_sid: 0,
            recv_sid: 0,
        }
    }

    pub fn send(&mut self, header: &Header, body: &Body<'_>, param: HeaderParam<'_>) -> HlsResult<u64> {
        let sid = self.send_sid;
        self.send_sid += 1;
        let mut request = RequestBuffer::new(header, body, param)?;
        loop {
            self.write_buffer.reset();
            let len = request.read(&mut self.write_buffer)?;
            if len == 0 { break; }
            self.stream.write(&mut self.write_buffer).wait()?;
        }
        Ok(sid)
    }

    pub fn recv(&mut self, responses: &mut HashMap<u64, Response>) -> HlsResult<Vec<u64>> {
        self.read_buffer.check_move(16384)?;
        self.stream.read(&mut self.read_buffer).wait()?;
        let response = responses.get_mut(&self.recv_sid).ok_or("resp not inited")?;
        let finish = response.extend_buffer(&mut self.read_buffer)?;
        if finish {
            let res = vec![self.recv_sid];
            self.recv_sid += 1;
            Ok(res)
        } else { Ok(vec![]) }
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


#[cfg(feature = "aync")]
pub struct HTTP1StreamA {
    write_buffer: Writer,
    read_buffer: Writer,
    stream: Stream,
    send_sid: u64,
    recv_sid: u64,
}

#[cfg(feature = "aync")]
impl HTTP1StreamA {
    pub fn new(stream: Stream) -> HTTP1StreamA {
        HTTP1StreamA {
            write_buffer: Writer::with_capacity(16384),
            read_buffer: Writer::with_capacity(16438),
            stream,
            send_sid: 0,
            recv_sid: 0,
        }
    }

    pub async fn send(&mut self, header: &Header, body: &Body<'_>, param: HeaderParam<'_>) -> HlsResult<u64> {
        let sid = self.send_sid;
        self.send_sid += 1;
        let mut request = RequestBuffer::new(header, body, param)?;
        loop {
            self.write_buffer.reset();
            let len = request.read(&mut self.write_buffer)?;
            if len == 0 { break; }
            self.stream.write(&mut self.write_buffer).await?;
        }
        Ok(sid)
    }

    pub async fn recv(&mut self, responses: &mut HashMap<u64, Response>) -> HlsResult<Vec<u64>> {
        self.read_buffer.check_move(16384)?;
        self.stream.read(&mut self.read_buffer).await?;
        let response = responses.get_mut(&self.recv_sid).ok_or("resp not inited")?;
        let finish = response.extend_buffer(&mut self.read_buffer)?;
        if finish {
            let res = vec![self.recv_sid];
            self.recv_sid += 1;
            Ok(res)
        } else { Ok(vec![]) }
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