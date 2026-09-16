#[cfg(feature = "aync")]
use std::pin::Pin;
#[cfg(feature = "aync")]
use std::task::{Context, Poll};
use reqtls::coder::DeflateStream;
use crate::error::HlsResult;
use crate::stream::write::StreamShutdown;
use crate::stream::Stream;
use crate::*;
use crate::packet::{Marker, WsFrameType};

pub struct WebSocket {
    stream: Stream,
    read_buffer: Writer,
    write_buffer: Writer,
    demask_buffer: Writer,
    coder: Option<DeflateStream>,
    mask: bool,
}

impl WebSocket {
    fn add_header(header: &mut Header) -> HlsResult<()> {
        if header.get_str("Sec-WebSocket-Key").unwrap_or("").is_empty() {
            header.insert("Sec-WebSocket-Key", "3eGwJ19k4qUKxRPJZUNYLw==")?
        }
        if header.get_str("Connection").unwrap_or("").is_empty() {
            header.set_connection("Upgrade")?;
        }
        if header.get_str("Sec-WebSocket-Version").unwrap_or("").is_empty() {
            header.insert("Sec-WebSocket-Version", "13")?
        }
        if header.get_str("Sec-WebSocket-Extensions").unwrap_or("").is_empty() {
            header.insert("Sec-WebSocket-Extensions", "permessage-deflate; client_max_window_bits")?
        }
        if header.get_str("Upgrade").unwrap_or("").is_empty() {
            header.insert("Upgrade", "websocket")?
        }
        Ok(())
    }

    pub fn open_sync(url: &str) -> HlsResult<WebSocket> {
        let mut header = Header::new_req_h1();
        WebSocket::add_header(&mut header)?;
        let mut req = ScReq::new().with_header(header);
        WebSocket::new(req.get(url, None)?, req.into_stream()?)
    }

    #[cfg(feature = "aync")]
    pub async fn open_async(url: &str) -> HlsResult<WebSocket> {
        let mut header = Header::new_req_h1();
        WebSocket::add_header(&mut header)?;
        let mut req = AcReq::new().with_header(header);
        WebSocket::new(req.get(url, None).await?, req.into_stream()?)
    }
}

impl WebSocket {
    pub fn new_with_buffer(resp: Response, stream: Stream, buffer: Writer) -> HlsResult<WebSocket> {
        if resp.header().status() != HttpStatus::SwitchingProtocols {
            return Err("Connect Failed".into());
        }
        let compressed = resp.header().get_str("Sec-WebSocket-Extensions").map(|x| x.contains("permessage-deflate")).unwrap_or(false);
        let coder = if compressed {
            Some(DeflateStream::new_decompress(DeflateStream::DEFLATE)?)
        } else { None };
        Ok(Self {
            stream,
            read_buffer: buffer,
            write_buffer: Writer::with_capacity(8206),
            demask_buffer: Writer::with_capacity(2048),
            coder,
            mask: true,
        })
    }

    pub fn new(resp: Response, stream: Stream) -> HlsResult<WebSocket> {
        println!("{}", resp.raw_string());
        WebSocket::new_with_buffer(resp, stream, Writer::with_capacity(16384))
    }
}

pub struct WsRead<'a> {
    stream: &'a mut Stream,
    coder: &'a mut Option<DeflateStream>,
    demask_buffer: &'a mut Writer,
    read_buffer: &'a mut Writer,
}

impl<'a> WsRead<'a> {
    fn frame_len(&self) -> HlsResult<usize> {
        let mut reader = Reader::from_slice(self.read_buffer.filled());
        reader.read_u8()?;
        let masker = Marker::from_u8(reader.read_u8()?);
        let frame_len = match masker.len_code() {
            127 => reader.read_u64()? as usize + 8,
            126 => reader.read_u16()? as usize + 2,
            _ => masker.len_code() as usize
        } + if masker.mask() { 4 } else { 0 } + 2;
        Ok(frame_len)
    }
    pub fn wait(self) -> HlsResult<WsFrame> {
        self.read_buffer.check_move(16384)?;
        while self.read_buffer.len() < self.frame_len().unwrap_or(usize::MAX) {
            self.stream.read(self.read_buffer).wait()?;
        }
        let mut reader = Reader::from_slice(self.read_buffer.filled());
        let frame = WsFrame::from_reader(&mut reader, self.coder.as_mut(), self.demask_buffer)?;
        self.read_buffer.used_empty(reader.position());
        Ok(frame)
    }
}

#[cfg(feature = "aync")]
impl<'a> Future for WsRead<'a> {
    type Output = HlsResult<WsFrame>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let reading = self.get_mut();
        reading.read_buffer.check_move(16384)?;
        while reading.read_buffer.len() < reading.frame_len().unwrap_or(usize::MAX) {
            let mut buf_reading = reading.stream.read(reading.read_buffer);
            if Pin::new(&mut buf_reading).poll(cx)?.is_pending() { return Poll::Pending; }
        }
        let mut reader = Reader::from_slice(reading.read_buffer.filled());
        let frame = WsFrame::from_reader(&mut reader, reading.coder.as_mut(), reading.demask_buffer)?;
        reading.read_buffer.used_empty(reader.position());
        Poll::Ready(Ok(frame))
    }
}

pub struct WsWrite<'a> {
    stream: &'a mut Stream,
    write_buffer: &'a mut Writer,
    buf: &'a [u8],
    typ: WsOpcode,
    mask: bool,
    chunk_count: usize,
    chunk_index: usize,
}

impl<'a> WsWrite<'a> {
    fn build_frame(&mut self) -> HlsResult<()> {
        for (i, chunk) in self.buf.chunks(8192).enumerate() {
            if i < self.chunk_index { continue; }
            let typ = WsFrameType::new(self.chunk_count == i + 1, self.typ);
            let masker = Marker::new(self.mask, chunk.len());
            self.write_buffer.write_u8(typ.encode())?;
            self.write_buffer.write_u8(masker.encode())?;
            match masker.len_code() {
                0..126 => {}
                126 => self.write_buffer.write_u16(chunk.len() as u16)?,
                127 => self.write_buffer.write_u64(chunk.len() as u64)?,
                _ => unreachable!()
            }
            let mask = rand::random::<[u8; 4]>();
            match masker.mask() {
                true => {
                    self.write_buffer.write_slice(mask.as_slice())?;
                    for (i, c) in chunk.iter().enumerate() {
                        self.write_buffer.write_u8(c ^ mask[i % 4])?;
                    }
                }
                false => self.write_buffer.write_slice(chunk)?
            }
            self.chunk_index = i + 1;
        }

        Ok(())
    }

    pub fn wait(mut self) -> HlsResult<()> {
        while self.chunk_index < self.chunk_count {
            self.write_buffer.reset();
            self.build_frame()?;
            self.stream.write(self.write_buffer).wait()?;
        }
        Ok(())
    }
}

#[cfg(feature = "aync")]
impl<'a> Future for WsWrite<'a> {
    type Output = HlsResult<()>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let writing = self.get_mut();
        loop {
            if writing.chunk_index >= writing.chunk_count && writing.write_buffer.is_empty() { break; }
            if writing.write_buffer.is_empty() { writing.build_frame()?; }
            let mut buf_writing = writing.stream.write(writing.write_buffer);
            if Pin::new(&mut buf_writing).poll(cx)?.is_pending() { return Poll::Pending; }
        }
        Poll::Ready(Ok(()))
    }
}

impl WebSocket {
    pub fn read_frame(&mut self) -> WsRead<'_> {
        WsRead {
            stream: &mut self.stream,
            coder: &mut self.coder,
            read_buffer: &mut self.read_buffer,
            demask_buffer: &mut self.demask_buffer,
        }
    }

    pub(crate) fn send_frame<'a>(&'a mut self, typ: WsOpcode, buf: &'a [u8]) -> WsWrite<'a> {
        WsWrite {
            stream: &mut self.stream,
            write_buffer: &mut self.write_buffer,
            chunk_count: buf.chunks(8192).count(),
            buf,
            typ,
            mask: self.mask,
            chunk_index: 0,
        }
    }

    pub fn send_text<'a>(&'a mut self, text: &'a str) -> WsWrite<'a> {
        self.send_frame(WsOpcode::TEXT, text.as_bytes())
    }

    pub fn send_binary<'a>(&'a mut self, data: &'a [u8]) -> WsWrite<'a> {
        self.send_frame(WsOpcode::BINARY, data)
    }

    pub fn send_ping<'a>(&'a mut self, data: &'a [u8]) -> WsWrite<'a> {
        self.send_frame(WsOpcode::PING, data)
    }

    pub fn send_pong<'a>(&'a mut self, data: &'a [u8]) -> WsWrite<'a> {
        self.send_frame(WsOpcode::PONG, data)
    }

    pub fn shutdown(&mut self) -> StreamShutdown<'_> {
        self.stream.shutdown()
    }
}

