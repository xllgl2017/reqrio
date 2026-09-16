use crate::error::HlsResult;
use crate::pack::{PackError, QPackDecode, QPackEncode, QPackType};
use crate::packet::{H3Frame, H3Setting, H3Stream, HeaderParam};
use crate::request::RequestBuffer;
use crate::stream::ConnParam;
use crate::*;
use reqtls::quic::{self, QUICFrame, QUICFrameFlag};
use std::collections::HashMap;
use crate::stream::quic::Queue;
use crate::stream::quic::QUICStream;

pub struct StreamParam {
    typ: H3Stream,
    fin: bool,
    last_offset: usize,
    buffer: Writer,
}


pub struct HTTP3StreamS {
    quic: QUICStream<std::net::UdpSocket>,
    stream_ids: HashMap<u64, StreamParam>,
    encoder: QPackEncode,
    decoder: QPackDecode,
    write_buffer: Writer,
    max_stream: u64,
    sid: u64,
}

impl HTTP3StreamS {
    pub fn connect(socket: std::net::UdpSocket, mut conn: ConnParam) -> HlsResult<HTTP3StreamS> {
        let addr = conn.url.addr().socket_addr(false)?;
        let timeout = conn.timeout.clone();
        let mut quic = QUICStream::connect(socket, addr, ClientConfig::from(&mut conn), timeout).wait().unwrap();
        let mut write_buffer = Writer::with_capacity(4096);
        write_buffer.write_u8(0)?;
        for frame in &conn.fingerprint.h3().frames {
            frame.write_to(&mut write_buffer)?;
        }
        let setting_frame = QUICFrame::Stream {
            flag: QUICFrameFlag::new(0),
            sid: 2,
            offset: 0,
            payload: Buf::Ref(write_buffer.filled()),
            buf_pos: 0..0,
        };
        quic.write_stream(vec![setting_frame]).wait()?;
        write_buffer.reset();
        Ok(HTTP3StreamS {
            quic,
            stream_ids: Default::default(),
            encoder: QPackEncode::new(65536),
            decoder: QPackDecode::new(65536),
            write_buffer,
            max_stream: 100,
            sid: 0,
        })
    }


    pub fn recv(&mut self, responses: &mut HashMap<u64, Response>) -> HlsResult<Vec<u64>> {
        let mut res = vec![];
        let off = self.quic.read_next_packet().wait()?;
        self.quic.handle_queues(off, &mut self.stream_ids, HTTP3StreamS::handle_stream)?;
        HTTP3StreamS::handle_frame(RecvParam {
            stream_ids: &mut self.stream_ids,
            decoder: &mut self.decoder,
            encoder: &mut self.encoder,
            res: &mut res,
            max_stream: &mut self.max_stream,
            responses,
        })?;
        self.quic.send_ack(QUICFlag::new_short(PacketType::ShortHeader)).wait()?;
        Ok(res)
    }
    fn send_inner<'a>(&'a mut self, header: &Header, body: &Body<'_>, mut param: HeaderParam<'a>) -> HlsResult<u64> {
        param.q_sid = &self.sid;
        param.qpack_encoder = Some(&mut self.encoder);
        let mut request = RequestBuffer::new(header, body, param)?;
        let priority = header.get_str("priority");
        let mut offset = 0;
        self.write_buffer.reset();
        loop {
            let (chunk_size, frames) = HTTP3StreamS::build_send_frame(SendParam {
                buffer: &mut self.write_buffer,
                priority,
                offset,
                sid: self.sid,
            }, &mut request)?;
            if frames.is_empty() { break; }
            self.quic.write_stream(frames).wait()?;
            self.write_buffer.used_empty(chunk_size);
            offset += chunk_size;
        }
        Ok(self.sid)
    }


    pub fn send(&mut self, header: &Header, body: &Body<'_>, param: HeaderParam<'_>) -> HlsResult<u64> {
        let sid = self.send_inner(header, body, param)?;
        self.sid += 4;
        Ok(sid)
    }

    pub fn shutdown_sync(&mut self) -> HlsResult<()> {
        Ok(())
    }
}

impl H3Handle for HTTP3StreamS {}

struct SendParam<'a> {
    buffer: &'a mut Writer,
    priority: Option<&'a str>,
    offset: usize,
    sid: u64,
}

struct RecvParam<'a> {
    stream_ids: &'a mut HashMap<u64, StreamParam>,
    decoder: &'a mut QPackDecode,
    encoder: &'a mut QPackEncode,
    res: &'a mut Vec<u64>,
    max_stream: &'a mut u64,
    responses: &'a mut HashMap<u64, Response>,
}

trait H3Handle {
    fn build_send_frame<'a>(param: SendParam<'a>, request: &mut impl reader::ReadExt) -> HlsResult<(usize, Vec<QUICFrame<'a>>)> {
        reader::ReadExt::read(request, param.buffer)?;
        let filled = param.buffer.filled();
        let chunk_size = if filled.len() >= 1100 { 1100 } else { filled.len() };
        if chunk_size == 0 { return Ok((0, vec![])); }
        let chunk = &filled[..chunk_size];
        let stream = QUICFrame::Stream {
            flag: QUICFrameFlag::new(param.offset).with_fin(request.wrote() && filled.len() == chunk_size),
            sid: param.sid,
            offset: param.offset,
            payload: Buf::Ref(chunk),
            buf_pos: 0..0,
        };
        let streams = if param.offset == 0 && let Some(priority) = param.priority {
            let frame = H3Frame::PriorityUpdate {
                stream_id: param.sid,
                value: priority,
            };
            vec![QUICFrame::Stream {
                flag: QUICFrameFlag::new(44),
                sid: 2,
                offset: 44 + (param.sid as usize / 4) * 12,
                payload: Buf::Vec(frame.encode(44)?),
                buf_pos: 0..0,
            }, stream]
        } else { vec![stream] };
        Ok((chunk_size, streams))
    }

    fn handle_stream(stream_ids: &mut HashMap<u64, StreamParam>, sid: &u64, queues: &mut Vec<Queue>, buffers: &HashMap<u64, (Writer, usize)>) -> HlsResult<Option<u64>> {
        let param = stream_ids.entry(*sid).or_insert_with(|| StreamParam {
            typ: H3Stream::BidirectionalStream,
            fin: false,
            last_offset: 0,
            buffer: Writer::with_capacity(if sid & 0b10 == 0b10 { 1500 } else { 8192 }),
        });
        let pos = queues.iter().position(|x| x.offset == param.last_offset);
        let Some(pos) = pos else { return Ok(None) };
        let queue = queues.remove(pos);
        param.fin = param.fin || queue.fin;
        let (task_buffer, _) = &buffers[&queue.bid];
        param.buffer.check_move(queue.pos.len())?;
        param.last_offset += queue.pos.len();
        if param.buffer.unfilled_len() < queue.pos.len() {
            #[cfg(all(debug_assertions, feature = "log"))]
            warn!("[HTTP3] resize buffer = {}",param.buffer.capacity()*2);
            param.buffer.resize(queue.pos.len() - param.buffer.unfilled_len())?;
        }
        param.buffer.write_slice(task_buffer.slice(queue.pos))?;
        let mut reader = Reader::from_slice(param.buffer.filled());
        if sid & 0b10 == 0b10 && queue.offset == 0 {
            param.typ = quic::read_variant(&mut reader)?.into();
            param.buffer.used_empty(reader.position());
        }
        Ok(Some(queue.bid))
    }

    fn handle_frame(recv: RecvParam) -> HlsResult<()> {
        let mut items = recv.stream_ids.iter_mut();
        let mut handle_enc = false;
        while let Some((sid, param)) = items.next() {
            if param.buffer.is_empty() {
                if param.fin { recv.res.push(*sid) };
                continue;
            }
            let mut reader = Reader::from_slice(param.buffer.filled());
            #[cfg(feature = "log")]
            debug!("[HTTP3] recv quic: typ={:?}; sid={}; fin={}; off={}",param.typ, sid,  param.fin, param.last_offset);
            let mut pos = reader.position();
            while reader.unread_len() > 0 {
                let frame = match param.typ.handle_stream(&mut reader, recv.decoder) {
                    Ok(frame) => frame,
                    Err(HlsError::Rls(RlsError::Buffer(BufferError::Insufficient))) => break,
                    Err(HlsError::Rls(RlsError::Buffer(BufferError::IndexOutBound { .. }))) => break,
                    Err(e) => return Err(e)
                };
                println!("{:#?}", frame);
                match frame {
                    H3Frame::Settings(settings) => for setting in settings {
                        match setting.flag() {
                            H3Setting::MaxTableCapacity => {
                                recv.encoder.update_table_size(setting.value() as usize);
                                recv.decoder.update_table_size(setting.value() as usize);
                            }
                            H3Setting::BlockedStreams => *recv.max_stream = setting.value(),
                            _ => {}
                        }
                    }
                    //客户端忽略，服务端暂不处理
                    H3Frame::PriorityUpdate { .. } => {}
                    H3Frame::Headers(hdr) => {
                        let Some(response) = recv.responses.get_mut(sid) else { continue };
                        let read_size = match recv.decoder.decode_into(hdr.as_ref(), response.header_mut(), QPackType::Stream, sid) {
                            Ok(size) => size,
                            Err(HlsError::HPack(PackError::BlockedStream(_))) => break,
                            Err(e) => return Err(e)
                        };
                        assert_eq!(read_size, hdr.len());
                        response.make_coding()?;
                    }
                    H3Frame::Data(body) => {
                        let Some(response) = recv.responses.get_mut(sid) else { continue };
                        response.push_raw_slice(body.as_ref())?;
                    }
                    H3Frame::Reserved { .. } => {}
                }
                pos = reader.position();
            }
            param.buffer.used_empty(pos);
            if param.fin && param.buffer.is_empty() { recv.res.push(*sid); }
            if param.typ == H3Stream::QPackEncoder && !handle_enc {
                items = recv.stream_ids.iter_mut();
                handle_enc = true;
            }
        }
        Ok(())
    }
}


#[cfg(feature = "aync")]
pub struct HTTP3StreamA {
    quic: QUICStream<tokio::net::UdpSocket>,
    stream_ids: HashMap<u64, StreamParam>,
    encoder: QPackEncode,
    decoder: QPackDecode,
    write_buffer: Writer,
    max_stream: u64,
    sid: u64,
}

#[cfg(feature = "aync")]
impl HTTP3StreamA {
    pub async fn connect(socket: tokio::net::UdpSocket, mut conn: ConnParam<'_>) -> HlsResult<HTTP3StreamA> {
        let addr = conn.url.addr().socket_addr(false)?;
        let timeout = conn.timeout.clone();
        let mut quic = QUICStream::connect(socket, addr, ClientConfig::from(&mut conn), timeout).await.unwrap();
        let mut write_buffer = Writer::with_capacity(4096);
        write_buffer.write_u8(0)?;
        for frame in &conn.fingerprint.h3().frames {
            frame.write_to(&mut write_buffer)?;
        }
        let setting_frame = QUICFrame::Stream {
            flag: QUICFrameFlag::new(0),
            sid: 2,
            offset: 0,
            payload: Buf::Ref(write_buffer.filled()),
            buf_pos: 0..0,
        };
        quic.write_stream(vec![setting_frame]).await?;
        write_buffer.reset();
        Ok(HTTP3StreamA {
            quic,
            stream_ids: Default::default(),
            encoder: QPackEncode::new(65536),
            decoder: QPackDecode::new(65536),
            write_buffer,
            max_stream: 100,
            sid: 0,
        })
    }


    pub async fn recv(&mut self, responses: &mut HashMap<u64, Response>) -> HlsResult<Vec<u64>> {
        let mut res = vec![];
        let off = self.quic.read_next_packet().await?;
        self.quic.handle_queues(off, &mut self.stream_ids, HTTP3StreamA::handle_stream)?;
        HTTP3StreamA::handle_frame(RecvParam {
            stream_ids: &mut self.stream_ids,
            decoder: &mut self.decoder,
            encoder: &mut self.encoder,
            res: &mut res,
            max_stream: &mut self.max_stream,
            responses,
        })?;
        self.quic.send_ack(QUICFlag::new_short(PacketType::ShortHeader)).await?;
        Ok(res)
    }
    async fn send_inner<'a>(&'a mut self, header: &Header, body: &Body<'_>, mut param: HeaderParam<'a>) -> HlsResult<u64> {
        param.q_sid = &self.sid;
        param.qpack_encoder = Some(&mut self.encoder);
        let mut request = RequestBuffer::new(header, body, param)?;
        let priority = header.get_str("priority");
        let mut offset = 0;
        self.write_buffer.reset();
        self.quic.send_ack(QUICFlag::new_short(PacketType::ShortHeader)).await?;
        loop {
            let (chunk_size, frames) = HTTP3StreamA::build_send_frame(SendParam {
                buffer: &mut self.write_buffer,
                priority,
                offset,
                sid: self.sid,
            }, &mut request)?;
            if frames.is_empty() { break; }
            self.quic.write_stream(frames).await?;
            self.write_buffer.used_empty(chunk_size);
            offset += chunk_size;
        }
        Ok(self.sid)
    }


    pub async fn send(&mut self, header: &Header, body: &Body<'_>, param: HeaderParam<'_>) -> HlsResult<u64> {
        let sid = self.send_inner(header, body, param).await?;
        self.sid += 4;
        Ok(sid)
    }
}

#[cfg(feature = "aync")]
impl H3Handle for HTTP3StreamA {}