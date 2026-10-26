use crate::body::RawBodyReader;
use crate::error::HlsResult;
use crate::pack::{PackError, QPackDecode, QPackEncode, QPackType};
use crate::packet::{H3FrameType, H3Payload, H3Setting, H3Stream};
use crate::reader::ReadExt;
use crate::stream::quic::QUICStream;
use crate::stream::quic::Queue;
use crate::stream::{SendParam, StreamMessage};
use crate::*;
use reqtls::quic::{self, QUICFrameFlag};
use std::collections::HashMap;

pub struct H3StreamParam {
    pub(crate) typ: H3Stream,
    pub(crate) send_offset: usize,
    pub(crate) recv_fin: bool,
    pub(crate) recv_offset: usize,
    pub(crate) buffer: Writer,
}

pub struct HTTP3Stream<S> {
    stream: QUICStream<S>,
    stream_ids: HashMap<u64, H3StreamParam>,
    encoder: QPackEncode,
    decoder: QPackDecode,
    max_stream: u64,
    sid: u64,
}

impl<S> HTTP3Stream<S> {
    pub fn new(stream: QUICStream<S>, offset: usize) -> HTTP3Stream<S> {
        let mut stream_ids = HashMap::with_capacity(30);
        stream_ids.insert(2, H3StreamParam {
            typ: H3Stream::Control,
            send_offset: offset,
            recv_fin: false,
            recv_offset: 0,
            buffer: Buffer::none(),
        });
        HTTP3Stream {
            stream,
            stream_ids,
            encoder: QPackEncode::new(65536),
            decoder: QPackDecode::new(65536),
            max_stream: 100,
            sid: 0,
        }
    }
    pub fn shutdown_sync(&mut self) -> HlsResult<()> {
        Ok(())
    }

    fn build_frame_head(typ: H3FrameType, off: usize, mut len: usize, sid: u64, flag: QUICFrameFlag, writer: &mut Writer) -> std::io::Result<usize> {
        //----------H3 Frame
        len += quic::write_variant_front(len as u64, writer)?;
        len += quic::write_variant_front(typ.into_inner(), writer)?;
        // ----------QUIC Frame
        quic::write_variant_front(len as u64, writer)?;
        if flag.offset() {
            quic::write_variant_front(off as u64, writer)?;
        }
        quic::write_variant_front(sid, writer)?;
        quic::write_variant_front(flag.encode(), writer)?;
        Ok(off + len)
    }

    fn encode_hdr(&mut self, body_len: usize, param: &SendParam, index: &mut usize) -> std::io::Result<Buffer> {
        let stream_param = self.stream_ids.entry(self.sid).or_insert_with(|| H3StreamParam {
            typ: H3Stream::BidirectionalStream,
            send_offset: 0,
            recv_fin: false,
            recv_offset: 0,
            buffer: Buffer::with_capacity(8192),
        });
        let mut writer = self.stream.alloc_buffer();
        writer.reset_offset(100..100);
        if *index == 0 {
            self.encoder.encode_head(&mut writer)?;
            self.encoder.encode_one(QPackType::Stream, ":method", param.method.spec(), self.sid, &mut writer)?;
            if param.url.addr().port() == 443 {
                self.encoder.encode_one(QPackType::Stream, ":authority", param.url.sni(), self.sid, &mut writer)?;
            } else {
                let authority = format!("{}:{}", param.url.sni(), param.url.addr().port());
                self.encoder.encode_one(QPackType::Stream, ":authority", authority, self.sid, &mut writer)?;
            }
            self.encoder.encode_one(QPackType::Stream, ":scheme", param.url.scheme().spec(), self.sid, &mut writer)?;
            if param.url.uri().path().is_empty() {
                self.encoder.encode_one(QPackType::Stream, ":path", "/", self.sid, &mut writer)?;
            } else {
                self.encoder.encode_one(QPackType::Stream, ":path", param.url.uri().to_string(), self.sid, &mut writer)?;
            }
        }
        let mut flag = QUICFrameFlag::new(stream_param.send_offset).with_fin(body_len == 0);
        for (i, key) in param.header.iter().enumerate() {
            if i < *index { continue; }
            if writer.len() > 1300 {
                flag = flag.with_fin(false);
                break;
            }
            *index = i;
            match key.name() {
                "host" | "Host" | "Transfer-Encoding" | "transfer-encoding" |
                "Upgrade" | "upgrade" | "connection" | "Connection" => continue,
                "content-length" | "Content-Length" => {
                    if body_len == 0 && param.method == Method::GET { continue; }
                    self.encoder.encode_one(QPackType::Stream, key.name(), body_len.to_string(), self.sid, &mut writer)?;
                }
                "content-type" | "Content-Type" => {
                    if matches!(param.body.context_type(), ContentType::Null) { continue; }
                    self.encoder.encode_one(QPackType::Stream, key.name(), param.body.context_type().spec(), self.sid, &mut writer)?;
                }
                "cookie" | "Cookie" => {
                    let cookies = key.cookies().unwrap_or(&[]);
                    if cookies.is_empty() { continue; }
                    for cookie in cookies.iter() {
                        self.encoder.encode_one(QPackType::Stream, key.name(), cookie.as_req(), self.sid, &mut writer)?;
                    }
                }
                _ => {
                    if key.value().is_empty() && key.is_reserved() { continue; }
                    match key.value() {
                        HeaderValue::String(v) => self.encoder.encode_one(QPackType::Stream, key.name(), v, self.sid, &mut writer)?,
                        _ => self.encoder.encode_one(QPackType::Stream, key.name(), key.value().to_string(), self.sid, &mut writer)?
                    }
                }
            };
        }
        stream_param.send_offset = HTTP3Stream::<S>::build_frame_head(
            H3FrameType::Header, stream_param.send_offset, writer.len(), self.sid, flag, &mut writer)?;
        if stream_param.send_offset == 0 && let Some(priority) = param.header.get_str("priority") {
            let param = self.stream_ids.get_mut(&2).unwrap();
            let mut len = writer.write_slice_front(priority.as_bytes())?;
            len += quic::write_variant_front(self.sid, &mut writer)?;
            let flag = QUICFrameFlag::new(param.send_offset);
            param.send_offset = HTTP3Stream::<S>::build_frame_head(H3FrameType::PriorityUpdate, param.send_offset, len, 2, flag, &mut writer)?;
        }
        Ok(writer)
    }

    fn encode_body(&mut self, reader: &mut RawBodyReader) -> std::io::Result<Buffer> {
        let stream_param = self.stream_ids.entry(self.sid).or_insert_with(|| H3StreamParam {
            typ: H3Stream::BidirectionalStream,
            send_offset: 0,
            recv_fin: false,
            recv_offset: 0,
            buffer: Buffer::with_capacity(8192),
        });
        let mut buffer = self.stream.alloc_buffer();
        buffer.reset_offset(100..100);

        let mut writer = Writer::from_ptr(buffer.unfilled_ptr(), buffer.unfilled_len() - 150);
        reader.read(&mut writer)?;
        let flag = QUICFrameFlag::new(stream_param.send_offset).with_fin(reader.wrote());
        buffer.add_len(writer.len());


        stream_param.send_offset = HTTP3Stream::<S>::build_frame_head(H3FrameType::Header, stream_param.send_offset, writer.len(), self.sid, flag, &mut buffer)?;
        Ok(buffer)
    }
}

impl HTTP3Stream<std::net::UdpSocket> {
    pub fn recv(&mut self, responses: &mut HashMap<u64, StreamMessage>) -> HlsResult<Vec<u64>> {
        let mut res = vec![];
        let off = self.stream.read_next_packet().wait()?;
        self.stream.handle_queues(off, &mut self.stream_ids, HTTP3Stream::<std::net::UdpSocket>::handle_stream)?;
        HTTP3Stream::<std::net::UdpSocket>::handle_frame(RecvParam1 {
            stream_ids: &mut self.stream_ids,
            decoder: &mut self.decoder,
            encoder: &mut self.encoder,
            res: &mut res,
            max_stream: &mut self.max_stream,
            responses,
        })?;
        self.stream.send_ack(QUICFlag::new_short(PacketType::ShortHeader), !res.is_empty()).wait()?;
        Ok(res)
    }

    pub fn send(&mut self, param: SendParam) -> HlsResult<u64> {
        let mut body_reader = param.body.as_reader()?;
        let mut index = 0;
        while index + 1 < param.header.len() {
            let buffer = self.encode_hdr(body_reader.len(), &param, &mut index)?;
            self.stream.write_packet(buffer).wait()?;
        }
        while body_reader.len() != 0 && !body_reader.wrote() {
            let buffer = self.encode_body(&mut body_reader)?;
            self.stream.write_packet(buffer).wait()?;
        }
        let sid = self.sid;
        self.sid += 4;
        Ok(sid)
    }

    fn handle_stream(stream_ids: &mut HashMap<u64, H3StreamParam>, sid: &u64, queues: &mut Vec<Queue>, buffers: &HashMap<u64, (Writer, usize)>) -> HlsResult<Option<u64>> {
        let param = stream_ids.entry(*sid).or_insert_with(|| H3StreamParam {
            typ: H3Stream::BidirectionalStream,
            send_offset: 0,
            recv_fin: false,
            recv_offset: 0,
            buffer: Writer::with_capacity(if sid & 0b10 == 0b10 { 1500 } else { 8192 }),
        });
        let pos = queues.iter().position(|x| x.offset == param.recv_offset);
        let Some(pos) = pos else { return Ok(None) };
        let queue = queues.remove(pos);
        param.recv_fin = param.recv_fin || queue.fin;
        let (task_buffer, _) = &buffers[&queue.bid];
        param.buffer.check_move(queue.pos.len())?;
        param.recv_offset += queue.pos.len();
        if param.buffer.unfilled_len() < queue.pos.len() {
            #[cfg(all(debug_assertions, feature = "log"))]
            warn!("[HTTP3] resize buffer = {}",param.buffer.capacity()*2);
            param.buffer.resize(queue.pos.len() - param.buffer.unfilled_len())?;
        }
        param.buffer.write_slice(task_buffer.slice(queue.pos))?;
        let mut reader = Reader::from_slice(param.buffer.filled());
        if sid & 0b10 == 0b10 && queue.offset == 0 {
            param.typ = H3Stream::from(quic::read_variant(&mut reader)? as usize);
            param.buffer.used_empty(reader.position());
        }
        Ok(Some(queue.bid))
    }

    fn handle_frame(recv: RecvParam1) -> HlsResult<()> {
        let mut items = recv.stream_ids.iter_mut();
        let mut handle_enc = false;
        while let Some((sid, param)) = items.next() {
            if param.buffer.is_empty() {
                if param.recv_fin { recv.res.push(*sid) };
                continue;
            }
            let mut reader = Reader::from_slice(param.buffer.filled());
            #[cfg(all(debug_assertions, feature = "log"))]
            trace!("[HTTP3] recv stream: typ={:?}; sid={}; fin={}; off={}",param.typ, sid,  param.recv_fin, param.recv_offset);
            let mut pos = reader.position();
            while reader.unread_len() > 0 {
                let frame = match param.typ.handle_stream(&mut reader, recv.decoder) {
                    Ok(frame) => frame,
                    Err(HlsError::Rls(RlsError::Buffer(BufferError::Insufficient))) => break,
                    Err(HlsError::Rls(RlsError::Buffer(BufferError::IndexOutBound { .. }))) => break,
                    Err(e) => return Err(e)
                };
                match (frame.frame_type(), frame.payload()) {
                    (H3FrameType::Header, H3Payload::Bytes(buf)) => {
                        let Some(response) = recv.responses.get_mut(sid) else { continue };
                        let read_size = match recv.decoder.decode_into(buf.as_ref(), response, QPackType::Stream, *sid) {
                            Ok(size) => size,
                            Err(HlsError::HPack(PackError::BlockedStream(_))) => break,
                            Err(e) => return Err(e)
                        };
                        assert_eq!(read_size, buf.len());
                        response.make_coding()?;
                    }
                    (H3FrameType::Data, H3Payload::Bytes(buf)) => {
                        let Some(response) = recv.responses.get_mut(sid) else { continue };
                        response.extend_body(buf.as_slice())?;
                    }
                    (H3FrameType::Setting, H3Payload::Settings(settings)) => {
                        for setting in settings {
                            match setting.flag() {
                                H3Setting::MaxTableCapacity => {
                                    recv.encoder.update_table_size(setting.value() as usize);
                                    recv.decoder.update_table_size(setting.value() as usize);
                                }
                                H3Setting::BlockedStreams => *recv.max_stream = setting.value(),
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
                pos = reader.position();
            }
            param.buffer.used_empty(pos);
            if param.recv_fin && param.buffer.is_empty() { recv.res.push(*sid); }
            if param.typ == H3Stream::QPackEncoder && !handle_enc {
                items = recv.stream_ids.iter_mut();
                handle_enc = true;
            }
        }
        for re in recv.res {
            recv.stream_ids.remove(re);
        }
        Ok(())
    }
}

#[cfg(feature = "aync")]
impl HTTP3Stream<tokio::net::UdpSocket> {
    pub async fn recv(&mut self, responses: &mut HashMap<u64, StreamMessage>) -> HlsResult<Vec<u64>> {
        let mut res = vec![];
        let off = self.stream.read_next_packet().await?;
        self.stream.handle_queues(off, &mut self.stream_ids, HTTP3Stream::<std::net::UdpSocket>::handle_stream)?;
        HTTP3Stream::<std::net::UdpSocket>::handle_frame(RecvParam1 {
            stream_ids: &mut self.stream_ids,
            decoder: &mut self.decoder,
            encoder: &mut self.encoder,
            res: &mut res,
            max_stream: &mut self.max_stream,
            responses,
        })?;
        self.stream.send_ack(QUICFlag::new_short(PacketType::ShortHeader), !res.is_empty()).await?;
        Ok(res)
    }

    pub async fn send(&mut self, param: SendParam<'_>) -> HlsResult<u64> {
        let mut body_reader = param.body.as_reader()?;
        let mut index = 0;
        while index + 1 < param.header.len() {
            let buffer = self.encode_hdr(body_reader.len(), &param, &mut index)?;
            self.stream.write_packet(buffer).await?;
        }
        while body_reader.len() != 0 && !body_reader.wrote() {
            let buffer = self.encode_body(&mut body_reader)?;
            self.stream.write_packet(buffer).await?;
        }
        let sid = self.sid;
        self.sid += 4;
        Ok(sid)
    }
}

struct RecvParam1<'a> {
    stream_ids: &'a mut HashMap<u64, H3StreamParam>,
    decoder: &'a mut QPackDecode,
    encoder: &'a mut QPackEncode,
    res: &'a mut Vec<u64>,
    max_stream: &'a mut u64,
    responses: &'a mut HashMap<u64, StreamMessage>,
}

#[cfg(test)]
mod tests {
    use super::HTTP3Stream;
    use crate::packet::H3FrameType;
    use reqtls::Writer;
    use reqtls::quic::QUICFrameFlag;

    #[test]
    fn test_frame_head_encode() {
        let mut writer = Writer::with_capacity(256);
        writer.reset_offset(100..100);
        writer.write_slice((0..50).collect::<Vec<_>>().as_slice()).unwrap();
        let offset = HTTP3Stream::<std::net::UdpSocket>::build_frame_head(
            H3FrameType::Header,
            0,
            writer.len(),
            0,
            QUICFrameFlag::new(0).with_fin(true),
            &mut writer,
        ).unwrap();
        assert_eq!(offset, 52);
        assert_eq!(&writer.filled()[..10], [11, 0, 52, 1, 50, 0, 1, 2, 3, 4]);
    }
}