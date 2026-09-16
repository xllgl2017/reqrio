mod connect;
mod write;
mod read;

use crate::error::HlsResult;
use crate::stream::http3;
use connect::{QUICConnState, QUICConnect};
use read::QUICPacketRead;
use write::QUICPacketWrite;
use crate::Timeout;
use reqtls::quic::*;
use reqtls::*;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::ops::Range;

#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone)]
pub(crate) enum QId {
    HId,
    AId(u64),
}

#[derive(Debug)]
pub(crate) struct Queue {
    pub(crate) bid: u64,
    pub(crate) fin: bool,
    pub(crate) offset: usize,
    pub(crate) pos: Range<usize>,
}

pub struct QUICStream<S> {
    socket: S,
    ur_buffer: Writer,
    tr_last_offset: usize,
    tr_buffer: Writer,
    uw_buffer: Writer,

    tw_buffer: Writer,
    conn: QUICConnection,
    sent_num: HashMap<u64, Range<usize>>,

    addr: SocketAddr,
    seq: u64,
    dcid: Buf<'static>,
    token: Buf<'static>,

    handshake_finish: bool,
    encrypted_channel: bool,
    hello_retrying: bool,
    crypto_offset: usize,

    packet_offsets: Vec<(PacketType, Range<usize>)>,
    current: PacketType,
    idle_buffer: Vec<(u64, Writer)>,

    buffer_size: u64,
    task_buffer: HashMap<u64, (Writer, usize)>,
    buffer_queues: HashMap<QId, Vec<Queue>>,

    timeout: Timeout,
}


impl<S> QUICStream<S> {
    pub fn connect(socket: S, remote_addr: SocketAddr, config: ClientConfig<'_>, mut timeout: Timeout) -> QUICConnect<'_, S> {
        let session = config.session.clone().unwrap_or_default();
        let key_log = config.key_log.clone();
        timeout.reset_connect();
        QUICConnect {
            state: QUICConnState::Connecting(Box::new(QUICStream {
                socket,
                ur_buffer: Writer::with_capacity(6000),
                tr_last_offset: 0,
                tr_buffer: Writer::with_capacity(8192),
                uw_buffer: Writer::with_capacity(1500),
                tw_buffer: Writer::with_capacity(16438),
                conn: QUICConnection::new(session, key_log, config.verify),
                sent_num: HashMap::new(),
                addr: remote_addr,
                seq: 1,
                dcid: Buf::Vec(rand::random::<[u8; 8]>().to_vec()),
                token: Buf::Ref(&[]),
                handshake_finish: false,
                encrypted_channel: false,
                hello_retrying: false,
                crypto_offset: 0,
                packet_offsets: vec![],
                current: PacketType::Initial,
                idle_buffer: vec![],
                buffer_size: 0,
                task_buffer: Default::default(),
                buffer_queues: Default::default(),
                timeout,
            })),
            config: Config::Client(config),
            sent_hello: false,
        }
    }

    pub fn send_ack(&mut self, flag: QUICFlag) -> QUICPacketWrite<'_, S> {
        let mut writer = QUICPacketWrite {
            packet: QUICPacket::default(),
            frames: vec![],
            uw_buffer: &mut self.uw_buffer,
            conn: &mut self.conn,
            socket: &mut self.socket,
            chunk_size: 0,
            seq: &mut self.seq,
            sent_num: &mut self.sent_num,
            addr: &self.addr,
            #[cfg(feature = "aync")]
            timeout: &mut self.timeout,
        };
        if writer.conn.recv_nums().is_empty() || !writer.conn.recv_nums().need_ack() { return writer; }
        writer.conn.recv_nums_mut().sort();
        println!("{:?}", writer.conn.recv_nums());
        let Some(max_range) = writer.conn.recv_nums().max_range() else { return writer };
        let mut ack_range = Vec::with_capacity(writer.conn.recv_nums().count() - 1);
        let remain = writer.conn.recv_nums().count() - 1;
        let mut pre_start = max_range.start;
        for i in 0..remain {
            let r = writer.conn.recv_nums().get(remain - i - 1);
            ack_range.push(AckRange {
                gap: pre_start - r.end - 2,
                range: r.end - r.start,
            });
            pre_start = r.start;
        }
        let frame = QUICFrame::Ack {
            largest_acknowledged: max_range.end,
            ack_delay: 200,
            ack_range_count: ack_range.len(),
            first_ack_range: max_range.end - max_range.start,
            ack_range,
        };
        writer.packet = QUICPacket::new_ack(flag, self.dcid.as_ref(), *writer.seq, frame.len());
        writer.frames.push(frame);
        writer.conn.recv_nums_mut().reset_sent_largest();
        writer
    }


    pub(super) fn write_crypto(&mut self, typ: PacketType) -> QUICPacketWrite<'_, S> {
        let chunks = self.tw_buffer.filled().chunks(350);
        let mut frames = Vec::with_capacity(10);
        let mut pd_len = 0;
        let start = self.crypto_offset;
        for chunk in chunks {
            if pd_len + chunk.len() > 1210 { break; }
            let frame = QUICFrame::Crypto {
                offset: self.crypto_offset,
                value: Buf::Ref(chunk),
                buf_pos: 0..0,
            };
            pd_len += frame.len();
            frames.push(frame);
            if self.crypto_offset == 0 {
                frames.insert(0, QUICFrame::Ping);
                pd_len += 1;
            }
            self.crypto_offset += chunk.len();
        }
        self.timeout.reset_write();
        QUICPacketWrite {
            packet: QUICPacket::new_long(typ, self.seq, pd_len, self.dcid.as_ref(), &self.token),
            frames,
            uw_buffer: &mut self.uw_buffer,
            conn: &mut self.conn,
            socket: &mut self.socket,
            chunk_size: self.crypto_offset - start,
            seq: &mut self.seq,
            sent_num: &mut self.sent_num,
            addr: &self.addr,
            #[cfg(feature = "aync")]
            timeout: &mut self.timeout,
        }
    }

    pub fn read_next_packet(&mut self) -> QUICPacketRead<'_, S> {
        self.timeout.reset_read();
        QUICPacketRead {
            socket: &mut self.socket,
            buffer: &mut self.ur_buffer,
            packet_offsets: &mut self.packet_offsets,
            current: self.current,
            #[cfg(feature = "aync")]
            timeout: &mut self.timeout,
        }
    }

    fn free_buffer(task_buffer: &mut HashMap<u64, (Writer, usize)>, idle_buffer: &mut Vec<(u64, Writer)>, bid: u64) -> Result<(), QUICError> {
        if task_buffer[&bid].1 <= 1 {
            if let Some((mut buffer, _)) = task_buffer.remove(&bid) {
                buffer.reset();
                idle_buffer.push((bid, buffer))
            }
        } else if let Some((_, buf_ref)) = task_buffer.get_mut(&bid) {
            *buf_ref -= 1;
        }
        Ok(())
    }

    fn handle_packet(&mut self, mut off: Range<usize>) -> Result<(), QUICError> {
        let mut reader = Reader::from_slice(self.ur_buffer.slice(off.clone()));
        let mut packet = QUICPacket::from_reader(&mut reader)?;
        if packet.flag().packet_type() == PacketType::Initial {
            self.conn.make_initial_cipher(packet.dc_id(), false)?;
        } else if packet.flag().packet_type() == PacketType::Retry {
            self.token = Buf::Vec(packet.token().to_vec());
            self.dcid = Buf::Vec(packet.sc_id().to_vec());
            return Err(QUICError::InitialRetry);
        }
        if self.dcid.as_ref() != packet.sc_id().as_ref() && !packet.sc_id().as_ref().is_empty() {
            self.dcid = Buf::Vec(packet.sc_id().as_ref().to_vec());
        }
        let (bid, mut idle_buffer) = if self.idle_buffer.is_empty() {
            let bid = self.buffer_size;
            self.buffer_size = bid + 1;
            (bid, Writer::with_capacity(1500))
        } else { self.idle_buffer.remove(0) };
        let len = self.conn.read_message(&mut packet, &mut reader, idle_buffer.unfilled()).unwrap();
        idle_buffer.add_len(len);
        assert_eq!(packet.len(), reader.position());
        let zero_len = reader.find(|&b| b != 0).unwrap_or(reader.unread_len());
        reader.read_slice(zero_len)?;
        off.start += reader.position();
        if !off.is_empty() {
            let flag = QUICFlag::from_raw(reader.inner()[reader.position()]);
            self.packet_offsets.insert(0, (flag.packet_type(), off));
        }
        self.handle_frames(bid, idle_buffer)
    }

    fn handle_frames(&mut self, bid: u64, buffer: Writer) -> Result<(), QUICError> {
        let mut reader = Reader::from_slice(buffer.filled());
        let mut buf_ref = 0;
        while reader.unread_len() > 0 {
            let frame = QUICFrame::from_reader(&mut reader).unwrap();
            if frame.need_ack() { self.conn.recv_nums_mut().set_ack(true) }
            match frame {
                QUICFrame::Ack { largest_acknowledged, first_ack_range, .. } => {
                    let start = largest_acknowledged - first_ack_range;
                    for large in start..=largest_acknowledged {
                        self.sent_num.remove(&large);
                    }
                }
                QUICFrame::ConnectionCloseTrp { reason, err_code, .. } => return Err(QUICError::TransportError { reason: reason.to_string(), err_code }),
                QUICFrame::Crypto { offset, buf_pos, .. } => {
                    #[cfg(feature = "log")]
                    trace!("[QUIC Frame] off={}; pd={}; pos={:?};", offset, buf_pos.len(), buf_pos);
                    let queues = self.buffer_queues.entry(QId::HId).or_insert_with(|| Vec::with_capacity(30));
                    queues.push(Queue {
                        bid,
                        fin: false,
                        offset,
                        pos: buf_pos,
                    });
                    buf_ref += 1;
                }
                QUICFrame::Stream { flag, sid, offset, buf_pos, .. } => {
                    #[cfg(feature = "log")]
                    trace!("[QUIC Frame] fin={}; sid={}; off={}; pd={}; pos={:?}", flag.fin(), sid, offset, buf_pos.len(), buf_pos);
                    let queues = self.buffer_queues.entry(QId::AId(sid)).or_insert_with(|| Vec::with_capacity(30));
                    queues.push(Queue {
                        bid,
                        fin: flag.fin(),
                        offset,
                        pos: buf_pos,
                    });
                    buf_ref += 1;
                }
                QUICFrame::Ping |
                QUICFrame::Padding(_) |
                QUICFrame::HandshakeDone |
                QUICFrame::NewConnectionId { .. } |
                QUICFrame::MaxStreamsBidi(_) |
                QUICFrame::MaxStreamData { .. } |
                QUICFrame::NewToken(_) => {}
                _ => unreachable!()
            }
        }
        if buf_ref != 0 { self.task_buffer.insert(bid, (buffer, buf_ref)); }
        Ok(())
    }

    pub(crate) fn handle_queues<F>(&mut self, off: Range<usize>, streams: &mut HashMap<u64, http3::StreamParam>, mut worker: F) -> HlsResult<()>
    where
        F: FnMut(&mut HashMap<u64, http3::StreamParam>, &u64, &mut Vec<Queue>, &HashMap<u64, (Writer, usize)>) -> HlsResult<Option<u64>>,
    {
        self.handle_packet(off)?;
        let mut keys = Vec::with_capacity(self.buffer_queues.len());

        for (qid, queues) in &mut self.buffer_queues {
            while !queues.is_empty() {
                let bid = match qid {
                    QId::AId(sid) => worker(streams, sid, queues, &self.task_buffer)?,
                    QId::HId => {
                        let pos = queues.iter().position(|x| x.offset == self.tr_last_offset);
                        let Some(pos) = pos else { break };
                        let queue = queues.remove(pos);
                        let (buffer, _) = &self.task_buffer[&queue.bid];
                        self.tr_buffer.check_move(queue.pos.len())?;
                        if self.tr_buffer.unfilled_len() < queue.pos.len() {
                            #[cfg(all(debug_assertions, feature = "log"))]
                            warn!("[QUIC] resize buffer = {}", self.tr_buffer.capacity()*2);
                            self.tr_buffer.resize(queue.pos.len() - self.tr_buffer.unfilled_len())?;
                        }
                        self.tr_last_offset += queue.pos.len();
                        self.tr_buffer.write_slice(buffer.slice(queue.pos))?;
                        Some(queue.bid)
                    }
                };
                let Some(bid) = bid else { break };
                QUICStream::<S>::free_buffer(&mut self.task_buffer, &mut self.idle_buffer, bid)?;
            }
            if queues.is_empty() { keys.push(*qid) }
        }
        for key in keys {
            self.buffer_queues.remove(&key);
        }
        Ok(())
    }


    pub fn write_stream<'a>(&'a mut self, frames: Vec<QUICFrame<'a>>) -> QUICPacketWrite<'a, S> {
        let pd_len = frames.iter().map(|s| s.len()).sum::<usize>();
        QUICPacketWrite {
            packet: QUICPacket::new_short(PacketType::ShortHeader, self.seq, pd_len, self.dcid.as_ref()),
            frames,
            uw_buffer: &mut self.uw_buffer,
            conn: &mut self.conn,
            socket: &mut self.socket,
            chunk_size: 0,
            seq: &mut self.seq,
            sent_num: &mut self.sent_num,
            addr: &self.addr,
            #[cfg(feature = "aync")]
            timeout: &mut self.timeout,
        }
    }
}

impl<S> StreamHandle for QUICStream<S> {
    fn stream_param(&mut self) -> (&Writer, StreamParam<'_>) {
        (&self.tr_buffer, StreamParam {
            handshake_finish: &mut self.handshake_finish,
            encrypted_channel: &mut self.encrypted_channel,
            hello_retrying: &mut self.hello_retrying,
            write_buffer: &mut self.tw_buffer,
            conn: self.conn.tls_conn(),
        })
    }
}
