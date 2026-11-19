mod connect;
mod write;
mod read;

use crate::error::HlsResult;
use crate::stream::http3;
pub use connect::QUICConnect;
use connect::QUICConnState;
use crate::Timeout;
pub(crate) use write::QUICPacketWrite;
use read::QUICPacketRead;
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
    udp_read_buffer: Writer,
    tr_last_offset: usize,
    tls_read_buffer: Writer,
    udp_write_buffer: Writer,

    tls_write_buffer: Writer,
    conn: QUICConnection,
    wait_ack: HashMap<u64, Buffer>,

    addr: SocketAddr,

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
    #[allow(unused)]
    timeout: Timeout,
}


impl<S> QUICStream<S> {
    pub fn connect(socket: S, remote_addr: SocketAddr, config: ClientConfig<'_>, timeout: Timeout) -> QUICConnect<'_, S> {
        let session = config.session.clone().unwrap_or_default();
        let key_log = config.key_log.clone();
        QUICConnect {
            state: QUICConnState::Connecting(Box::new(QUICStream {
                socket,
                udp_read_buffer: Writer::with_capacity(6000),
                tr_last_offset: 0,
                tls_read_buffer: Writer::with_capacity(8192),
                udp_write_buffer: Writer::with_capacity(1500),
                tls_write_buffer: Writer::with_capacity(16438),
                conn: QUICConnection::new(session, key_log, config.verify),
                wait_ack: HashMap::with_capacity(10),
                addr: remote_addr,
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
            #[cfg(feature = "aync")]
            timeout_reset: false,
        }
    }

    pub fn build_ack(&mut self, must: bool) -> Option<Buffer> {
        if !self.conn.recv_nums().need_ack() && !must { return None; }
        let seq = self.conn.seq;
        let mut ranges = self.conn.recv_nums_mut().ranges(seq);
        let max_range = ranges.pop()?;
        ranges.reverse();
        let mut ack_range = Vec::with_capacity(ranges.len());
        let mut pre_start = max_range.start;
        for range in ranges {
            ack_range.push(AckRange {
                gap: pre_start - range.end - 2,
                range: range.end - range.start,
            });
            pre_start = range.start;
        }
        let mut buffer = self.alloc_buffer();
        QUICFrame::Ack {
            largest_acknowledged: max_range.end,
            ack_delay: 200,
            ack_range_count: ack_range.len() as u64,
            first_ack_range: max_range.end - max_range.start,
            ack_range,
        }.write_to(&mut buffer).ok();
        Some(buffer)
    }

    pub fn read_next_packet(&mut self) -> QUICPacketRead<'_, S> {
        QUICPacketRead {
            socket: &mut self.socket,
            buffer: &mut self.udp_read_buffer,
            packet_offsets: &mut self.packet_offsets,
            current: self.current,
            #[cfg(feature = "aync")]
            timeout: &mut self.timeout,
            #[cfg(feature = "aync")]
            timeout_reset: false,
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
        let mut reader = Reader::from_slice(self.udp_read_buffer.slice(off.clone()));
        let mut packet = QUICPacket::from_reader(&mut reader)?;
        if packet.flag().packet_type() == PacketType::Initial {
            self.conn.make_initial_cipher(false)?;
        } else if packet.flag().packet_type() == PacketType::Retry {
            self.conn.token = packet.token().to_vec();
            self.conn.dcid = packet.sc_id().to_vec();
            return Err(QUICError::InitialRetry);
        }
        if self.conn.dcid != packet.sc_id().as_ref() && !packet.sc_id().as_ref().is_empty() {
            self.conn.dcid = packet.sc_id().to_vec();
        }
        let (bid, mut idle_buffer) = if self.idle_buffer.is_empty() {
            let bid = self.buffer_size;
            self.buffer_size = bid + 1;
            (bid, Writer::with_capacity(1500))
        } else { self.idle_buffer.remove(0) };
        debug_assert!(idle_buffer.is_empty());
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
            match frame {
                QUICFrame::Ack { largest_acknowledged, first_ack_range, ack_range: _ack_range, .. } => {
                    #[cfg(all(debug_assertions, feature = "log"))]
                    trace!("[QUIC ACK] largest={}; first={}; range={:?}",largest_acknowledged, first_ack_range, _ack_range);
                    let start = largest_acknowledged - first_ack_range;
                    for large in start..=largest_acknowledged {
                        self.conn.recv_nums_mut().remove(large);
                        if let Some(mut buffer) = self.wait_ack.remove(&large) {
                            buffer.reset();
                            self.idle_buffer.push((self.buffer_size.wrapping_add(1), buffer))
                        };
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

    pub(crate) fn handle_queues<F>(&mut self, off: Range<usize>, streams: &mut HashMap<u64, http3::H3StreamParam>, mut worker: F) -> HlsResult<()>
    where
        F: FnMut(&mut HashMap<u64, http3::H3StreamParam>, &u64, &mut Vec<Queue>, &HashMap<u64, (Writer, usize)>) -> HlsResult<Option<u64>>,
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
                        self.tls_read_buffer.check_move(queue.pos.len())?;
                        if self.tls_read_buffer.unfilled_len() < queue.pos.len() {
                            #[cfg(all(debug_assertions, feature = "log"))]
                            warn!("[QUIC] resize buffer = {}", self.tls_read_buffer.capacity()*2);
                            self.tls_read_buffer.resize(queue.pos.len() - self.tls_read_buffer.unfilled_len())?;
                        }
                        self.tr_last_offset += queue.pos.len();
                        self.tls_read_buffer.write_slice(buffer.slice(queue.pos))?;
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


    pub fn alloc_buffer(&mut self) -> Buffer {
        let mut buffer = self.idle_buffer.pop().map(|x| x.1).unwrap_or_else(||
            Buffer::with_capacity(1500));
        buffer.reset();
        buffer
    }

    pub fn write_packet(&mut self, buffer: Buffer, flag: QUICFlag) -> QUICPacketWrite<'_, S> {
        QUICPacketWrite {
            buffer: Some(buffer),
            flag,
            stream: self,
        }
    }

    pub fn make_message(&mut self, buffer: Buffer, flag: QUICFlag) -> Result<(), RlsError> {
        self.conn.make_message(buffer.filled(), &mut self.udp_write_buffer, flag)?;
        self.wait_ack.insert(self.conn.seq - 1, buffer);
        Ok(())
    }
}

#[cfg(all(feature = "aync", feature = "quic"))]
impl QUICStream<tokio::net::UdpSocket> {
    pub fn poll_send(&mut self, cx: &mut std::task::Context) -> std::task::Poll<HlsResult<()>> {
        match self.socket.poll_send_to(cx, self.udp_write_buffer.filled(), self.addr)? {
            std::task::Poll::Ready(ready) => {
                debug_assert_eq!(ready, self.udp_write_buffer.filled().len());
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl QUICStream<std::net::UdpSocket> {
    pub fn send(&mut self, buf: Buffer, flag: QUICFlag) -> HlsResult<()> {
        self.make_message(buf, flag)?;
        let len = self.socket.send_to(self.udp_write_buffer.filled(), self.addr)?;
        debug_assert_eq!(len, self.udp_write_buffer.filled().len());
        Ok(())
    }
}

impl<S> StreamHandle for QUICStream<S> {
    fn stream_param(&mut self) -> (&Writer, StreamParam<'_>) {
        (&self.tls_read_buffer, StreamParam {
            handshake_finish: &mut self.handshake_finish,
            encrypted_channel: &mut self.encrypted_channel,
            hello_retrying: &mut self.hello_retrying,
            write_buffer: &mut self.tls_write_buffer,
            conn: self.conn.tls_conn(),
        })
    }
}
