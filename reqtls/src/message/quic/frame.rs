use crate::quic::{self, QUICError};
use crate::{Buf, BufferError, Reader, Writer};
use std::ops::Range;

#[repr(u16)]
#[allow(non_camel_case_types)]
#[derive(Debug)]
pub enum TrpErrKind {
    NO_ERROR = 0x00,
    INTERNAL_ERROR = 0x01,
    CONNECTION_REFUSED = 0x02,
    FLOW_CONTROL_ERROR = 0x03,
    STREAM_LIMIT_ERROR = 0x04,
    STREAM_STATE_ERROR = 0x05,
    FINAL_SIZE_ERROR = 0x06,
    FRAME_ENCODING_ERROR = 0x07,
    TRANSPORT_PARAMETER_ERROR = 0x08,
    CONNECTION_ID_LIMIT_ERROR = 0x09,
    PROTOCOL_VIOLATION = 0x0a,
    INVALID_TOKEN = 0x0b,
    APPLICATION_ERROR = 0x0c,
    CRYPTO_BUFFER_EXCEEDED = 0x0d,
    KEY_UPDATE_ERROR = 0x0e,
    AEAD_LIMIT_REACHED = 0x0f,
    NO_VIABLE_PATH = 0x10,
    //0x0100 - 0x01ff
    CRYPTO_ERROR(u16),
}

impl From<u16> for TrpErrKind {
    fn from(value: u16) -> Self {
        match value {
            0x00 => TrpErrKind::NO_ERROR,
            0x01 => TrpErrKind::INTERNAL_ERROR,
            0x02 => TrpErrKind::CONNECTION_REFUSED,
            0x03 => TrpErrKind::FLOW_CONTROL_ERROR,
            0x04 => TrpErrKind::STREAM_LIMIT_ERROR,
            0x05 => TrpErrKind::STREAM_STATE_ERROR,
            0x06 => TrpErrKind::FINAL_SIZE_ERROR,
            0x07 => TrpErrKind::FRAME_ENCODING_ERROR,
            0x08 => TrpErrKind::TRANSPORT_PARAMETER_ERROR,
            0x09 => TrpErrKind::CONNECTION_ID_LIMIT_ERROR,
            0x0a => TrpErrKind::PROTOCOL_VIOLATION,
            0x0b => TrpErrKind::INVALID_TOKEN,
            0x0c => TrpErrKind::APPLICATION_ERROR,
            0x0d => TrpErrKind::CRYPTO_BUFFER_EXCEEDED,
            0x0e => TrpErrKind::KEY_UPDATE_ERROR,
            0x0f => TrpErrKind::AEAD_LIMIT_REACHED,
            0x10 => TrpErrKind::NO_VIABLE_PATH,
            _ => TrpErrKind::CRYPTO_ERROR(value),
        }
    }
}

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct QUICFrameFlag {
    fin: bool,
    len: bool,
    offset: bool,
}

impl QUICFrameFlag {
    pub const fn new(offset: usize) -> QUICFrameFlag {
        QUICFrameFlag {
            fin: false,
            len: true,
            offset: offset != 0,
        }
    }

    pub const fn with_fin(mut self, fin: bool) -> Self {
        self.fin = fin;
        self
    }

    pub const fn fin(&self) -> bool { self.fin }

    pub const fn offset(&self) -> bool { self.offset }

    pub const fn encode(&self) -> u64 {
        let mut v = 8;
        if self.fin {
            v |= 0b1;
        }
        if self.len {
            v |= 0b10;
        }
        if self.offset {
            v |= 0b100;
        }
        v
    }
}

impl From<u64> for QUICFrameFlag {
    fn from(value: u64) -> Self {
        QUICFrameFlag {
            fin: value & 1 == 1,
            len: value & 0b10 == 0b10,
            offset: value & 0b100 == 0b100,
        }
    }
}

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct AckRange {
    pub gap: u64,
    pub range: u64,
}

impl AckRange {
    pub fn new(gap: u64, range: u64) -> Self {
        AckRange { gap, range }
    }

    pub fn is_empty(&self) -> bool { false }

    pub fn len(&self) -> usize {
        quic::variant_len(self.gap) + quic::variant_len(self.range)
    }

    pub fn write_to(&self, writer: &mut Writer) -> Result<(), BufferError> {
        quic::write_variant(self.gap, writer)?;
        quic::write_variant(self.range, writer)
    }
}

#[repr(u64)]
#[derive(Debug)]
#[allow(dead_code)]
pub enum QUICFrameType {
    Padding = 0x00,
    Ping = 0x01,
    Ack = 0x02,
    AckEcn = 0x03,
    ResetStream = 0x04,
    StopSending = 0x05,
    Crypto = 0x06,
    NewToken = 0x07,
    Stream(u64),
    MaxData = 0x10,
    MaxStreamData = 0x11,
    MaxStreamsBidi = 0x12,
    MaxStreamsUni = 0x13,
    DataBlocked = 0x14,
    StreamDataBlocked = 0x15,
    StreamsBlockedBidi = 0x16,
    StreamsBlockedUnu = 0x17,
    NewConnectionId = 0x18,
    RetireConnectionId = 0x19,
    PathChallenge = 0x1a,
    PathResponse = 0x1b,
    ConnectionCloseTrp = 0x1c,
    ConnectionCloseApp = 0x1d,
    HandshakeDone = 0x1e,
}

impl From<u64> for QUICFrameType {
    fn from(typ: u64) -> Self {
        match typ {
            0x00 => QUICFrameType::Padding,
            0x01 => QUICFrameType::Ping,
            0x02 => QUICFrameType::Ack,
            0x5 => QUICFrameType::StopSending,
            0x06 => QUICFrameType::Crypto,
            0x07 => QUICFrameType::NewToken,
            0x08..=0x10 => QUICFrameType::Stream(typ),
            0x11 => QUICFrameType::MaxStreamData,
            0x12 => QUICFrameType::MaxStreamsBidi,
            0x18 => QUICFrameType::NewConnectionId,
            0x1c => QUICFrameType::ConnectionCloseTrp,
            0x1e => QUICFrameType::HandshakeDone,
            _ => {
                println!("{:x?}", typ);
                unreachable!()
            }
        }
    }
}

#[repr(u64)]
#[cfg_attr(debug_assertions, derive(Debug))]
pub enum QUICFrame<'a> {
    Padding(usize),
    Ping,
    Ack {
        largest_acknowledged: u64,
        ack_delay: u64,
        ack_range_count: u64,
        first_ack_range: u64,
        ack_range: Vec<AckRange>,
    },
    AckEcn,
    ResetStream,
    StopSending {
        sid: u64,
        error_code: u64,
    },
    Crypto {
        offset: usize,
        value: Buf<'a>,
        buf_pos: Range<usize>,
    },
    NewToken(Buf<'a>),
    Stream {
        flag: QUICFrameFlag,
        sid: u64,
        offset: usize,
        payload: Buf<'a>,
        buf_pos: Range<usize>,
    },
    MaxData,
    MaxStreamData {
        sid: u64,
        data: u64,
    },
    MaxStreamsBidi(u64),
    MaxStreamsUni,
    DataBlocked,
    StreamDataBlocked,
    StreamsBlockedBidi,
    StreamsBlockedUnu,
    NewConnectionId {
        seq: u64,
        retire: u64,
        cid: Buf<'a>,
        reset_token: Buf<'a>,
    },
    RetireConnectionId,
    PathChallenge,
    PathResponse,
    ConnectionCloseTrp {
        err_code: TrpErrKind,
        frame_typ: u64,
        reason: &'a str,
    },
    ConnectionCloseApp,
    HandshakeDone,
}

impl<'a> QUICFrame<'a> {
    pub fn from_reader(reader: &mut Reader<'a>) -> Result<QUICFrame<'a>, QUICError> {
        let typ: QUICFrameType = quic::read_variant(reader)?.into();
        match typ {
            QUICFrameType::Padding => {
                let len = reader.find(|&x| x != 0).unwrap_or(reader.unread_len());
                let value = Buf::new_ref(reader.read_slice(len).unwrap());
                Ok(QUICFrame::Padding(value.len()))
            }
            QUICFrameType::Ping => Ok(QUICFrame::Ping),
            QUICFrameType::Ack => {
                let largest_acknowledged = quic::read_variant(reader)?;
                let ack_delay = quic::read_variant(reader)?;
                let ack_range_count = quic::read_variant(reader)?;
                let first_ack_range = quic::read_variant(reader)?;
                let mut ack_range = Vec::with_capacity(ack_range_count as usize);
                for _ in 0..ack_range_count {
                    ack_range.push(AckRange {
                        gap: quic::read_variant(reader)?,
                        range: quic::read_variant(reader)?,
                    })
                }
                Ok(QUICFrame::Ack {
                    largest_acknowledged,
                    ack_delay,
                    ack_range_count,
                    first_ack_range,
                    ack_range,
                })
            }
            QUICFrameType::StopSending => Ok(QUICFrame::StopSending {
                sid: quic::read_variant(reader)?,
                error_code: quic::read_variant(reader)?,
            }),
            QUICFrameType::Crypto => {
                let offset = quic::read_variant(reader)? as usize;
                let len = quic::read_variant(reader)? as usize;
                let pos = reader.position()..reader.position() + len;
                Ok(QUICFrame::Crypto {
                    offset,
                    value: Buf::new_ref(reader.read_slice(len)?),
                    buf_pos: pos,
                })
            }
            QUICFrameType::NewToken => {
                let len = quic::read_variant(reader)? as usize;
                Ok(QUICFrame::NewToken(Buf::new_ref(reader.read_slice(len)?)))
            }
            QUICFrameType::Stream(typ) => {
                let flag: QUICFrameFlag = typ.into();
                let sid = quic::read_variant(reader)?;
                let offset = if flag.offset { quic::read_variant(reader)? as usize } else { 0 };
                let len = if flag.len { quic::read_variant(reader)? as usize } else { reader.unread_len() };
                let pos = reader.position()..reader.position() + len;
                Ok(QUICFrame::Stream {
                    flag,
                    sid,
                    // len,
                    offset,
                    payload: Buf::new_ref(reader.read_slice(len)?),
                    buf_pos: pos,
                })
            }
            QUICFrameType::MaxStreamsBidi => Ok(QUICFrame::MaxStreamsBidi(quic::read_variant(reader)?)),
            QUICFrameType::NewConnectionId => {
                let seq = quic::read_variant(reader)?;
                let retire = quic::read_variant(reader)?;
                let len = reader.read_u8()? as usize;
                Ok(QUICFrame::NewConnectionId {
                    seq,
                    retire,
                    cid: Buf::new_ref(reader.read_slice(len)?),
                    reset_token: Buf::new_ref(reader.read_slice(16)?),
                })
            }
            QUICFrameType::ConnectionCloseTrp => {
                let err_code = quic::read_variant(reader)? as u16;
                let frame_typ = quic::read_variant(reader)?;
                let reason_len = quic::read_variant(reader)? as usize;
                Ok(QUICFrame::ConnectionCloseTrp {
                    err_code: err_code.into(),
                    frame_typ,
                    reason: reader.read_str(reason_len)?,
                })
            }
            QUICFrameType::HandshakeDone => Ok(QUICFrame::HandshakeDone),
            QUICFrameType::MaxStreamData => {
                println!("{:?}", &reader.inner()[reader.position()..]);
                let sid = quic::read_variant(reader)?;
                Ok(QUICFrame::MaxStreamData {
                    sid: sid,
                    data: quic::read_variant(reader)?,
                })
            }
            _ => {
                unimplemented!("{:?}", typ)
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn len(&self) -> usize {
        match self {
            QUICFrame::Padding(size) => *size,
            QUICFrame::Ping => 1,
            QUICFrame::Crypto { offset, value, .. } => {
                let offset_size = quic::variant_len(*offset as u64);
                let value_size = quic::variant_len(value.len() as u64);
                1 + offset_size + value_size + value.len()
            }
            QUICFrame::Ack {
                largest_acknowledged,
                ack_delay,
                ack_range_count,
                first_ack_range,
                ack_range
            } => {
                1 + quic::variant_len(*largest_acknowledged) +
                    quic::variant_len(*ack_delay) +
                    quic::variant_len(*ack_range_count) +
                    quic::variant_len(*first_ack_range) +
                    ack_range.iter().map(|x| x.len()).sum::<usize>()
            }
            QUICFrame::Stream { flag, sid, offset, payload, .. } => {
                let mut res = 1 + quic::variant_len(*sid);
                if flag.offset {
                    res += quic::variant_len(*offset as u64);
                }
                if flag.len {
                    res += quic::variant_len(payload.len() as u64);
                }
                res + payload.len()
            }
            _ => todo!()
        }
    }

    pub fn write_to(&self, writer: &mut Writer) -> Result<(), BufferError> {
        match self {
            QUICFrame::Padding(size) => writer.write_slice(&vec![0; *size]),
            QUICFrame::Ping => writer.write_u8(0x01),
            QUICFrame::Crypto { offset, value, .. } => {
                writer.write_u8(0x06)?;
                quic::write_variant(*offset as u64, writer)?;
                quic::write_variant(value.len() as u64, writer)?;
                writer.write_slice(value.as_ref())
            }
            QUICFrame::Ack {
                largest_acknowledged,
                ack_delay,
                ack_range_count,
                first_ack_range,
                ack_range
            } => {
                writer.write_u8(0x02)?;
                quic::write_variant(*largest_acknowledged, writer)?;
                quic::write_variant(*ack_delay, writer)?;
                quic::write_variant(*ack_range_count, writer)?;
                quic::write_variant(*first_ack_range, writer)?;
                for ack in ack_range {
                    ack.write_to(writer)?;
                }
                Ok(())
            }
            QUICFrame::Stream {
                flag,
                sid,
                offset,
                payload,
                ..
            } => {
                quic::write_variant(flag.encode(), writer)?;
                quic::write_variant(*sid, writer)?;
                if flag.offset {
                    quic::write_variant(*offset as u64, writer)?;
                }
                if flag.len {
                    quic::write_variant(payload.len() as u64, writer)?;
                }
                writer.write_slice(payload.as_ref())
            }
            _ => todo!()
        }
    }

    pub fn need_ack(&self) -> bool {
        matches!(self,
            QUICFrame::Crypto{..}|
            QUICFrame::Stream {..}|
            QUICFrame::NewToken(_)|
            QUICFrame::HandshakeDone|
            QUICFrame::StopSending {..}|
            QUICFrame::MaxStreamsBidi(_)|
            QUICFrame::MaxStreamData {..},
        )
    }
}