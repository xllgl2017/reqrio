#[cfg(debug_assertions)]
use std::fmt::{Debug, Formatter};
use reqtls::{quic, Buf, Writer, BufferError, Reader};
use crate::HlsError;
use crate::pack::{QPackDecode, QPackType};

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct H3Setting {
    flag: u64,
    value: u64,
}
#[allow(non_upper_case_globals)]
impl H3Setting {
    pub const MaxTableCapacity: u64 = 0x01;
    pub const MaxFieldSectionSize: u64 = 0x06;
    pub const BlockedStreams: u64 = 0x07;
    pub const EnableDatagram: u64 = 0x33;

    pub fn new(flag: u64, value: u64) -> H3Setting {
        H3Setting { flag, value }
    }

    pub fn from_reader(reader: &mut Reader) -> Result<H3Setting, BufferError> {
        Ok(H3Setting {
            flag: quic::read_variant(reader)? as u64,
            value: quic::read_variant(reader)? as u64,
        })
    }

    pub fn len(&self) -> usize {
        quic::variant_len(self.flag) + quic::variant_len(self.value)
    }

    pub fn write_to(&self, writer: &mut Writer) -> Result<(), BufferError> {
        quic::write_variant(self.flag, writer)?;
        quic::write_variant(self.value, writer)
    }

    pub fn flag(&self) -> u64 {
        self.flag
    }

    pub fn value(&self) -> u64 {
        self.value
    }
}


#[repr(u64)]
pub enum H3Frame<'a> {
    Data(Buf<'a>),
    Settings(Vec<H3Setting>),
    PriorityUpdate {
        stream_id: u64,
        value: &'a str,
    },
    Headers(Buf<'a>),
    Reserved {
        typ: u64,
        payload: Buf<'a>,
    },
}
impl<'a> H3Frame<'a> {
    pub const DATA: u64 = 0x0;
    pub const HEADERS: u64 = 0x1;
    const SETTINGS: u64 = 0x4;
    pub const PRIORITY_UPDATE: u64 = 0xf0700;

    pub fn from_reader(reader: &mut Reader<'a>) -> Result<H3Frame<'a>, BufferError> {
        let typ = quic::read_variant(reader)?;
        let len = quic::read_variant(reader)? as usize;
        if reader.unread_len() < len { return Err(BufferError::Insufficient); }
        let mut reader = reader.read_reader(len)?;
        match typ {
            H3Frame::DATA => Ok(H3Frame::Data(Buf::new_ref(reader.read_slice(len)?))),
            H3Frame::HEADERS => Ok(H3Frame::Headers(Buf::new_ref(reader.read_slice(len)?))),
            H3Frame::SETTINGS => {
                let mut settings = vec![];
                while reader.unread_len() > 0 {
                    let setting = H3Setting::from_reader(&mut reader)?;
                    settings.push(setting);
                }
                Ok(H3Frame::Settings(settings))
            }
            H3Frame::PRIORITY_UPDATE => {
                let pos = reader.position();
                let stream_id = quic::read_variant(&mut reader)? as u64;
                let sid_len = reader.position() - pos;
                Ok(H3Frame::PriorityUpdate {
                    stream_id,
                    value: reader.read_str(len - sid_len)?,
                })
            }
            _ => Ok(H3Frame::Reserved {
                typ,
                payload: Buf::new_ref(reader.read_slice(len)?),
            })
        }
    }

    pub fn write_to(&self, writer: &mut Writer) -> Result<(), BufferError> {
        match self {
            H3Frame::Data(data) => {
                writer.write_u8(H3Frame::DATA as u8)?;
                quic::write_variant(data.len() as u64, writer)?;
                writer.write_slice(data.as_ref())
            }
            H3Frame::Settings(settings) => {
                writer.write_u8(H3Frame::SETTINGS as u8)?;
                let len = settings.iter().map(|x| x.len()).sum::<usize>();
                quic::write_variant(len as u64, writer)?;
                for setting in settings {
                    setting.write_to(writer)?;
                }
                Ok(())
            }
            H3Frame::PriorityUpdate { stream_id, value } => {
                quic::write_variant(H3Frame::PRIORITY_UPDATE, writer)?;
                let len = quic::variant_len(*stream_id) + value.len();
                quic::write_variant(len as u64, writer)?;
                quic::write_variant(*stream_id, writer)?;
                writer.write_slice(value.as_ref())
            }
            H3Frame::Headers(hdr) => {
                writer.write_u8(H3Frame::HEADERS as u8)?;
                quic::write_variant(hdr.len() as u64, writer)?;
                writer.write_slice(hdr.as_ref())
            }
            H3Frame::Reserved { typ, payload } => {
                quic::write_variant(*typ, writer)?;
                quic::write_variant(payload.len() as u64, writer)?;
                writer.write_slice(payload.as_ref())
            }
        }
    }

    pub fn encode(&self, offset: usize) -> Result<Vec<u8>, BufferError> {
        let mut res = vec![0; 100];
        let mut writer = Writer::from_ptr(res.as_mut_ptr(), res.len());
        if offset == 0 { writer.write_u8(0)?; }
        self.write_to(&mut writer)?;
        res.truncate(writer.len());
        Ok(res)
    }
}

#[cfg(debug_assertions)]
impl<'a> Debug for H3Frame<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            H3Frame::Data(pd) => write!(f, "Data({})", pd.len()),
            H3Frame::Settings(sts) => write!(f, "Settings({:?})", sts),
            H3Frame::PriorityUpdate { stream_id, value } => write!(f, "PriorityUpdate({}, {})", stream_id, value),
            H3Frame::Headers(hdrs) => write!(f, "Headers({})", hdrs.len()),
            H3Frame::Reserved { typ, payload } => write!(f, "Reserved({}, {})", typ, payload.len()),
        }
    }
}


#[repr(u64)]
#[derive(PartialEq)]
#[cfg_attr(debug_assertions, derive(Debug))]
pub enum H3Stream {
    Control = 0x00,
    QPackEncoder = 0x02,
    QPackDecoder = 0x03,
    Reserved(u64),
    BidirectionalStream,
}

impl From<usize> for H3Stream {
    fn from(val: usize) -> H3Stream {
        match val {
            0x00 => H3Stream::Control,
            0x02 => H3Stream::QPackEncoder,
            0x03 => H3Stream::QPackDecoder,
            _ => H3Stream::Reserved(val as u64),
        }
    }
}

impl H3Stream {
    pub fn handle_stream<'a>(&self, reader: &mut Reader<'a>, decoder: &mut QPackDecode) -> Result<H3Frame<'a>, HlsError> {
        match self {
            H3Stream::QPackEncoder => {
                let _item = decoder.decode_next(QPackType::StreamEncoder, 0, reader)?;
                // println!("{:?}", item);
                Ok(H3Frame::Reserved { typ: 0, payload: Buf::default() })
            }
            H3Stream::QPackDecoder => {
                decoder.decode_next(QPackType::StreamDecoder, 0, reader)?;
                Ok(H3Frame::Reserved { typ: 0, payload: Buf::default() })
            }
            H3Stream::BidirectionalStream | H3Stream::Control => Ok(H3Frame::from_reader(reader)?),
            H3Stream::Reserved(val) => {
                Ok(H3Frame::Reserved {
                    typ: *val,
                    payload: Buf::new_ref(reader.read_slice(reader.unread_len())?),
                })
            }
        }
    }
}