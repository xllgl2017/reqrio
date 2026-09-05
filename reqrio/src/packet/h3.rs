use std::fmt::{Debug, Formatter};
use reqtls::{quic, Buf, Writer, BufferError, Reader};
use crate::HlsError;
use crate::pack::{QPackDecode, QPackType};

#[derive(Debug)]
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
        quic::variant_len(self.flag as usize) + quic::variant_len(self.value as usize)
    }

    pub fn write_to(&self, writer: &mut Writer) -> Result<(), BufferError> {
        quic::write_variant(self.flag as usize, writer)?;
        quic::write_variant(self.value as usize, writer)
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
    const DATA: u64 = 0x0;
    const HEADERS: u64 = 0x1;
    const SETTINGS: u64 = 0x4;
    const PRIORITY_UPDATE: u64 = 0xf0700;

    pub fn from_reader(reader: &mut Reader<'a>) -> Result<H3Frame<'a>, BufferError> {
        let typ = quic::read_variant(reader)? as u64;
        let len = quic::read_variant(reader)?;
        if reader.unread_len() < len { return Err(BufferError::Insufficient); }
        let mut reader = reader.read_reader(len)?;
        match typ {
            H3Frame::DATA => Ok(H3Frame::Data(Buf::Ref(reader.read_slice(len)?))),
            H3Frame::HEADERS => Ok(H3Frame::Headers(Buf::Ref(reader.read_slice(len)?))),
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
                payload: Buf::Ref(reader.read_slice(len)?),
            })
        }
    }

    pub fn write_to(&self, writer: &mut Writer) -> Result<(), BufferError> {
        match self {
            H3Frame::Data(data) => {
                quic::write_variant(H3Frame::DATA as usize, writer)?;
                quic::write_variant(data.len(), writer)?;
                writer.write_slice(data.as_ref())
            }
            H3Frame::Settings(settings) => {
                quic::write_variant(H3Frame::SETTINGS as usize, writer)?;
                let len = settings.iter().map(|x| x.len()).sum::<usize>();
                quic::write_variant(len, writer)?;
                for setting in settings {
                    setting.write_to(writer)?;
                }
                Ok(())
            }
            H3Frame::PriorityUpdate { stream_id, value } => {
                quic::write_variant(H3Frame::PRIORITY_UPDATE as usize, writer)?;
                let len = quic::variant_len(*stream_id as usize) + value.len();
                quic::write_variant(len, writer)?;
                quic::write_variant(*stream_id as usize, writer)?;
                writer.write_slice(value.as_ref())
            }
            H3Frame::Headers(hdr) => {
                quic::write_variant(H3Frame::HEADERS as usize, writer)?;
                quic::write_variant(hdr.len(), writer)?;
                writer.write_slice(hdr.as_ref())
            }
            H3Frame::Reserved { typ, payload } => {
                quic::write_variant(*typ as usize, writer)?;
                quic::write_variant(payload.len(), writer)?;
                writer.write_slice(payload.as_ref())
            }
        }
    }

    pub fn encode(&self, offset: usize) -> Result<Vec<u8>, BufferError> {
        let mut res = vec![0; 100];
        let mut writer = Writer::from_ptr(res.as_mut_slice());
        if offset == 0 { writer.write_u8(0)?; }
        self.write_to(&mut writer)?;
        res.truncate(writer.len());
        Ok(res)
    }
}

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
#[derive(Debug, PartialEq)]
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
                let item = decoder.decode_next(QPackType::StreamEncoder, &0, reader)?;
                println!("{:?}", item);
                Ok(H3Frame::Reserved { typ: 0, payload: Buf::Ref(&[]) })
            }
            H3Stream::QPackDecoder => {
                decoder.decode_next(QPackType::StreamDecoder, &0, reader)?;
                Ok(H3Frame::Reserved { typ: 0, payload: Buf::Ref(&[]) })
            }
            H3Stream::BidirectionalStream | H3Stream::Control => Ok(H3Frame::from_reader(reader)?),
            H3Stream::Reserved(val) => {
                Ok(H3Frame::Reserved {
                    typ: *val,
                    payload: Buf::Ref(reader.read_slice(reader.unread_len())?),
                })
            }
        }
    }
}