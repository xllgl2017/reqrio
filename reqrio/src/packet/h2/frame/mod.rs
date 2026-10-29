use crate::error::HlsResult;
pub use flag::H2FrameFlag;
use reqtls::{Buf, BufferError, Reader, Writer, u24};
pub use setting::H2Setting;
pub use typo::H2FrameType;


mod setting;
mod typo;
mod flag;

#[cfg_attr(debug_assertions, derive(Debug))]
pub enum H2PayloadValue<'a> {
    Data(Buf<'a>),
    U32(u32),
    Settings(Vec<H2Setting>),
}


#[cfg_attr(debug_assertions, derive(Debug))]
pub struct H2Payload<'a> {
    pub(crate) padding: usize,
    pub(crate) stream_dependency: u32,
    pub(crate) weight: u8,
    pub(crate) value: H2PayloadValue<'a>,
}

impl<'a> Default for H2Payload<'a> {
    fn default() -> H2Payload<'a> {
        H2Payload {
            padding: 0,
            stream_dependency: 0,
            weight: 0,
            value: H2PayloadValue::Data(Buf::new_ref(&[])),
        }
    }
}

impl<'a> H2Payload<'a> {
    pub fn from_reader(typ: H2FrameType, flag: H2FrameFlag, mut reader: Reader) -> Result<H2Payload, BufferError> {
        let mut padding_len = 0;
        if flag.padding() {
            padding_len = reader.read_u8()? as usize;
            // reader.read_slice(padding_len)?;
        }
        let mut stream_dependency = 0;
        let mut weight = 0;
        if flag.priority() {
            stream_dependency = reader.read_u32()? & !2147483648;
            weight = reader.read_u8()?;
        }
        Ok(H2Payload {
            padding: padding_len,
            stream_dependency,
            weight,
            value: match typ {
                H2FrameType::RstStream |
                H2FrameType::WindowUpdate |
                H2FrameType::Goaway => H2PayloadValue::U32(reader.read_u32()?),
                H2FrameType::Headers |
                H2FrameType::Data => {
                    let data = reader.read_slice(reader.unread_len() - padding_len)?;
                    reader.read_slice(padding_len)?;
                    H2PayloadValue::Data(Buf::new_ref(data))
                }
                H2FrameType::Settings => {
                    let mut res = Vec::with_capacity(8);
                    while let Ok(setting) = H2Setting::from_reader(&mut reader) {
                        res.push(setting);
                    }
                    H2PayloadValue::Settings(res)
                }
                _ => unreachable!("{}", typ)
            },
        })
    }

    pub fn write_to(&self, flag: H2FrameFlag, writer: &mut Writer) -> Result<(), BufferError> {
        if flag.padding() {
            writer.write_u8(self.padding as u8)?;
            writer.write_slice(&vec![0; self.padding])?;
        }
        if flag.priority() {
            writer.write_u32(self.stream_dependency | 2147483648)?;
            writer.write_u8(self.weight)?;
        }
        match self.value {
            H2PayloadValue::Data(ref buf) => writer.write_slice(buf.as_slice()),
            H2PayloadValue::U32(val) => writer.write_u32(val),
            H2PayloadValue::Settings(ref settings) => {
                for setting in settings.iter() {
                    setting.write_to(writer)?;
                }
                Ok(())
            }
        }
    }
}


#[cfg_attr(debug_assertions, derive(Debug))]
pub struct H2Frame<'a> {
    #[allow(dead_code)]
    len: u24,
    typ: H2FrameType,
    flag: H2FrameFlag,
    stream_identifier: u32,
    pub(crate) payload: H2Payload<'a>,
}

impl<'a> H2Frame<'a> {
    pub fn new(sid: u32, frame_type: H2FrameType) -> H2Frame<'a> {
        H2Frame {
            len: 0,
            typ: frame_type,
            flag: H2FrameFlag::new(0),
            stream_identifier: sid,
            payload: H2Payload::default(),
        }
    }

    pub fn new_setting(settings: Vec<H2Setting>) -> H2Frame<'a> {
        let mut frame = H2Frame::new(0, H2FrameType::Settings);
        frame.payload.value = H2PayloadValue::Settings(settings);
        frame
    }

    pub fn new_window_update(window_size: u32) -> H2Frame<'a> {
        let mut frame = H2Frame::new(0, H2FrameType::WindowUpdate);
        frame.payload.value = H2PayloadValue::U32(window_size);
        frame
    }

    pub fn from_reader(mut reader: Reader<'a>) -> HlsResult<H2Frame<'a>> {
        let len = reader.read_u24()?;
        let frame_type = H2FrameType::new(reader.read_u8()?);
        let flag = H2FrameFlag::new(reader.read_u8()?);
        Ok(H2Frame {
            len,
            typ: frame_type,
            flag,
            stream_identifier: reader.read_u32()?,
            payload: H2Payload::from_reader(frame_type, flag, reader.read_reader(len as usize)?)?,
        })
    }

    pub fn write_to(&self, writer: &mut Writer) -> Result<(), BufferError> {
        let start = writer.end();
        writer.write_u24(0)?;
        writer.write_u8(self.typ.into_inner())?;
        writer.write_u8(self.flag.inner())?;
        writer.write_u32(self.stream_identifier)?;
        self.payload.write_to(self.flag, writer)?;
        writer.write_u24_in(start, (writer.end() - start - 9) as u24)?;
        Ok(())
    }

    pub fn flag(&self) -> H2FrameFlag { self.flag }

    pub fn frame_type(&self) -> H2FrameType { self.typ }

    pub fn payload(&self) -> &H2Payload<'a> { &self.payload }

    pub fn set_payload(&mut self, payload: &'a [u8]) { self.payload.value = H2PayloadValue::Data(Buf::new_ref(payload)); }

    pub fn set_frame_type(&mut self, frame_type: H2FrameType) {
        self.typ = frame_type;
    }

    pub fn set_flag(&mut self, flag: H2FrameFlag) {
        self.flag = flag;
    }

    pub fn set_weight(&mut self, weight: u8) {
        self.payload.weight = weight;
    }

    pub fn add_flag(&mut self, flag: H2FrameFlag) {
        self.flag |= flag;
    }

    pub fn set_priority(&mut self, weight: u8) {
        self.payload.weight = weight;
        self.add_flag(H2FrameFlag::Priority);
    }

    pub fn set_stream_identifier(&mut self, stream_identifier: u32) {
        self.stream_identifier = stream_identifier;
    }

    pub fn stream_identifier(&self) -> u32 {
        self.stream_identifier
    }

    pub fn is_end_frame(&self) -> bool {
        self.flag.end_stream() && (self.typ == H2FrameType::Data || self.typ == H2FrameType::Headers)
    }
}

