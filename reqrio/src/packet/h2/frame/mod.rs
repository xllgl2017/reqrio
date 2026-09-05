use crate::error::HlsResult;
pub use flag::FrameFlag;
use reqtls::{u24, BufferError, Reader, Writer};
pub use setting::H2Setting;
use std::fmt::Debug;
pub use typo::FrameType;

mod setting;
mod typo;
mod flag;

#[derive(Debug)]
enum EncodePayload<'a> {
    Setting(&'a Vec<H2Setting>),
    WindowUpdate(&'a u32),
    Data(&'a [u8]),
}


#[derive(Debug)]
pub struct H2EncodeFrame<'a> {
    frame_type: FrameType,
    frame_flag: FrameFlag,
    stream_identifier: &'a u32,
    stream_dependency: u32,
    weight: u8,
    payload: EncodePayload<'a>,
}

impl<'a> H2EncodeFrame<'a> {
    pub fn new_setting(settings: &'a Vec<H2Setting>) -> H2EncodeFrame<'a> {
        H2EncodeFrame {
            frame_type: FrameType::Settings,
            frame_flag: FrameFlag::default(),
            stream_identifier: &0,
            stream_dependency: 0,
            weight: 0,
            payload: EncodePayload::Setting(settings),
        }
    }

    pub fn new_window_update(window_size: &'a u32) -> H2EncodeFrame<'a> {
        H2EncodeFrame {
            frame_type: FrameType::WindowUpdate,
            frame_flag: FrameFlag::default(),
            stream_identifier: &0,
            stream_dependency: 0,
            weight: 0,
            payload: EncodePayload::WindowUpdate(window_size),
        }
    }

    pub fn new_header(body_len: usize, sid: &'a u32) -> H2EncodeFrame<'a> {
        let mut res = H2EncodeFrame {
            frame_type: FrameType::Headers,
            frame_flag: FrameFlag::EndHeader,
            stream_identifier: sid,
            stream_dependency: 0,
            weight: 0,
            payload: EncodePayload::Data(&[]),
        };
        if body_len == 0 { res.frame_flag |= FrameFlag::EndStream; }
        res
    }

    pub fn is_empty(&self) -> bool {
        match self.payload {
            EncodePayload::Setting(v) => v.is_empty(),
            EncodePayload::WindowUpdate(_) => false,
            EncodePayload::Data(v) => v.is_empty()
        }
    }

    pub fn len(&self) -> usize {
        match self.payload {
            EncodePayload::Setting(v) => v.len() * 6,
            EncodePayload::WindowUpdate(_) => 4,
            EncodePayload::Data(v) => if self.frame_flag.priority() { v.len() + 5 } else { v.len() }
        }
    }

    pub fn set_priority(&mut self, weight: u8) {
        self.weight = weight;
        self.frame_flag |= FrameFlag::Priority
    }

    pub fn write_to(self, writer: &mut Writer) -> Result<(), BufferError> {
        let len = self.len() as u24;
        writer.write_u24(len)?;
        writer.write_u8(self.frame_type.to_u8())?;
        writer.write_u8(self.frame_flag.as_u8())?;
        writer.write_ru32(self.stream_identifier)?;
        if self.frame_flag.priority() {
            writer.write_u32(self.stream_dependency | 2147483648)?;
            writer.write_u8(self.weight)?;
        }
        match self.payload {
            EncodePayload::Setting(settings) => {
                for setting in settings {
                    setting.write_to(writer)?;
                }
                Ok(())
            }
            EncodePayload::WindowUpdate(size) => writer.write_ru32(size),
            EncodePayload::Data(data) => writer.write_slice(data),
        }
    }
}


#[derive(Debug)]
pub struct H2Frame<'a> {
    len: u24,
    frame_type: FrameType,
    flag: FrameFlag,
    stream_identifier: u32,
    stream_dependency: u32,
    weight: u8,
    payload: &'a [u8],
}

impl<'a> H2Frame<'a> {
    pub fn none_frame() -> H2Frame<'a> {
        H2Frame {
            len: 0,
            frame_type: FrameType::Data,
            flag: FrameFlag::default(),
            stream_identifier: 0,
            stream_dependency: 0,
            weight: 0,
            payload: &[],
        }
    }

    pub fn from_reader(mut reader: Reader<'a>) -> HlsResult<H2Frame<'a>> {
        let len = reader.read_u24()?;
        let frame_type = FrameType::from_u8(reader.read_u8()?)?;
        let flag = FrameFlag::from_u8(reader.read_u8()?);
        let mut stream_identifier = reader.read_u32()?;
        stream_identifier &= !2147483648;
        if reader.unread_len() < len as usize { return Err("byte not enough".into()); }
        let mut frame = H2Frame {
            len,
            frame_type,
            flag,
            stream_identifier,
            stream_dependency: 0,
            weight: 0,
            payload: &[],
        };
        let mut pd_len = frame.len as usize;
        let padding_len = if frame.flag.padding() { reader.read_u8()? as usize } else { 0 };
        if padding_len > 0 {
            pd_len -= 1;
            pd_len -= padding_len;
        }
        if frame.flag.priority() {
            frame.stream_dependency = reader.read_u32()?;
            frame.weight = reader.read_u8()?;
            pd_len -= 5;
        }
        frame.payload = reader.read_slice(pd_len)?;
        reader.read_slice(padding_len)?;
        Ok(frame)
    }

    pub fn to_bytes(mut self) -> Vec<u8> {
        let mut res = (if self.flag.priority() { self.payload.len() + 5 } else { self.payload.len() } as u32).to_be_bytes()[1..].to_vec();
        res.push(self.frame_type.to_u8());
        let mut dep_bs = vec![];
        if self.flag.priority() {
            self.stream_dependency |= 2147483648;
            dep_bs = self.stream_dependency.to_be_bytes().to_vec();
            dep_bs.push(self.weight);
        }
        res.push(self.flag.into_inner());
        let stream_identifier = self.stream_identifier;
        res.extend(stream_identifier.to_be_bytes());
        res.extend(dep_bs);
        res.extend(self.payload);
        res
    }

    pub fn flag(&self) -> &FrameFlag {
        &self.flag
    }

    pub fn frame_type(&self) -> &FrameType {
        &self.frame_type
    }

    pub fn payload(&self) -> &[u8] { self.payload }

    pub fn set_payload(&mut self, payload: &'a [u8]) { self.payload = payload }

    pub fn is_empty(&self) -> bool { self.len == 0 }

    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn frame_id(&self) -> u32 {
        self.stream_identifier
    }

    pub fn set_frame_type(&mut self, frame_type: FrameType) {
        self.frame_type = frame_type;
    }

    pub fn set_flag(&mut self, flag: FrameFlag) {
        self.flag = flag;
    }

    pub fn set_weight(&mut self, weight: u8) {
        self.weight = weight;
    }

    pub fn add_flag(&mut self, flag: FrameFlag) {
        self.flag |= flag;
    }

    pub fn set_priority(&mut self, weight: u8) {
        self.weight = weight;
        self.add_flag(FrameFlag::Priority);
    }

    pub fn set_stream_identifier(&mut self, stream_identifier: u32) {
        self.stream_identifier = stream_identifier;
    }

    pub fn stream_identifier(&self) -> u32 {
        self.stream_identifier
    }

    pub fn is_end_frame(&self) -> bool {
        self.flag.end_stream() &&
            (self.frame_type == FrameType::Data || self.frame_type == FrameType::Headers)
    }
}

