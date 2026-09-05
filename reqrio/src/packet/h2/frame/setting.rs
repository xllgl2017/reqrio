use crate::error::HlsResult;
use std::fmt::{Debug, Formatter};
use reqtls::{BufferError, Reader, Writer};

#[derive(PartialEq, Copy, Clone)]
#[repr(u16)]
pub enum H2Setting {
    HeaderTableSize(u32) = 0x1,
    EnablePush(u32) = 0x2,
    MaxConcurrentStreams(u32) = 0x3,
    InitialWindowSize(u32) = 0x4,
    MaxFrameSize(u32) = 0x5,
    MaxHeaderListSize(u32) = 0x6,
    Reserved { flag: u16, value: u32 },
}

impl H2Setting {
    pub fn from_reader(reader: &mut Reader<'_>) -> HlsResult<H2Setting> {
        let flag = reader.read_u16()?;
        let value = reader.read_u32()?;
        Ok(match flag {
            0x1 => H2Setting::HeaderTableSize(value),
            0x2 => H2Setting::EnablePush(value),
            0x3 => H2Setting::MaxConcurrentStreams(value),
            0x4 => H2Setting::InitialWindowSize(value),
            0x5 => H2Setting::MaxFrameSize(value),
            0x6 => H2Setting::MaxHeaderListSize(value),
            _ => H2Setting::Reserved { flag, value },
        })
    }

    pub fn write_to(&self, writer: &mut Writer) -> Result<(), BufferError> {
        let (flag, value) = match self {
            H2Setting::HeaderTableSize(v) => (0x1, v),
            H2Setting::EnablePush(v) => (0x2, v),
            H2Setting::MaxConcurrentStreams(v) => (0x3, v),
            H2Setting::InitialWindowSize(v) => (0x4, v),
            H2Setting::MaxFrameSize(v) => (0x5, v),
            H2Setting::MaxHeaderListSize(v) => (0x6, v),
            H2Setting::Reserved { flag, value } => (*flag, value),
        };
        writer.write_u16(flag)?;
        writer.write_ru32(value)
    }

    pub fn value(&self) -> &u32 {
        match self {
            H2Setting::HeaderTableSize(v) => v,
            H2Setting::EnablePush(v) => v,
            H2Setting::MaxConcurrentStreams(v) => v,
            H2Setting::InitialWindowSize(v) => v,
            H2Setting::MaxFrameSize(v) => v,
            H2Setting::MaxHeaderListSize(v) => v,
            H2Setting::Reserved { value, .. } => value
        }
    }
}

impl Debug for H2Setting {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            H2Setting::HeaderTableSize(v) => write!(f, "HeaderTableSize({})", v),
            H2Setting::EnablePush(v) => write!(f, "EnablePush({})", v),
            H2Setting::MaxConcurrentStreams(v) => write!(f, "MaxConcurrentStreams({})", v),
            H2Setting::InitialWindowSize(v) => write!(f, "InitialWindowSize({})", v),
            H2Setting::MaxFrameSize(v) => write!(f, "MaxFrameSize({})", v),
            H2Setting::MaxHeaderListSize(v) => write!(f, "MaxHeaderListSize({})", v),
            H2Setting::Reserved { flag, value } => write!(f, "Reserved{{flag: {}; value: {}}}", flag, value),
        }
    }
}
