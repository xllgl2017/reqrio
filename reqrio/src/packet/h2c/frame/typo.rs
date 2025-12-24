use crate::error::HlsResult;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FrameType {
    Data = 0x00,
    Headers = 0x01,
    Priority = 0x02,
    RstStream = 0x03,
    Settings = 0x04,
    PushPromise = 0x05,
    Ping = 0x06,
    Goaway = 0x07,
    WindowUpdate = 0x08,
    Continuation = 0x09,
}


impl FrameType {
    pub fn from_u8(byte: u8) -> HlsResult<FrameType> {
        match byte {
            0x00 => Ok(FrameType::Data),
            0x01 => Ok(FrameType::Headers),
            0x02 => Ok(FrameType::Priority),
            0x03 => Ok(FrameType::RstStream),
            0x04 => Ok(FrameType::Settings),
            0x05 => Ok(FrameType::PushPromise),
            0x06 => Ok(FrameType::Ping),
            0x07 => Ok(FrameType::Goaway),
            0x08 => Ok(FrameType::WindowUpdate),
            0x09 => Ok(FrameType::Continuation),
            _ => Err(format!("Unknown frame type: {}", byte).into()),
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

