use crate::error::RlsResult;
use super::message::{Message, Payload};
use super::version::Version;

#[derive(Debug, Copy, Clone)]
pub enum RecordType {
    CipherSpec = 0x14,
    Alert = 0x15,
    HandShake = 0x16,
    ApplicationData = 0x17,

}

impl RecordType {
    pub fn from_byte(byte: u8) -> Option<RecordType> {
        match byte {
            0x14 => Some(RecordType::CipherSpec),
            0x15 => Some(RecordType::Alert),
            0x16 => Some(RecordType::HandShake),
            0x17 => Some(RecordType::ApplicationData),
            _ => None
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}


#[derive(Debug)]
pub struct RecordLayer<'a> {
    pub context_type: RecordType,
    pub version: Version,
    pub len: u16,
    pub message: Message<'a>,
}

impl<'a> RecordLayer<'a> {
    pub fn new() -> RecordLayer<'a> {
        RecordLayer {
            context_type: RecordType::CipherSpec,
            version: Version::new(0),
            len: 0,
            message: Message::CipherSpec,
        }
    }
    pub fn from_bytes(bytes: &mut [u8], payload: bool) -> RlsResult<RecordLayer<'_>> {
        let mut res = RecordLayer::new();
        res.context_type = RecordType::from_byte(bytes[0]).ok_or("LayerType Unknown")?;
        res.version = Version::new(u16::from_be_bytes([bytes[1], bytes[2]]));
        res.len = u16::from_be_bytes([bytes[3], bytes[4]]);
        if bytes.len() - 5 != res.len as usize { return Err("record body not enough".into()); }
        res.message = match res.context_type {
            RecordType::HandShake => Message::from_bytes(&mut bytes[5..], payload)?,
            RecordType::ApplicationData => Message::Payload(Payload::from_slice(&mut bytes[5..])),
            RecordType::Alert=>if payload {
                Message::Payload(Payload::from_slice(&mut bytes[5..]))
            }else {
                Message::CipherSpec
            }
            _ => Message::CipherSpec,
        };
        Ok(res)
    }

    pub fn handshake_bytes(&self) -> Vec<u8> {
        let mut res = self.head_bytes();
        let msg = self.message.as_bytes();
        res.extend((msg.len() as u16).to_be_bytes());
        res.extend(msg);
        res
    }

    pub fn head_bytes(&self) -> Vec<u8> {
        let mut res = vec![self.context_type.as_u8()];
        res.extend(self.version.as_bytes());
        res
    }
}