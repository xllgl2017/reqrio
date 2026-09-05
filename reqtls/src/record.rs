use super::version::Version;
use crate::buffer::Buf;
use crate::error::RlsResult;
use crate::suite::KeyExchangeAlg;
use crate::{HandShakeError, Message, MessageParsed, Reader, Writer, ALPN};

#[derive(Debug, Copy, Clone)]
pub enum RecordType {
    CipherSpec = 0x14,
    Alert = 0x15,
    HandShake = 0x16,
    ApplicationData = 0x17,

}

impl RecordType {
    pub fn from_byte(byte: u8) -> Result<RecordType, HandShakeError> {
        match byte {
            0x14 => Ok(RecordType::CipherSpec),
            0x15 => Ok(RecordType::Alert),
            0x16 => Ok(RecordType::HandShake),
            0x17 => Ok(RecordType::ApplicationData),
            _ => Err(HandShakeError::UnknownRecord(byte))
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}


#[derive(Debug)]
pub struct RecordLayer<'a> {
    pub content_type: RecordType,
    pub version: Version,
    pub len: u16,
    pub messages: Vec<Message<'a>>,
}

impl<'a> RecordLayer<'a> {
    pub fn new(rt: RecordType, version: Version) -> RecordLayer<'a> {
        RecordLayer {
            content_type: rt,
            version,
            len: 0,
            messages: vec![],
        }
    }

    pub fn handshake(version: Version) -> RecordLayer<'a> {
        RecordLayer::new(RecordType::HandShake, version)
    }

    pub fn from_bytes(bytes: &'a [u8], alg: KeyExchangeAlg, encrypted: bool) -> RlsResult<RecordLayer<'a>> {
        let mut reader = Reader::from_slice(bytes);
        let content_type = RecordType::from_byte(reader.read_u8()?)?;
        let version = Version::new(reader.read_u16()?);
        let len = reader.read_u16()?;
        let mut msg_readers = reader.read_reader(len as usize)?;
        let mut messages = vec![];
        while msg_readers.unread_len() > 0 {
            let message = match encrypted {
                true => Message {
                    encoded: Buf::Ref(msg_readers.read_slice(msg_readers.unread_len())?),
                    parsed: MessageParsed::Payload(Buf::Ref(&[])),
                },
                false => Message::from_reader(&mut msg_readers, &content_type, alg, &version)?
            };
            messages.push(message);
        }
        Ok(RecordLayer {
            content_type,
            version,
            len,
            messages,
        })
    }

    pub fn write_to(self, writer: &mut Writer, kea: KeyExchangeAlg) -> RlsResult<()> {
        let offset = writer.offset().end;
        let sni = self.messages[0].parsed.client().and_then(|x| x.host_name()).unwrap_or("").to_string();
        let h2 = self.messages[0].parsed.client().map(|x| x.alps().map(|x| x.values().iter().any(|x| x == &ALPN::Http20)).unwrap_or(false)).unwrap_or(false);
        writer.write_u8(self.content_type as u8)?;
        writer.write_u16(self.version.into_inner())?;
        let len = self.messages.iter().map(|x| x.parsed.len(kea)).sum::<usize>();
        writer.write_u16(len as u16)?;
        for message in self.messages {
            message.parsed.write_to(writer, kea)?;
        }
        writer.flush(offset, sni, h2)
    }
}

