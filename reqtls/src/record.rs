use crate::error::RlsResult;
use super::message::Message;
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
pub struct RecordLayer {
    pub context_type: RecordType,
    pub version: Version,
    pub len: u16,
    pub message: Message,
}

impl RecordLayer {
    pub fn new() -> RecordLayer {
        RecordLayer {
            context_type: RecordType::CipherSpec,
            version: Version::new(0),
            len: 0,
            message: Message::CipherSpec,
        }
    }
    pub fn from_bytes(bytes: &[u8], payload: bool) -> RlsResult<RecordLayer> {
        let mut res = RecordLayer::new();
        res.context_type = RecordType::from_byte(bytes[0]).ok_or("LayerType Unknown")?;
        res.version = Version::new(u16::from_be_bytes([bytes[1], bytes[2]]));
        res.len = u16::from_be_bytes([bytes[3], bytes[4]]);
        if bytes.len()-5!=res.len as usize { return Err("record body not enough".into()); }
        res.message = match res.context_type {
            RecordType::HandShake => Message::from_bytes(bytes[5..].to_vec(), payload)?,
            _ => Message::CipherSpec,
        };
        Ok(res)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = vec![self.context_type.as_u8()];
        res.extend(self.version.as_bytes());
        let msg = self.message.as_bytes();
        res.extend((msg.len() as u16).to_be_bytes());
        res.extend(msg);
        res
    }

    // pub fn read<R: Read>(r: &mut R) -> SyncResult<RecordLayer> {
    //     let mut head = [0; 5];
    //     let len = r.read(&mut head)?;
    //     if len != 5 { return Err(SyncError::HeadSizeInvalid); }
    //     let mut res = RecordLayer::new();
    //     res.context_type = RecordType::from_byte(head[0]).ok_or("LayerType Unknown")?;
    //     res.version = Version::new(u16::from_be_bytes([head[1], head[2]]));
    //     res.len = u16::from_be_bytes([head[3], head[4]]) as usize;
    //
    //     let mut buffer = Vec::with_capacity(res.len);
    //     buffer.resize(res.len, 0); //unsafe { buffer.set_len(res.len); }
    //     let mut index = 0;
    //     while index < res.len {
    //         let len = r.read(&mut buffer[index..])?;
    //         if len == 0 { return Err(SyncError::PeerClosedConnection); }
    //         index += len;
    //     }
    //     let rd = hex::encode(&buffer);
    //     res.message = match res.context_type {
    //         RecordType::HandShake => Message::from_bytes(buffer)?,
    //         RecordType::ApplicationData => Message::from_bytes(buffer)?,
    //         _ => Message::CipherSpec,
    //     };
    //
    //     let sd = hex::encode(res.message.as_bytes());
    //     // println!("{}\n{}", rd, sd);
    //     if rd != sd { return Err("data error".into()); }
    //     Ok(res)
    // }
}