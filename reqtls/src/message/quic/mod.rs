mod frame;

use std::cmp::Ordering;
use crate::{u24, Buf, Buffer, BufferError, Reader, WriteExt};
pub use frame::{QUICFrame, QUICFrameFlag, AckRange, TrpErrKind};


#[derive(Default, Copy, Clone, Debug, PartialEq)]
pub enum PacketType {
    #[default]
    Initial = 0,
    Handshake = 2,
    Retry = 3,
    ShortHeader,
}

impl From<u8> for PacketType {
    fn from(value: u8) -> Self {
        match value {
            0 => PacketType::Initial,
            2 => PacketType::Handshake,
            3 => PacketType::Retry,
            _ => unreachable!(),
        }
    }
}

impl PartialOrd for PacketType {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            (PacketType::Initial, PacketType::Initial) => Some(Ordering::Equal),
            (PacketType::Initial, PacketType::Handshake) => Some(Ordering::Less),
            (PacketType::Initial, PacketType::ShortHeader) => Some(Ordering::Less),
            (PacketType::Handshake, PacketType::Initial) => Some(Ordering::Greater),
            (PacketType::Handshake, PacketType::Handshake) => Some(Ordering::Equal),
            (PacketType::Handshake, PacketType::ShortHeader) => Some(Ordering::Less),
            (PacketType::ShortHeader, PacketType::Initial) => Some(Ordering::Greater),
            (PacketType::ShortHeader, PacketType::Handshake) => Some(Ordering::Greater),
            (PacketType::ShortHeader, PacketType::ShortHeader) => Some(Ordering::Equal),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::PacketType;

    #[test]
    fn test_packet_type() {
        assert_eq!(PacketType::Initial, PacketType::Initial);
        assert_eq!(PacketType::Handshake, PacketType::Handshake);
        assert_eq!(PacketType::Retry, PacketType::Retry);
        assert!(PacketType::Initial < PacketType::Handshake);
        assert!(PacketType::Initial < PacketType::ShortHeader);
        assert!(PacketType::Handshake < PacketType::ShortHeader);
        assert!(PacketType::Handshake > PacketType::Initial);
    }
}


#[derive(Default, Debug, Copy, Clone)]
pub struct QUICFlag {
    long_header: bool,
    fixed_bit: bool,
    spin_bit: bool,
    packet_type: PacketType,
    reserved: u8,
    key_phase: bool,
    num_len: u8,
}

impl QUICFlag {
    pub fn new_long(typ: PacketType) -> Self {
        QUICFlag {
            long_header: true,
            fixed_bit: false,
            spin_bit: false,
            packet_type: typ,
            reserved: 0,
            key_phase: false,
            num_len: 0,
        }
    }

    pub fn new_short(typ: PacketType) -> Self {
        QUICFlag {
            long_header: false,
            fixed_bit: true,
            spin_bit: false,
            packet_type: typ,
            reserved: 0,
            key_phase: false,
            num_len: 0,
        }
    }

    pub fn with_fixed_bit(mut self, fix_bit: bool) -> Self {
        self.fixed_bit = fix_bit;
        self
    }

    pub fn from_raw(v: u8) -> QUICFlag {
        let mut flag = QUICFlag {
            long_header: v & 0x80 == 0x80,
            fixed_bit: v & 0x40 == 0x40,
            spin_bit: false,
            packet_type: PacketType::ShortHeader,
            reserved: 0,
            key_phase: false,
            num_len: 0,
        };
        if flag.long_header {
            flag.packet_type = ((v & 0x30) >> 4).into();
        } else {
            flag.spin_bit = (v & 0x20) == 0x20;
        }
        flag
    }

    fn decode(&mut self, v: u8) {
        if self.long_header {
            self.reserved = v & 0xc >> 2;
        } else {
            self.reserved = (v >> 3) & 3;
            self.key_phase = v & 4 == 4;
        }
        self.num_len = (v & 3) + 1;
    }

    pub fn encode(&self) -> u8 {
        let mut v = 0;
        if self.long_header {
            v |= 0x80;
        }
        if self.fixed_bit {
            v |= 0x40;
        }
        if self.long_header {
            v |= (self.packet_type as u8) << 4;
            v |= self.reserved << 2;
        } else {
            if self.spin_bit {
                v |= 0x20;
            }
            v |= self.reserved << 3;
            if self.key_phase {
                v |= 4;
            }
        }
        match self.num_len {
            1 => v |= 0b00,
            2 => v |= 0b01,
            4 => v |= 0b10,
            8 => v |= 0b11,
            _ => unreachable!(),
        }
        v
    }

    pub fn num_len(&self) -> usize {
        self.num_len as usize
    }

    pub fn packet_type(&self) -> PacketType {
        self.packet_type
    }

    pub fn is_long_header(&self) -> bool {
        self.long_header
    }
}

#[derive(Debug)]
pub struct QUICPacket<'a> {
    pub(crate) flag: QUICFlag,
    pub(crate) ver: u32,
    pub(crate) dc_id: Buf<'a>,
    pub(crate) sc_id: Buf<'a>,
    pub(crate) token: Buf<'a>,
    len: usize,
    pub(crate) pn_offset: usize,
    pub(crate) num: u64,
    pub(crate) payload: Buf<'a>,

    pub(crate) hdr_raw: Buffer,
    pub(crate) padding: usize,
    pub(crate) tag: Buf<'a>,
}

impl<'a> Default for QUICPacket<'a> {
    fn default() -> Self {
        QUICPacket {
            flag: QUICFlag::default(),
            ver: 0,
            dc_id: Buf::Ref(&[]),
            sc_id: Buf::Ref(&[]),
            token: Buf::Ref(&[]),
            len: 0,
            pn_offset: 0,
            num: 0,
            payload: Buf::Ref(&[]),
            hdr_raw: Buffer::with_capacity(256),
            padding: 0,
            tag: Buf::Ref(&[]),
        }
    }
}

impl<'a> QUICPacket<'a> {
    pub fn new_long(pty: PacketType, num: u64, pd_len: usize, dcid: &'a [u8], token: &'a Buf<'a>) -> Self {
        std::debug_assert_matches!(pty,  PacketType::Initial| PacketType::Handshake);
        let num_len = crate::quic::variant_len(num as usize);
        let (len, padding) = if pd_len + num_len + 16 >= 1232 {
            (pd_len + num_len + 16, 0)
        } else { (1232, 1232 - pd_len - num_len - 16) };
        QUICPacket {
            flag: QUICFlag {
                long_header: true,
                fixed_bit: true,
                spin_bit: false,
                packet_type: pty,
                reserved: 0,
                key_phase: false,
                num_len: num_len as u8,
            },
            ver: 1,
            len,
            num,
            padding,
            dc_id: Buf::Ref(dcid),
            token: Buf::Ref(token.as_ref()),
            ..Default::default()
        }
    }

    pub fn new_short(pty: PacketType, num: u64, pd_len: usize, dcid: &'a [u8]) -> Self {
        std::debug_assert_matches!(pty, PacketType::ShortHeader);
        let num_len = crate::quic::variant_len(num as usize);
        QUICPacket {
            flag: QUICFlag {
                long_header: false,
                fixed_bit: true,
                spin_bit: false,
                packet_type: pty,
                reserved: 0,
                key_phase: false,
                num_len: num_len as u8,
            },
            ver: 1,
            len: pd_len + num_len + 16,
            num,
            padding: 0,
            dc_id: Buf::Ref(dcid),
            ..Default::default()
        }
    }

    pub fn new_ack(flag: QUICFlag, dc_id: &'a [u8], num: u64, pd_len: usize) -> Self {
        let num_len = crate::quic::variant_len(num as usize);
        let len = pd_len + num_len + 16;
        QUICPacket {
            flag: QUICFlag {
                long_header: flag.long_header,
                fixed_bit: flag.fixed_bit,
                spin_bit: false,
                packet_type: flag.packet_type,
                reserved: flag.reserved,
                key_phase: flag.key_phase,
                num_len: num_len as u8,
            },
            ver: 1,
            len,
            num,
            padding: 0,
            dc_id: Buf::Ref(dc_id),
            ..Default::default()
        }
    }

    pub fn is_empty(&self) -> bool {
        self.hdr_raw.is_empty()
    }

    pub fn len(&self) -> usize {
        self.hdr_raw.len() + self.len - self.flag.num_len as usize
    }

    pub fn hdr_raw(&self) -> &[u8] {
        self.hdr_raw.filled()
    }

    pub fn hdr_len(&self) -> usize {
        self.hdr_raw.len()
    }

    pub fn flag(&self) -> &QUICFlag {
        &self.flag
    }

    pub fn padding_size(&self) -> usize {
        self.padding
    }

    pub fn pd_len(&self) -> usize {
        self.len
    }

    pub fn encode(&mut self) -> Result<(), BufferError> {
        self.hdr_raw.reset();
        if self.flag.long_header {
            self.hdr_raw.write_u8(self.flag.encode())?;
            self.hdr_raw.write_u32(self.ver)?;
            self.hdr_raw.write_u8(self.dc_id.len() as u8)?;
            self.hdr_raw.write_slice(self.dc_id.as_ref())?;
            self.hdr_raw.write_u8(self.sc_id.len() as u8)?;
            self.hdr_raw.write_slice(self.sc_id.as_ref())?;
            if self.flag.packet_type == PacketType::Initial {
                crate::quic::write_variant(self.token.len(), &mut self.hdr_raw)?;
                self.hdr_raw.write_slice(self.token.as_ref())?;
            }
            crate::quic::write_variant(self.len, &mut self.hdr_raw)?;
        } else {
            self.hdr_raw.write_u8(self.flag.encode())?;
            self.hdr_raw.write_slice(self.dc_id.as_ref())?;
        }
        self.pn_offset = self.hdr_raw.len();
        match self.flag.num_len() {
            1 => self.hdr_raw.write_u8(self.num as u8)?,
            2 => self.hdr_raw.write_u16(self.num as u16)?,
            4 => self.hdr_raw.write_u32(self.num as u32)?,
            8 => self.hdr_raw.write_slice(&self.num.to_be_bytes())?,
            _ => unreachable!()
        }
        Ok(())
    }

    pub fn from_reader(reader: &mut Reader<'a>) -> Result<QUICPacket<'a>, BufferError> {
        let pos = reader.position();
        let flag = QUICFlag::from_raw(reader.read_u8()?);
        if flag.long_header {
            let ver = reader.read_u32()?;
            let dcid_len = reader.read_u8()? as usize;
            let dc_id = reader.read_slice(dcid_len)?;
            let scid_len = reader.read_u8()? as usize;
            let sc_id = reader.read_slice(scid_len)?;
            let mut packet = QUICPacket {
                flag,
                ver,
                dc_id: Buf::Ref(dc_id),
                sc_id: Buf::Ref(sc_id),
                ..Default::default()
            };
            match flag.packet_type {
                PacketType::Initial => {
                    let tk_len = crate::quic::read_variant(reader)?;
                    packet.token = Buf::Ref(reader.read_slice(tk_len)?);
                    packet.len = crate::quic::read_variant(reader)?;
                    packet.pn_offset = reader.position() - pos;
                }
                PacketType::Handshake => {
                    packet.len = crate::quic::read_variant(reader)?;
                    packet.pn_offset = reader.position() - pos;
                }
                PacketType::Retry => {
                    packet.token = Buf::Ref(reader.read_slice(80)?);
                    packet.tag = Buf::Ref(reader.read_slice(16)?)
                }
                PacketType::ShortHeader => {
                    packet.len = crate::quic::read_variant(reader)?;
                    packet.pn_offset = reader.position() - pos;
                }
            }
            packet.hdr_raw.write_slice(&reader.inner()[pos..reader.position()])?;
            Ok(packet)
        } else {
            let mut hdr_raw = Buffer::with_capacity(30);
            hdr_raw.write_u8(reader.inner()[pos])?;
            Ok(QUICPacket {
                flag,
                len: reader.unread_len(),
                pn_offset: reader.position() - pos,
                hdr_raw,
                ..Default::default()
            })
        }
    }

    pub fn decode(&mut self, mask: &[u8], reader: &mut Reader<'a>) -> Result<(), BufferError> {
        let mut mask_reader = Reader::from_slice(mask);
        let mut flag = self.hdr_raw.filled()[0];
        if self.flag.long_header {
            flag ^= mask_reader.read_u8()? & 0x0f;
            self.hdr_raw.write_slice_in(0, &[flag])?;
        } else {
            flag ^= mask_reader.read_u8()? & 0x1f;
            self.hdr_raw.write_slice_in(0, &[flag])?;
        }
        self.flag.decode(flag);
        match self.flag.num_len() {
            1 => {
                self.num = (reader.read_u8()? ^ mask_reader.read_u8()?) as u64;
                self.hdr_raw.write_u8(self.num as u8)?;
            }
            2 => {
                self.num = (reader.read_u16()? ^ mask_reader.read_u16()?) as u64;
                self.hdr_raw.write_u16(self.num as u16)?;
            }
            3 => {
                self.num = (reader.read_u24()? ^ mask_reader.read_u24()?) as u64;
                self.hdr_raw.write_u24(self.num as u24)?;
            }
            4 => {
                self.num = (reader.read_u32()? ^ mask_reader.read_u32()?) as u64;
                self.hdr_raw.write_u32(self.num as u32)?;
            }
            _ => unreachable!()
        };
        self.payload = Buf::Ref(reader.read_slice(self.len - self.flag.num_len())?);
        Ok(())
    }

    pub fn dc_id(&self) -> &Buf<'a> {
        &self.dc_id
    }

    pub fn sc_id(&self) -> &Buf<'a> {
        &self.sc_id
    }

    pub fn num(&self) -> u64 {
        self.num
    }

    pub fn token(&self) -> &Buf<'a> {
        &self.token
    }
}