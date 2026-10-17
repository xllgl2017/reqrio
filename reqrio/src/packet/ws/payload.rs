use reqtls::coder::{StreamDecode, TZCoder};
use super::Marker;
use crate::*;

pub struct WsPayload {
    len: usize,
    mask: [u8; 4],
    payload: Buffer,
}

impl WsPayload {
    const DEFLATE_END: [u8; 4] = [0x00, 0x00, 0xff, 0xff];

    pub fn new() -> WsPayload {
        WsPayload {
            len: 0,
            mask: rand::random::<[u8; 4]>(),
            payload: Buffer::none(),
        }
    }

    // fn decode(&self, coder: &mut TZCoder, reader: &mut Reader, payload: &mut Buffer) -> HlsResult<usize> {
    //
    //     let mut out_len = 0;
    //     while reader.unread_len() > 0 {
    //         out_len += coder.decompress_once(reader, payload, true)?;
    //     }
    //     Ok(out_len)
    // }

    pub(crate) fn read_payload(&mut self, mut reader: Reader, masker: &Marker, coder: Option<&mut TZCoder>, demask_buffer: &mut Writer) -> HlsResult<()> {
        demask_buffer.reset();
        match (masker.mask, coder) {
            (true, None) => {
                let mut payload = Buffer::with_capacity(reader.inner().len());
                for (i, b) in reader.inner().iter().enumerate() {
                    payload.write_u8(b ^ self.mask[i % 4])?
                }
                self.payload = payload
            }
            (false, None) => {
                self.payload = Buffer::with_capacity(reader.size());
                self.payload.write_slice(reader.inner())?;
            }
            (false, Some(coder)) => {
                let mut payload = Buffer::with_capacity(reader.inner().len() * 2);
                coder.decompress(&mut reader, &mut payload)?;
                // let mut out_len = self.decode(coder, &mut reader, &mut payload)?;
                let mut reader = Reader::from_slice(&Self::DEFLATE_END);
                coder.decompress(&mut reader, &mut payload)?;
                // out_len += self.decode(coder, &mut reader, &mut payload)?;
                // payload.truncate(out_len);
                self.payload = payload;
            }
            (true, Some(coder)) => {
                if demask_buffer.capacity() < reader.inner().len() {
                    demask_buffer.resize(reader.inner().len())?;
                }
                for (i, b) in reader.inner().iter().enumerate() {
                    demask_buffer.write_u8(b ^ self.mask[i % 4])?;
                }
                let mut payload = Buffer::with_capacity(reader.inner().len() * 2);
                let mut reader = Reader::from_slice(demask_buffer.filled());
                coder.decompress(&mut reader, &mut payload)?;
                let mut reader = Reader::from_slice(&Self::DEFLATE_END);
                coder.decompress(&mut reader, &mut payload)?;
                // let mut out_len = self.decode(coder, &mut reader, &mut payload)?;
                // out_len += self.decode(coder, &mut reader, &mut payload)?;
                // payload.truncate(out_len);
                self.payload = payload;
            }
        }
        Ok(())
    }

    pub fn from_reader(masker: &Marker, reader: &mut Reader, coder: Option<&mut TZCoder>, demask_buffer: &mut Writer) -> HlsResult<WsPayload> {
        let mut res = WsPayload::new();
        res.len = match masker.len_code {
            127 => reader.read_u64()? as usize,
            126 => reader.read_u16()? as usize,
            _ => masker.len_code as usize
        };
        if masker.mask {
            res.mask.copy_from_slice(reader.read_slice(4)?);
        }
        res.read_payload(reader.read_reader(res.len)?, masker, coder, demask_buffer)?;
        Ok(res)
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.payload.filled()
    }

    pub fn len(&self) -> usize {
        self.len
    }
}
