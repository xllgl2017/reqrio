use super::Marker;
use crate::*;
use reqtls::coder::{CodingError, DeflateStream};

pub struct WsPayload {
    len: usize,
    mask: [u8; 4],
    payload: Vec<u8>,
}

impl WsPayload {
    const DEFLATE_END: [u8; 4] = [0x00, 0x00, 0xff, 0xff];

    pub fn new() -> WsPayload {
        WsPayload {
            len: 0,
            mask: rand::random::<[u8; 4]>(),
            payload: vec![],
        }
    }

    fn decode(&self, coder: &mut DeflateStream, reader: &mut Reader, payload: &mut Vec<u8>) -> Result<usize, CodingError> {
        let mut out_len = 0;
        while reader.unread_len() > 0 {
            out_len += coder.decompress_once(reader, payload, true)?;
        }
        Ok(out_len)
    }

    pub(crate) fn read_payload(&mut self, mut reader: Reader, masker: &Marker, coder: Option<&mut DeflateStream>, demask_buffer: &mut Writer) -> Result<(), CodingError> {
        demask_buffer.reset();
        match (masker.mask, coder) {
            (true, None) => {
                let mut payload = Vec::with_capacity(reader.inner().len());
                for (i, b) in reader.inner().iter().enumerate() {
                    payload.push(b ^ self.mask[i % 4])
                }
                self.payload = payload
            }
            (false, None) => self.payload = reader.inner().to_vec(),
            (false, Some(coder)) => {
                let mut payload = vec![0; reader.inner().len() * 2];
                let mut out_len = self.decode(coder, &mut reader, &mut payload)?;
                let mut reader = Reader::from_slice(&Self::DEFLATE_END);
                out_len += self.decode(coder, &mut reader, &mut payload)?;
                payload.truncate(out_len);
                self.payload = payload;
            }
            (true, Some(coder)) => {
                if demask_buffer.capacity() < reader.inner().len() {
                    demask_buffer.resize(reader.inner().len())?;
                }
                for (i, b) in reader.inner().iter().enumerate() {
                    demask_buffer.write_u8(b ^ self.mask[i % 4])?;
                }
                let mut payload = vec![0; reader.inner().len() * 2];
                let mut reader = Reader::from_slice(demask_buffer.filled());
                let mut out_len = self.decode(coder, &mut reader, &mut payload)?;
                let mut reader = Reader::from_slice(&Self::DEFLATE_END);
                out_len += self.decode(coder, &mut reader, &mut payload)?;
                payload.truncate(out_len);
                self.payload = payload;
            }
        }
        Ok(())
    }

    pub fn from_reader(masker: &Marker, reader: &mut Reader, coder: Option<&mut DeflateStream>, demask_buffer: &mut Writer) -> Result<WsPayload, CodingError> {
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
        self.payload.as_ref()
    }

    pub fn len(&self) -> usize {
        self.len
    }
}
