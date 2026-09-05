use super::ech::{Aead, KDF};
use crate::error::RlsResult;
use crate::{BufferError, Reader, WriteExt};

#[derive(Debug, Clone, Copy)]
enum ClientHelloType {
    OuterClientHello = 0,
}

impl ClientHelloType {
    fn from_u8(v: u8) -> Option<ClientHelloType> {
        match v {
            0 => Some(ClientHelloType::OuterClientHello),
            _ => None
        }
    }
}


#[derive(Debug, Clone)]
pub(super) struct CipherSuite {
    pub(super) kdf: KDF,
    pub(super) aead: Aead,
}

impl CipherSuite {
    pub fn from_reader(reader: &mut Reader<'_>) -> RlsResult<CipherSuite> {
        Ok(CipherSuite {
            kdf: KDF::from_u16(reader.read_u16()?).ok_or("KDF Unknown")?,
            aead: Aead::from_u16(reader.read_u16()?).ok_or("AEAD Unknown")?,
        })
    }

    pub fn len(&self) -> usize { 4 }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) -> Result<(), BufferError> {
        writer.write_u16(self.kdf as u16)?;
        writer.write_u16(self.aead as u16)
    }
}


#[derive(Debug, Clone)]
pub struct EncryptClientHello<'a> {
    type_: ClientHelloType,
    cipher_suite: CipherSuite,
    config_id: u8,
    enc_len: u16,
    enc: &'a [u8],
    payload_len: u16,
    payload: &'a [u8],
}

impl<'a> EncryptClientHello<'a> {
    pub fn new() -> EncryptClientHello<'a> {
        EncryptClientHello {
            type_: ClientHelloType::OuterClientHello,
            cipher_suite: CipherSuite {
                kdf: KDF::HKDF_SHA256,
                aead: Aead::AES_128_GCM,
            },
            config_id: 0,
            enc_len: 0,
            enc: &[],
            payload_len: 0,
            payload: &[],
        }
    }

    pub fn from_reader(mut reader: Reader<'a>) -> RlsResult<EncryptClientHello<'a>> {
        let mut res = EncryptClientHello::new();
        res.type_ = ClientHelloType::from_u8(reader.read_u8()?).ok_or("ClientHelloType Unknown")?;
        res.cipher_suite = CipherSuite::from_reader(&mut reader)?;
        res.config_id = reader.read_u8()?;
        res.enc_len = reader.read_u16()?;
        res.enc = reader.read_slice(res.enc_len as usize)?;
        res.payload_len = reader.read_u16()?;
        res.payload = reader.read_slice(res.payload_len as usize)?;
        Ok(res)
    }

    pub fn len(&self) -> usize {
        6 + self.cipher_suite.len() + self.enc.len() + self.payload.len()
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) -> Result<(), BufferError> {
        writer.write_u8(self.type_ as u8)?;
        self.cipher_suite.write_to(writer)?;
        writer.write_u8(self.config_id)?;
        writer.write_u16(self.enc.len() as u16)?;
        writer.write_slice(self.enc.as_ref())?;
        writer.write_u16(self.payload.len() as u16)?;
        writer.write_slice(self.payload.as_ref())
    }
}