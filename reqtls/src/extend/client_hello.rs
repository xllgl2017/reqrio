use super::ech::KDF;
use crate::error::RlsResult;
use crate::{Aead, Buf, BufferError, Reader, Writer};

#[derive(Clone, Copy)]
struct HelloType(u8);

impl HelloType {
    #[allow(non_upper_case_globals)]
    pub const OuterClientHello: HelloType = HelloType::new(0);
    pub const fn new(v: u8) -> HelloType { HelloType(v) }

    // pub const fn inner(self) -> u8 { self.0 }

    pub const fn into_inner(self) -> u8 { self.0 }
}


#[derive(Clone)]
#[cfg_attr(debug_assertions, derive(Debug))]
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

    pub fn write_to(self, writer: &mut Writer) -> Result<(), BufferError> {
        writer.write_u16(self.kdf as u16)?;
        writer.write_u16(self.aead as u16)
    }
}


#[derive(Clone)]
pub struct EncryptClientHello<'a> {
    typ: HelloType,
    cipher_suite: CipherSuite,
    config_id: u8,
    enc_len: u16,
    enc: Buf<'a>,
    payload_len: u16,
    payload: Buf<'a>,
}

impl<'a> EncryptClientHello<'a> {
    pub fn new() -> EncryptClientHello<'a> {
        EncryptClientHello {
            typ: HelloType::OuterClientHello,
            cipher_suite: CipherSuite {
                kdf: KDF::HKDF_SHA256,
                aead: Aead::AES_128_GCM,
            },
            config_id: 0,
            enc_len: 0,
            enc: Buf::default(),
            payload_len: 0,
            payload: Buf::default(),
        }
    }

    pub fn from_reader(mut reader: Reader<'a>) -> RlsResult<EncryptClientHello<'a>> {
        let mut res = EncryptClientHello::new();
        res.typ = HelloType::new(reader.read_u8()?);
        res.cipher_suite = CipherSuite::from_reader(&mut reader)?;
        res.config_id = reader.read_u8()?;
        res.enc_len = reader.read_u16()?;
        res.enc = Buf::new_ref(reader.read_slice(res.enc_len as usize)?);
        res.payload_len = reader.read_u16()?;
        res.payload = Buf::new_ref(reader.read_slice(res.payload_len as usize)?);
        Ok(res)
    }

    pub fn len(&self) -> usize {
        6 + self.cipher_suite.len() + self.enc.len() + self.payload.len()
    }

    pub fn write_to(self, writer: &mut Writer) -> Result<(), BufferError> {
        writer.write_u8(self.typ.into_inner())?;
        self.cipher_suite.write_to(writer)?;
        writer.write_u8(self.config_id)?;
        writer.write_u16(self.enc.len() as u16)?;
        writer.write_slice(self.enc.as_ref())?;
        writer.write_u16(self.payload.len() as u16)?;
        writer.write_slice(self.payload.as_ref())
    }
}