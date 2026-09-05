use crate::buffer::Buf;
use crate::error::RlsResult;
use crate::{rand, BufferError, Reader, WriteExt};

#[derive(Debug, Clone)]
pub struct PskIdentity<'a> {
    value: Buf<'a>,
    age: u32,
}

impl<'a> PskIdentity<'a> {
    fn new() -> PskIdentity<'a> {
        PskIdentity {
            value: Buf::Ref(&[]),
            age: 0,
        }
    }

    fn random() -> PskIdentity<'a> {
        let mut res = PskIdentity::new();
        res.value = Buf::Vec(rand::random::<[u8; 140]>().to_vec());
        res.age = rand::random();
        res
    }

    fn from_reader(reader: &mut Reader<'a>) -> RlsResult<PskIdentity<'a>> {
        let len = reader.read_u16()?;
        Ok(PskIdentity {
            value: Buf::Ref(reader.read_slice(len as usize)?),
            age: reader.read_u32()?,
        })
    }

    pub fn len(&self) -> usize {
        6 + self.value.len()
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) -> Result<(), BufferError> {
        writer.write_u16(self.value.len() as u16)?;
        writer.write_slice(self.value.as_ref())?;
        writer.write_u32(self.age)
    }
}

#[derive(Debug, Clone)]
pub struct PskBinder<'a> {
    value: Buf<'a>,
}

impl<'a> PskBinder<'a> {
    fn new() -> PskBinder<'a> {
        PskBinder {
            value: Buf::Ref(&[]),
        }
    }

    fn random() -> PskBinder<'a> {
        let mut res = PskBinder::new();
        res.value = Buf::Vec(rand::random::<[u8; 48]>().to_vec());
        res
    }

    fn from_reader(reader: &mut Reader<'a>) -> RlsResult<PskBinder<'a>> {
        let len = reader.read_u8()?;
        Ok(PskBinder { value: Buf::Ref(reader.read_slice(len as usize)?) })
    }

    pub fn len(&self) -> usize {
        1 + self.value.len()
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) -> Result<(), BufferError> {
        writer.write_u8(self.value.len() as u8)?;
        writer.write_slice(self.value.as_ref())
    }
}

#[derive(Debug, Clone)]
pub struct PreSharedKey<'a> {
    identity: PskIdentity<'a>,
    binder: PskBinder<'a>,

}

impl<'a> PreSharedKey<'a> {
    pub fn new() -> PreSharedKey<'a> {
        PreSharedKey {
            identity: PskIdentity::new(),
            binder: PskBinder::new(),
        }
    }

    pub fn from_reader(mut reader: Reader) -> RlsResult<PreSharedKey> {
        reader.read_u16()?;
        let identity = PskIdentity::from_reader(&mut reader)?;
        reader.read_u16()?;
        Ok(PreSharedKey {
            identity,
            binder: PskBinder::from_reader(&mut reader)?,
        })
    }

    pub fn random() -> PreSharedKey<'a> {
        let mut res = PreSharedKey::new();
        res.identity = PskIdentity::random();
        res.binder = PskBinder::random();
        res
    }

    pub fn len(&self) -> usize {
        4 + self.binder.len() + self.identity.len()
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) -> Result<(), BufferError> {
        writer.write_u16(self.identity.len() as u16)?;
        self.identity.write_to(writer)?;
        writer.write_u16(self.binder.len() as u16)?;
        self.binder.write_to(writer)
    }
}