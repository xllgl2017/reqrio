use crate::dns::error::DNSError;
use crate::dns::{DNSClass, DNSValue, DnsType, Domain};
use crate::{BufferError, Reader, Writer};
use std::fmt::Debug;

pub struct AddOptionCode(u16);

impl AddOptionCode {
    const COOKIE: u16 = 0x000a;

    fn spec(&self) -> &str {
        match self.0 {
            AddOptionCode::COOKIE => "COOKIE",
            _ => "Reserved"
        }
    }
}

impl Debug for AddOptionCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}(0x{:x})", self.spec(), self.0)
    }
}

impl From<u16> for AddOptionCode {
    fn from(code: u16) -> Self {
        AddOptionCode(code)
    }
}

pub enum AddOption<'a> {
    Cookie(&'a [u8]),
    Reserved(&'a [u8]),
}

impl<'b, 'a: 'b> AddOption<'a> {
    pub fn len(&self) -> usize {
        4 + match self {
            AddOption::Cookie(v) => v.len(),
            AddOption::Reserved(v) => v.len()
        }
    }

    pub fn from_bytes(reader: &'b mut Reader<'a>) -> Result<AddOption<'a>, DNSError> {
        let code: AddOptionCode = reader.read_u16()?.into();
        let len = reader.read_u16()? as usize;
        match code.0 {
            AddOptionCode::COOKIE => Ok(AddOption::Cookie(reader.read_slice(len)?)),
            _ => Ok(AddOption::Reserved(reader.read_slice(len)?)),
        }
    }

    pub fn write_to(self, writer: &mut Writer) -> Result<(), BufferError> {
        match self {
            AddOption::Cookie(v) => {
                writer.write_u16(AddOptionCode::COOKIE)?;
                writer.write_u16(v.len() as u16)?;
                writer.write_slice(v)
            }
            AddOption::Reserved(_) => unimplemented!()
        }
    }
}

impl<'a> Debug for AddOption<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddOption::Cookie(v) => write!(f, "Cookie({})", hex::encode(v)),
            AddOption::Reserved(v) => write!(f, "Reserved({})", hex::encode(v)),
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct Additional<'a> {
    name: Domain<'a>,
    type_: DnsType,
    class: DNSClass,
    live_sec: u32,
    data_len: u16,
    data: DNSValue<'a>,
}

impl<'b, 'a: 'b> Additional<'a> {
    pub fn new_opt(cookie: &'a [u8]) -> Additional<'a> {
        Additional {
            name: Domain::new(""),
            type_: DnsType::OPT.into(),
            class: DNSClass(4096),
            live_sec: 0,
            data_len: 0,
            data: DNSValue::OPT(AddOption::Cookie(cookie)),
        }
    }

    pub fn from_bytes(reader: &'b mut Reader<'a>) -> Result<Additional<'a>, DNSError> {
        let name = Domain::from_bytes(reader)?;
        let type_: DnsType = reader.read_u16()?.into();
        let class: DNSClass = reader.read_u16()?.into();
        let live_sec = reader.read_u32()?;
        let data_len = reader.read_u16()?;
        let data = DNSValue::from_bytes(&type_, reader, data_len as usize)?;
        Ok(Additional {
            name,
            type_,
            class,
            live_sec,
            data_len,
            data,
        })
    }

    pub fn write_to(self, writer: &mut Writer) -> Result<(), BufferError> {
        self.name.write_to(writer)?;
        writer.write_u16(self.type_.into_inner())?;
        writer.write_u16(self.class.into_inner())?;
        writer.write_u32(self.live_sec)?;
        writer.write_u16(self.data.len() as u16)?;
        self.data.write_to(writer)
    }
}