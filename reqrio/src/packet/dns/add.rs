use std::fmt::Debug;
use reqtls::{BufferError, Reader, Writer};
use crate::hex;
use super::{DNSClass, DNSError, Domain, DNSValue, DnsType};

#[derive(PartialEq)]
pub struct AddOptionCode(u16);

impl AddOptionCode {
    const COOKIE: AddOptionCode = AddOptionCode::new(0x000a);

    const fn new(val: u16) -> AddOptionCode {
        AddOptionCode(val)
    }

    const fn spec(&self) -> &str {
        match *self {
            AddOptionCode::COOKIE => "COOKIE",
            _ => "Reserved"
        }
    }

    const fn inner(&self) -> u16 { self.0 }

    const fn into_inner(self) -> u16 { self.0 }
}

#[cfg(debug_assertions)]
impl Debug for AddOptionCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}(0x{:x})", self.spec(), self.0)
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

    pub fn from_reader(reader: &'b mut Reader<'a>) -> Result<AddOption<'a>, BufferError> {
        let code = AddOptionCode::new(reader.read_u16()?);
        let len = reader.read_u16()? as usize;
        match code {
            AddOptionCode::COOKIE => Ok(AddOption::Cookie(reader.read_slice(len)?)),
            _ => Ok(AddOption::Reserved(reader.read_slice(len)?)),
        }
    }

    pub fn write_to(self, writer: &mut Writer) -> Result<(), BufferError> {
        match self {
            AddOption::Cookie(v) => {
                writer.write_u16(AddOptionCode::COOKIE.into_inner())?;
                writer.write_u16(v.len() as u16)?;
                writer.write_slice(v)
            }
            AddOption::Reserved(_) => unimplemented!()
        }
    }
}

#[cfg(debug_assertions)]
impl<'a> Debug for AddOption<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddOption::Cookie(v) => write!(f, "Cookie({})", hex::encode(v)),
            AddOption::Reserved(v) => write!(f, "Reserved({})", hex::encode(v)),
        }
    }
}

#[derive(Debug)]
pub struct Additional<'a> {
    name: Domain<'a>,
    typ: DnsType,
    class: DNSClass,
    live_sec: u32,
    data_len: u16,
    data: DNSValue<'a>,
}

impl<'b, 'a: 'b> Additional<'a> {
    pub fn new_opt(cookie: &'a [u8]) -> Additional<'a> {
        Additional {
            name: Domain::new(""),
            typ: DnsType::OPT.into(),
            class: DNSClass(4096),
            live_sec: 0,
            data_len: 0,
            data: DNSValue::OPT(AddOption::Cookie(cookie)),
        }
    }

    pub fn from_reader(reader: &'b mut Reader<'a>) -> Result<Additional<'a>, DNSError> {
        let name = Domain::from_reader(reader)?;
        let typ =DnsType::new(reader.read_u16()?);
        let class=DNSClass::new(reader.read_u16()?);
        let live_sec = reader.read_u32()?;
        let data_len = reader.read_u16()?;
        let data = DNSValue::from_reader(&typ, reader, data_len as usize)?;
        Ok(Additional {
            name,
            typ: typ,
            class,
            live_sec,
            data_len,
            data,
        })
    }

    pub fn write_to(self, writer: &mut Writer) -> Result<(), BufferError> {
        self.name.write_to(writer)?;
        writer.write_u16(self.typ.into_inner())?;
        writer.write_u16(self.class.into_inner())?;
        writer.write_u32(self.live_sec)?;
        writer.write_u16(self.data.len() as u16)?;
        self.data.write_to(writer)
    }
}