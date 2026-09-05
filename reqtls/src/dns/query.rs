use super::{DNSClass, DNSError, DnsType, Domain};
use crate::{BufferError, Reader, WriteExt};
use std::fmt::Debug;


#[derive(Debug)]
pub struct DNSQuery<'a> {
    name: Domain<'a>,
    type_: DnsType,
    class: DNSClass,
}


impl<'a> DNSQuery<'a> {
    pub fn new_query(type_: impl Into<DnsType>, domain: &'a str) -> DNSQuery<'a> {
        DNSQuery {
            name: Domain::new(domain),
            type_: type_.into(),
            class: DNSClass::IN.into(),
        }
    }

    pub fn from_bytes<'b>(reader: &'b mut Reader<'a>) -> Result<DNSQuery<'a>, DNSError> {
        let name = Domain::from_bytes(reader)?;
        Ok(DNSQuery {
            name,
            type_: reader.read_u16()?.into(),
            class: reader.read_u16()?.into(),
        })
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) -> Result<(), BufferError> {
        self.name.write_to(writer)?;
        writer.write_u16(self.type_.into_inner())?;
        writer.write_u16(self.class.into_inner())
    }
}
