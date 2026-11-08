use super::{DNSClass, DNSError, DNSValue, DnsType, Domain};
use crate::Reader;
use std::fmt::Debug;


#[derive(Debug)]
#[allow(dead_code)]
pub struct DNSAnswer<'a> {
    name: Domain<'a>,
    typ: DnsType,
    class: DNSClass,
    live_sec: u32,
    data_len: u16,
    data: DNSValue<'a>,
}

impl<'b, 'a: 'b> DNSAnswer<'a> {
    pub fn from_reader(reader: &'b mut Reader<'a>) -> Result<DNSAnswer<'a>, DNSError> {
        let name = Domain::from_reader(reader)?;
        let typ = DnsType::new(reader.read_u16()?);
        let class = DNSClass::new(reader.read_u16()?);
        let live_sec = reader.read_u32()?;
        let data_len = reader.read_u16()?;
        let data = DNSValue::from_reader(&typ, reader, data_len as usize)?;
        Ok(DNSAnswer {
            name,
            typ,
            class,
            live_sec,
            data_len,
            data,

        })
    }

    pub const fn typ(&self) -> DnsType {
        self.typ
    }

    pub const fn data(&self) -> &DNSValue<'a> {
        &self.data
    }
}