use super::{DNSClass, DNSError, DNSValue, DnsType, Domain};
use crate::Reader;
use std::fmt::Debug;


#[derive(Debug)]
#[allow(dead_code)]
pub struct DNSAnswer<'a> {
    name: Domain<'a>,
    type_: DnsType,
    class: DNSClass,
    live_sec: u32,
    data_len: u16,
    data: DNSValue<'a>,
}

impl<'b, 'a: 'b> DNSAnswer<'a> {
    pub fn from_bytes(reader: &'b mut Reader<'a>) -> Result<DNSAnswer<'a>, DNSError> {
        let name = Domain::from_bytes(reader)?;
        let type_: DnsType = reader.read_u16()?.into();
        let class: DNSClass = reader.read_u16()?.into();
        let live_sec = reader.read_u32()?;
        let data_len = reader.read_u16()?;
        let data = DNSValue::from_bytes(&type_, reader, data_len as usize)?;
        Ok(DNSAnswer {
            name,
            type_,
            class,
            live_sec,
            data_len,
            data,

        })
    }

    pub fn type_(&self) -> &DnsType {
        &self.type_
    }

    pub fn data(&self) -> &DNSValue<'a> {
        &self.data
    }
}