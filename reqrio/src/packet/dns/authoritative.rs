use super::{DNSClass, DNSValue, DnsType, Domain};
use crate::Reader;
use reqtls::BufferError;

#[derive(Debug)]
#[allow(dead_code)]
pub struct Authoritative<'a> {
    name: Domain<'a>,
    type_: DnsType,
    class: DNSClass,
    live_sec: u32,
    data_len: u16,
    data: DNSValue<'a>,
}

impl<'b, 'a: 'b> Authoritative<'a> {
    pub fn from_reader(reader: &'b mut Reader<'a>) -> Result<Authoritative<'a>, BufferError> {
        let name = Domain::from_reader(reader)?;
        let typ = DnsType::new(reader.read_u16()?);
        let class = DNSClass::new(reader.read_u16()?);
        let live_sec = reader.read_u32()?;
        let data_len = reader.read_u16()?;
        let data = DNSValue::from_reader(&typ, reader, data_len as usize)?;

        Ok(Authoritative {
            name,
            type_: typ,
            class,
            live_sec,
            data_len,
            data,
        })
    }
}