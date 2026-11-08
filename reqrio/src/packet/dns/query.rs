use super::{DNSClass, DNSError, DnsType, Domain};
use std::fmt::Debug;
use reqtls::{BufferError, Reader, Writer};

#[derive(Debug)]
pub struct DNSQuery<'a> {
    name: Domain<'a>,
    typ: DnsType,
    class: DNSClass,
}


impl<'a> DNSQuery<'a> {
    pub fn new_query(typ: DnsType, domain: &'a str) -> DNSQuery<'a> {
        DNSQuery {
            name: Domain::new(domain),
            typ,
            class: DNSClass::IN.into(),
        }
    }

    pub fn from_bytes<'b>(reader: &'b mut Reader<'a>) -> Result<DNSQuery<'a>, DNSError> {
        let name = Domain::from_reader(reader).unwrap();
        Ok(DNSQuery {
            name,
            typ: DnsType::new(reader.read_u16().unwrap()),
            class: DNSClass::new(reader.read_u16().unwrap()),
        })
    }

    pub fn write_to(self, writer: &mut Writer) -> Result<(), BufferError> {
        self.name.write_to(writer)?;
        writer.write_u16(self.typ.into_inner())?;
        writer.write_u16(self.class.into_inner())
    }
}
