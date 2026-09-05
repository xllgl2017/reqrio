use std::fmt::Debug;
use std::net::{Ipv4Addr, Ipv6Addr};
use crate::dns::add::AddOption;
use crate::dns::domain::Domain;
use crate::dns::error::DNSError;
use crate::dns::SvcParam;
use crate::{BufferError, Reader, WriteExt};

pub struct DnsType(u16);

impl DnsType {
    ///Host Address
    pub const A: u16 = 0x0001;
    /// Authoritative name server
    pub const NS: u16 = 0x0002;
    ///Canonical Name
    pub const CNAME: u16 = 0x0005;
    ///Start of a zone of authority
    pub const SOA: u16 = 0x0006;
    ///Domain name PoinTeR
    pub const PTR: u16 = 0x000c;
    ///IPv6 Address
    pub const AAAA: u16 = 0x001c;
    ///
    pub const OPT: u16 = 0x0029;
    ///Https specific service endpoints
    pub const HTTPS: u16 = 0x0041;

    pub fn as_u16(&self) -> u16 {
        self.0
    }

    pub fn into_inner(self) -> u16 { self.0 }


    fn spec(&self) -> &str {
        match self.0 {
            DnsType::A => "A",
            DnsType::NS => "NS",
            DnsType::CNAME => "CNAME",
            DnsType::SOA => "SOA",
            DnsType::PTR => "PTR",
            DnsType::AAAA => "AAAA",
            DnsType::OPT => "OPT",
            DnsType::HTTPS => "HTTPS",
            _ => "Reserved"
        }
    }
}

impl Debug for DnsType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}(0x{:x})", self.spec(), self.0)
    }
}

impl From<&[u8]> for DnsType {
    fn from(bytes: &[u8]) -> Self {
        DnsType(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
}

impl From<u16> for DnsType {
    fn from(value: u16) -> Self {
        DnsType(value)
    }
}

impl PartialEq<u16> for &DnsType {
    fn eq(&self, other: &u16) -> bool {
        &self.as_u16() == other
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum DNSValue<'a> {
    A(Ipv4Addr),
    NS(Domain<'a>),
    CName(Domain<'a>),
    Soa {
        primary_name: Domain<'a>,
        authority: Domain<'a>,
        serial_number: u32,
        refresh_interval: u32,
        retry_interval: u32,
        expire_limit: u32,
        min_ttl: u32,
    },
    AAAA(Ipv6Addr),
    OPT(AddOption<'a>),
    Https {
        priority: u16,
        target: Domain<'a>,
        params: Vec<SvcParam<'a>>,
    },
    Null,
}

impl<'b, 'a: 'b> DNSValue<'a> {
    pub fn len(&self) -> usize {
        if let DNSValue::OPT(value) = self {
            value.len()
        } else { unreachable!() }
    }

    pub fn from_bytes(type_: &DnsType, reader: &'b mut Reader<'a>, len: usize) -> Result<Self, DNSError> {
        if len == 0 { return Ok(DNSValue::Null); }
        match type_.as_u16() {
            DnsType::A => Ok(DNSValue::A(Ipv4Addr::from_octets(reader.read_slice(4)?.try_into().map_err(DNSError::SliceError)?))),
            DnsType::NS => Ok(DNSValue::NS(Domain::from_bytes(reader)?)),
            DnsType::CNAME => Ok(DNSValue::CName(Domain::from_bytes(reader)?)),
            DnsType::SOA => {
                let primary_name = Domain::from_bytes(reader)?;
                let authority = Domain::from_bytes(reader)?;
                Ok(DNSValue::Soa {
                    primary_name,
                    authority,
                    serial_number: reader.read_u32()?,
                    refresh_interval: reader.read_u32()?,
                    retry_interval: reader.read_u32()?,
                    expire_limit: reader.read_u32()?,
                    min_ttl: reader.read_u32()?,
                })
            }
            DnsType::AAAA => Ok(DNSValue::AAAA(Ipv6Addr::from_octets(reader.read_slice(16)?.try_into().map_err(DNSError::SliceError)?))),
            DnsType::OPT => {
                Ok(DNSValue::OPT(AddOption::from_bytes(reader)?))
            }
            DnsType::HTTPS => {
                let start = reader.position();
                let priority = reader.read_u16()?;
                let target = Domain::from_bytes(reader)?;
                let mut params = vec![];
                while reader.position() < start + len {
                    let param = SvcParam::from_bytes(reader)?;
                    params.push(param);
                }
                Ok(DNSValue::Https {
                    priority,
                    target,
                    params,
                })
            }
            _ => Err(DNSError::UnknownDNSValue(type_.as_u16()))
        }
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) -> Result<(), BufferError> {
        if let DNSValue::OPT(value) = self {
            value.write_to(writer)
        } else { unreachable!() }
    }
}
