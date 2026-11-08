use super::SvcParam;
use super::add::AddOption;
use super::domain::Domain;
use reqtls::{BufferError, Reader, Writer};
use std::fmt::Debug;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Copy, Clone, PartialEq)]
pub struct DnsType(u16);

impl DnsType {
    ///Host Address
    pub const A: DnsType = DnsType::new(0x0001);
    /// Authoritative name server
    pub const NS: DnsType = DnsType::new(0x0002);
    ///Canonical Name
    pub const CNAME: DnsType = DnsType::new(0x0005);
    ///Start of a zone of authority
    pub const SOA: DnsType = DnsType::new(0x0006);
    ///Domain name PoinTeR
    pub const PTR: DnsType = DnsType::new(0x000c);
    ///IPv6 Address
    pub const AAAA: DnsType = DnsType::new(0x001c);
    ///
    pub const OPT: DnsType = DnsType::new(0x0029);
    ///Https specific service endpoints
    pub const HTTPS: DnsType = DnsType::new(0x0041);

    pub const fn new(val: u16) -> DnsType {
        DnsType(val)
    }

    pub const fn inner(&self) -> u16 {
        self.0
    }

    pub const fn into_inner(self) -> u16 { self.0 }

    const fn spec(&self) -> &str {
        match *self {
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
#[cfg(debug_assertions)]
impl Debug for DnsType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}(0x{:x})", self.spec(), self.0)
    }
}


#[cfg_attr(debug_assertions, derive(Debug))]
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

    pub fn from_reader(typ: &DnsType, reader: &'b mut Reader<'a>, len: usize) -> Result<Self, BufferError> {
        if len == 0 { return Ok(DNSValue::Null); }
        match *typ {
            DnsType::A => Ok(DNSValue::A(Ipv4Addr::from_bits(reader.read_u32_le()?))),
            DnsType::NS => Ok(DNSValue::NS(Domain::from_reader(reader)?)),
            DnsType::CNAME => Ok(DNSValue::CName(Domain::from_reader(reader)?)),
            DnsType::SOA => {
                let primary_name = Domain::from_reader(reader)?;
                let authority = Domain::from_reader(reader)?;
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
            DnsType::AAAA => Ok(DNSValue::AAAA(Ipv6Addr::from_octets(reader.read_slice(16)?.try_into().map_err(|_| BufferError::Insufficient)?))),
            DnsType::OPT => {
                Ok(DNSValue::OPT(AddOption::from_reader(reader)?))
            }
            DnsType::HTTPS => {
                let start = reader.position();
                let priority = reader.read_u16()?;
                let target = Domain::from_reader(reader)?;
                let mut params = vec![];
                while reader.position() < start + len {
                    let param = SvcParam::from_reader(reader)?;
                    params.push(param);
                }
                Ok(DNSValue::Https {
                    priority,
                    target,
                    params,
                })
            }
            _ => unreachable!("unknown dns-{:?}", typ)
        }
    }

    pub fn write_to(self, writer: &mut Writer) -> Result<(), BufferError> {
        if let DNSValue::OPT(value) = self {
            value.write_to(writer)
        } else { unreachable!() }
    }
}
