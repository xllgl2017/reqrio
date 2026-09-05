use super::super::message::HandshakeType;
use crate::buffer::Buf;
use crate::error::RlsResult;
use crate::{u24, BufferError, Reader, Version, Writer};
use crate::extend::Extension;

#[derive(Debug)]
#[allow(unused)]
pub struct TlsSessionTicket<'a> {
    lifetime: u32,
    age_add: u32,
    nonce: Buf<'a>,
    ticket: Buf<'a>,
    extensions: Vec<Extension<'a>>,
}

impl<'a> Default for TlsSessionTicket<'a> {
    fn default() -> TlsSessionTicket<'a> {
        TlsSessionTicket {
            lifetime: 3600,
            age_add: 0,
            nonce: Buf::Ref(&[]),
            ticket: Buf::Ref(&[]),
            extensions: vec![],
        }
    }
}

impl<'a> TlsSessionTicket<'a> {
    pub fn from_reader(reader: &mut Reader<'a>, version: &Version) -> RlsResult<TlsSessionTicket<'a>> {
        let lifetime = reader.read_u32()?;
        let (age_add, nonce) = match *version {
            Version::TLS_1_3 => {
                let age_add = reader.read_u32()?;
                let nonce_len = reader.read_u8()? as usize;
                let nonce = Buf::Ref(reader.read_slice(nonce_len)?);
                (age_add, nonce)
            }
            _ => (0, Buf::Ref(&[]))
        };
        let len = reader.read_u16()? as usize;
        let ticket = Buf::Ref(reader.read_slice(len)?);
        let extensions = if version == &Version::TLS_1_3 {
            let ext_len = reader.read_u16()?;
            Extension::from_reader(reader.read_reader(ext_len as usize)?, true)?
        } else { vec![] };

        Ok(TlsSessionTicket {
            lifetime,
            age_add,
            nonce,
            ticket,
            extensions,
        })
    }

    pub fn is_empty(&self) -> bool { self.len() == 0 }

    pub fn len(&self) -> usize {
        6 + self.ticket.len()
    }

    pub fn write_to(self, writer: &mut Writer) -> Result<(), BufferError> {
        writer.write_u32(self.lifetime)?;
        writer.write_u16(self.ticket.len() as u16)?;
        writer.write_slice(self.ticket.as_ref())
    }

    pub fn set_value(&mut self, value: &'a [u8]) {
        self.ticket = Buf::Ref(value);
    }

    pub fn ticket(&self) -> &Buf<'a> {
        &self.ticket
    }
}

#[derive(Debug)]
pub struct SessionTicket<'a> {
    handshake_type: HandshakeType,
    tls_ticket: TlsSessionTicket<'a>,
}

impl<'a> Default for SessionTicket<'a> {
    fn default() -> SessionTicket<'a> {
        SessionTicket {
            handshake_type: HandshakeType::NewSessionTicket,
            tls_ticket: TlsSessionTicket::default(),
        }
    }
}

impl<'a> SessionTicket<'a> {
    pub fn from_reader(ht: HandshakeType, reader: &mut Reader<'a>, version: &Version) -> RlsResult<SessionTicket<'a>> {
        reader.read_u24()?;
        Ok(SessionTicket {
            handshake_type: ht,
            tls_ticket: TlsSessionTicket::from_reader(reader, version)?,
        })
    }

    pub fn is_empty(&self) -> bool { self.len() == 0 }

    pub fn len(&self) -> usize {
        4 + self.tls_ticket.len()
    }

    pub fn write_to(self, writer: &mut Writer) -> Result<(), BufferError> {
        writer.write_u8(self.handshake_type as u8)?;
        writer.write_u24(self.tls_ticket.len() as u24)?;
        self.tls_ticket.write_to(writer)
    }

    pub fn tls_ticket_mut(&mut self) -> &mut TlsSessionTicket<'a> {
        &mut self.tls_ticket
    }

    pub fn tls_ticket(&self) -> &TlsSessionTicket<'a> {
        &self.tls_ticket
    }
}