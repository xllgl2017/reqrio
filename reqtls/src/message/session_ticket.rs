use crate::error::RlsResult;
use crate::{u24, BufferError, Reader, Version, Writer};
use std::os::raw::c_void;
use std::ptr::null;
use std::slice;

#[repr(C)]
#[cfg_attr(debug_assertions, derive(Debug))]
pub struct SessionTicket {
    pub(crate) len: u24,
    lifetime: u32,
    age_add: u32,
    nonce_len: u8,
    nonce: *const u8,
    pub(crate) ticket_len: u16,
    ticket: *const u8,
    ext_len: u16,
    extensions: *const c_void,
}

impl SessionTicket {
    pub fn new(lifetime: u32, ticket: &[u8]) -> SessionTicket {
        SessionTicket {
            len: 0,
            lifetime,
            age_add: 0,
            nonce_len: 0,
            nonce: null(),
            ticket_len: ticket.len() as u16,
            ticket: ticket.as_ptr(),
            ext_len: 0,
            extensions: null(),
        }
    }

    pub fn from_reader(reader: &mut Reader, version: Version) -> RlsResult<SessionTicket> {
        let len = reader.read_u24()?;
        let lifetime = reader.read_u32()?;
        let (age_add, nonce_len, nonce) = match version {
            Version::TLS_1_3 => {
                let age_add = reader.read_u32()?;
                let nonce_len = reader.read_u8()?;
                let nonce = reader.read_ptr(nonce_len as usize)?;
                (age_add, nonce_len, nonce)
            }
            _ => (0, 0, null())
        };
        let ticket_len = reader.read_u16()?;
        let ticket = reader.read_ptr(ticket_len as usize)?;
        let (ext_len, extensions) = if version == Version::TLS_1_3 {
            let ext_len = reader.read_u16()?;
            let ptr = reader.read_ptr(ext_len as usize)?;
            (ext_len, ptr)
        } else { (0, null()) };

        Ok(SessionTicket {
            len,
            lifetime,
            age_add,
            nonce_len,
            nonce,
            ticket_len,
            ticket,
            ext_len,
            extensions: extensions as *const c_void,
        })
    }

    pub fn len(&self) -> usize {
        9 + self.ticket_len as usize
    }

    pub fn write_to(self, writer: &mut Writer) -> Result<(), BufferError> {
        writer.write_u24((6 + self.ticket_len) as u24)?;
        writer.write_u32(self.lifetime)?;
        writer.write_u16(self.ticket_len)?;
        writer.write_slice(self.ticket())
    }

    pub fn set_ticket(&mut self, value: &[u8]) {
        self.ticket_len = value.len() as u16;
        self.ticket = value.as_ptr();
    }


    pub fn ticket(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.ticket, self.ticket_len as usize) }
    }
}