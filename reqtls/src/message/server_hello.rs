use super::super::message::HandshakeType;
use super::super::version::Version;
use crate::error::RlsResult;
use crate::{u24, BufferError, Reader, Writer};
use std::os::raw::c_void;
use std::ptr::null;
use std::slice;

#[repr(C)]
#[cfg_attr(debug_assertions, derive(Debug))]
pub struct ServerHello {
    pub(crate) len: u24,
    pub(crate) version: Version,
    random: *const u8,
    pub(crate) session_id_len: u8,
    session_id: *const u8,
    pub(crate) cipher_suite: u16,
    pub(crate) compress_method: u8,
    pub(crate) extend_len: u16,
    pub(crate) extensions: *const c_void,
}

impl ServerHello {
    pub fn from_reader(reader: &mut Reader) -> RlsResult<ServerHello> {
        let mut server_hello = ServerHello {
            len: reader.read_u24()?,
            version: Version::new(reader.read_u16()?),
            random: reader.read_ptr(32)?,
            session_id_len: reader.read_u8()?,
            session_id: null(),
            cipher_suite: 0,
            compress_method: 0,
            extend_len: 0,
            extensions: null(),
        };

        server_hello.session_id = reader.read_ptr(server_hello.session_id_len as usize)?;
        server_hello.cipher_suite = reader.read_u16()?;
        server_hello.compress_method = reader.read_u8()?;
        if reader.unread_len() == 0 { return Ok(server_hello); }
        server_hello.extend_len = reader.read_u16()?;
        server_hello.extensions = reader.read_ptr(server_hello.extend_len as usize)? as *const c_void;
        Ok(server_hello)
    }

    pub fn random(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.random, 32) }
    }

    pub fn session_id(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.session_id, self.session_id_len as usize) }
    }
}

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct ServerHelloDone {
    handshake_type: HandshakeType,
    len: u24,
}

impl ServerHelloDone {
    pub fn new() -> ServerHelloDone {
        ServerHelloDone {
            handshake_type: HandshakeType::ServerHelloDone,
            len: 0,
        }
    }

    pub fn from_reader(ht: HandshakeType, reader: &mut Reader<'_>) -> RlsResult<ServerHelloDone> {
        Ok(ServerHelloDone {
            handshake_type: ht,
            len: reader.read_u24()?,
        })
    }

    pub fn len(&self) -> usize {
        4
    }

    pub fn write_to(self, writer: &mut Writer) -> Result<(), BufferError> {
        writer.write_u8(self.handshake_type.into_inner())?;
        writer.write_u24(self.len)
    }
}