use crate::*;
#[cfg(debug_assertions)]
use std::fmt::{Debug, Formatter};
use std::ptr::null;
use std::slice;
use std::str::Utf8Error;

#[repr(C)]
#[derive(Default, Clone)]
pub struct ServerName {
    typ: u8,
    len: u16,
    ptr: *const u8,
}

impl ServerName {
    pub const HOSTNAME: ServerName = ServerName { typ: 0, len: 0, ptr: null() };

    pub fn new_sni(sni: &str) -> ServerName {
        ServerName {
            typ: 0,
            len: sni.len() as u16,
            ptr: sni.as_ptr(),
        }
    }

    pub(crate) fn len(&self) -> usize {
        3 + self.len as usize
    }

    pub(crate) fn write_to(&self, writer: &mut Writer) -> Result<(), BufferError> {
        writer.write_u8(self.typ)?;
        writer.write_u16(self.len)?;
        writer.write_slice(unsafe { slice::from_raw_parts(self.ptr, self.len as usize) })
    }

    pub(crate) fn from_reader(reader: &mut Reader) -> Result<ServerName, BufferError> {
        let typ = reader.read_u8()?;
        let len = reader.read_u16()?;
        Ok(ServerName {
            typ,
            len,
            ptr: reader.read_ptr(len as usize)?,
        })
    }

    pub(crate) fn value(&self) -> Result<&str, Utf8Error> {
        unsafe {
            let slice = slice::from_raw_parts(self.ptr, self.len as usize);
            std::str::from_utf8(slice)
        }
    }
}

unsafe impl Sync for ServerName {}
unsafe impl Send for ServerName {}

#[cfg(debug_assertions)]
impl Debug for ServerName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut debug_struct = f.debug_struct("ServerName");
        if self.typ == 0x0 {
            debug_struct.field("type", &"Hostname");
            let hostname = unsafe { slice::from_raw_parts(self.ptr, self.len as usize) };
            debug_struct.field("value", &std::str::from_utf8(hostname).unwrap());
        }
        debug_struct.finish()
    }
}



