use std::fmt::{Debug, Formatter};
use crate::dns::error::DNSError;
use crate::{BufferError, Reader, WriteExt};

pub struct Domain<'a>(Vec<&'a str>);

impl<'b, 'a: 'b> Domain<'a> {
    pub fn new(domain: &'a str) -> Self {
        Domain(if domain.is_empty() { vec![] } else { domain.split(".").collect() })
    }

    pub fn from_bytes(reader: &'b mut Reader<'a>) -> Result<Domain<'a>, DNSError> {
        let mut names = Vec::with_capacity(100);
        let mut pos = reader.position();
        while reader.current()? != 0 {
            match reader.current()? >> 6 == 0b11 {
                true => {
                    let read_pos = reader.read_u16()? as usize & 0b0011_1111_1111_1111;
                    if reader.position() - 2 == pos { pos += 2; }
                    reader.set_position(read_pos);
                    // pos += 2;
                }
                _ => {
                    let len = reader.read_u8()? as usize;
                    let item = reader.read_str(len)?;
                    if reader.position() > pos {
                        pos += 1 + item.len();
                    }
                    names.push(item);
                }
            }
        }
        if reader.position() < pos {
            reader.set_position(pos);
        } else { reader.set_position(reader.position() + 1) }
        Ok(Domain(names))
    }

    ///only support dns query
    pub fn write_to<W: WriteExt>(self, writer: &mut W) -> Result<(), BufferError> {
        for item in self.0 {
            writer.write_u8(item.len() as u8)?;
            writer.write_slice(item.as_bytes())?;
        }
        writer.write_u8(00)
    }
}
impl<'a> Debug for Domain<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        for (i, item) in self.0.iter().enumerate() {
            write!(f, "{}", item)?;
            if i < self.0.len() - 1 { write!(f, ".")? }
        }
        Ok(())
    }
}
