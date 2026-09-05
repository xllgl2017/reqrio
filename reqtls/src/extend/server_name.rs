use crate::{BufferError, Writer};

#[derive(Debug, Clone)]
pub enum SNType<'a> {
    HostName(&'a str),
}

impl<'a> SNType<'a> {
    pub const HOST_NAME: u8 = 0x0;

    pub fn len(&self) -> usize {
        match self {
            SNType::HostName(name) => 3 + name.len()
        }
    }

    pub fn write_to(&self, writer: &mut Writer) -> Result<(), BufferError> {
        match self {
            SNType::HostName(name) => {
                writer.write_u8(SNType::HOST_NAME)?;
                writer.write_u16(name.len() as u16)?;
                writer.write_slice(name.as_bytes())?;
            }
        }
        Ok(())
    }
}




