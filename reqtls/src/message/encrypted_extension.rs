use crate::error::RlsResult;
use crate::message::HandshakeType;
use crate::extend::Extension;
use crate::{u24, BufferError, Reader, Writer, ALPN};

#[derive(Debug)]
pub struct EncryptedExtension<'a> {
    handshake_type: HandshakeType,
    extensions: Vec<Extension<'a>>,
}

impl<'a> EncryptedExtension<'a> {
    pub fn from_reader(ht: HandshakeType, reader: &mut Reader<'a>) -> RlsResult<EncryptedExtension<'a>> {
        reader.read_u24()?;
        let extend_len = reader.read_u16()?;
        Ok(EncryptedExtension {
            handshake_type: ht,
            extensions: Extension::from_reader(reader.read_reader(extend_len as usize)?, true)?,
        })
    }

    pub fn len(&self) -> usize {
        6 + self.extensions.iter().map(|x| x.len(true)).sum::<usize>()
    }

    pub fn write_to(self, writer: &mut Writer) -> Result<(), BufferError> {
        writer.write_u8(self.handshake_type.as_u8())?;
        writer.write_u24(self.len() as u24 - 4)?;
        writer.write_u16(self.len() as u16 - 6)?;
        for extension in self.extensions {
            extension.write_to(writer, true)?
        }
        Ok(())
    }

    pub fn alpn(&self) -> Option<&ALPN> {
        let extend = self.extensions.iter().find(|x| matches!(x, Extension::ApplicationLayerProtocolNegotiation(_)));
        if let Some(extend) = extend && let Some(alps) = extend.alps() {
            alps.values().first()
        } else { None }
    }
}