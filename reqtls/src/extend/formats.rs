use std::fmt::{Debug, Formatter};
use crate::error::RlsResult;
use crate::{BufferError, Reader, Writer};

#[allow(non_camel_case_types)]
#[derive(Clone, PartialEq, Copy)]
pub struct EcPointFormat(u8);

impl EcPointFormat {
    pub const UNCOMPRESSED: EcPointFormat = EcPointFormat(0x0);
    pub const ANSI_X962_PRIME: EcPointFormat = EcPointFormat(0x1);
    pub const ANSI_X962_CHAR2: EcPointFormat = EcPointFormat(0x2);
    pub const ALL: [EcPointFormat; 3] = [EcPointFormat::UNCOMPRESSED, EcPointFormat::ANSI_X962_PRIME, EcPointFormat::ANSI_X962_CHAR2];

    pub fn spec(&self) -> &str {
        match *self {
            EcPointFormat::UNCOMPRESSED => "UNCOMPRESSED",
            EcPointFormat::ANSI_X962_PRIME => "ANSI_X962_PRIME",
            EcPointFormat::ANSI_X962_CHAR2 => "ANSI_X962_CHAR2",
            _ => "Reserved"
        }
    }
    pub fn into_inner(self) -> u8 {
        self.0
    }

    pub fn new(v: u8) -> EcPointFormat {
        EcPointFormat(v)
    }
}

impl Debug for EcPointFormat {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}(0x{:02x})", self.spec(), self.0)
    }
}

impl From<u8> for EcPointFormat {
    fn from(v: u8) -> EcPointFormat {
        EcPointFormat::new(v)
    }
}

#[derive(Debug, Clone)]
pub struct EcPointFormats {
    formats: Vec<EcPointFormat>,
}

impl EcPointFormats {
    pub fn new(formats: Vec<EcPointFormat>) -> EcPointFormats {
        EcPointFormats {
            formats,
        }
    }

    pub fn random() -> EcPointFormats {
        EcPointFormats::new(vec![EcPointFormat::UNCOMPRESSED])
    }

    pub fn from_reader(mut reader: Reader) -> RlsResult<EcPointFormats> {
        let len = reader.read_u8()?;
        let mut formats = Vec::with_capacity(reader.unread_len());
        for _ in 0..len {
            formats.push(EcPointFormat::new(reader.read_u8()?));
        }
        Ok(EcPointFormats { formats })
    }

    pub fn len(&self) -> usize { self.formats.len() + 1 }

    pub fn write_to(self, writer: &mut Writer) -> Result<(), BufferError> {
        writer.write_u8(self.len() as u8 - 1)?;
        for format in self.formats {
            writer.write_u8(format.into_inner())?;
        }
        Ok(())
    }

    pub fn clear(&mut self) {
        self.formats.clear();
    }

    pub fn add_format(&mut self, format: EcPointFormat) {
        self.formats.push(format);
    }

    pub fn formats(&self) -> &Vec<EcPointFormat> {
        &self.formats
    }
}