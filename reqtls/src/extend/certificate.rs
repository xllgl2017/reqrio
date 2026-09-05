use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use crate::error::RlsResult;
use crate::{BufferError, Reader, WriteExt};

#[derive(PartialEq, Copy, Clone)]
pub struct CompressionMethod(u16);

impl CompressionMethod {
    pub const NULL: CompressionMethod = CompressionMethod(0);
    pub const DEFLATE: CompressionMethod = CompressionMethod(1);
    pub const BROTLI: CompressionMethod = CompressionMethod(2);
    pub const GZIP: CompressionMethod = CompressionMethod(0xFFFF);
    pub const ZSTD: CompressionMethod = CompressionMethod(0xFFFE);
    pub fn new(value: u16) -> CompressionMethod {
        CompressionMethod(value)
    }

    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> CompressionMethod {
        match bytes.as_ref() {
            b"deflate" => CompressionMethod::DEFLATE,
            b"br" => CompressionMethod::BROTLI,
            b"gzip" => CompressionMethod::GZIP,
            b"zstd" => CompressionMethod::ZSTD,
            _ => CompressionMethod::NULL
        }
    }

    pub fn into_inner(self) -> u16 {
        self.0
    }
}


impl Debug for CompressionMethod {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.0 {
            0 => write!(f, "Null(0x{:04x})", self.0),
            1 => write!(f, "Deflate(0x{:04x})", self.0),
            2 => write!(f, "Brotli(0x{:04x})", self.0),
            _ => write!(f, "Reserved(0x{:04x})", self.0),
        }
    }
}

impl Display for CompressionMethod {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            CompressionMethod::DEFLATE => write!(f, "deflate"),
            CompressionMethod::BROTLI => write!(f, "br"),
            CompressionMethod::GZIP => write!(f, "gzip"),
            CompressionMethod::ZSTD => write!(f, "zstd"),
            _ => Err(fmt::Error),
        }
    }
}

impl From<u16> for CompressionMethod {
    fn from(value: u16) -> CompressionMethod {
        CompressionMethod::new(value)
    }
}

#[derive(Debug, Clone)]
pub struct CompressCertificate {
    algorithms: Vec<CompressionMethod>,
}

impl CompressCertificate {
    pub fn new(algorithms: Vec<CompressionMethod>) -> CompressCertificate {
        CompressCertificate {
            algorithms,
        }
    }

    pub fn from_reader(mut reader: Reader<'_>) -> RlsResult<CompressCertificate> {
        let len = reader.read_u8()?;
        let mut methods = Vec::with_capacity(reader.unread_len());
        for _ in (0..len).step_by(2) {
            methods.push(CompressionMethod::new(reader.read_u16()?));
        }
        Ok(CompressCertificate {
            algorithms: methods
        })
    }

    pub fn len(&self) -> usize {
        self.algorithms.len() * 2 + 1
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) -> Result<(), BufferError> {
        writer.write_u8(self.len() as u8 - 1)?;
        for ty in self.algorithms {
            writer.write_u16(ty.0)?;
        }
        Ok(())
    }

    pub fn push(&mut self, ty: CompressionMethod) {
        self.algorithms.push(ty);
    }

    pub fn methods(&self) -> &[CompressionMethod] {
        &self.algorithms
    }
}



