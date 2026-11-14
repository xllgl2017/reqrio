use std::error::Error;
use crate::Reader;

#[derive(Copy, Clone, Debug)]
pub enum LibType {
    Static = 0,
    Dynamic = 1,
}

impl From<u8> for LibType {
    fn from(value: u8) -> Self {
        match value {
            0 => LibType::Static,
            1 => LibType::Dynamic,
            _ => unreachable!()
        }
    }
}

impl LibType {
    pub fn link(&self) -> &'static str {
        match self {
            LibType::Static => "static",
            LibType::Dynamic => "dylib"
        }
    }
}

#[cfg_attr(debug_assertions, derive(Debug))]
pub enum Frame<'a> {
    GetLib {
        typ: LibType,
        os: &'a str,
        arch: &'a str,
        env: &'a str,
        version: &'a str,
        token: &'a str,
    },
    FileStream {
        filesize: u32,
        filename: &'a str,
    },
    Error {
        code: u16,
        message: &'a str,
    },
}

impl<'a> Frame<'a> {
    const GET_LIB: u8 = 0;
    const FILE_STREAM: u8 = 1;
    const ERROR: u8 = 2;

    pub fn from_reader(mut reader: Reader<'a>) -> Result<Frame<'a>, Box<dyn Error>> {
        let typ = reader.read_u8()?;
        match typ {
            Frame::ERROR => {
                let code = reader.read_u16()?;
                let msg_len = reader.read_u8()? as usize;
                Ok(Frame::Error {
                    code,
                    message: reader.read_str(msg_len)?,
                })
            }
            Frame::FILE_STREAM => {
                let filesize = reader.read_u32()?;
                let filename_len = reader.read_u8()? as usize;
                Ok(Frame::FileStream {
                    filesize,
                    filename: reader.read_str(filename_len)?,
                })
            }
            _ => unreachable!()
        }
    }

    pub fn encode(&self, writer: &mut Vec<u8>) {
        writer.extend((self.len() as u32).to_be_bytes());
        match self {
            Frame::GetLib {
                typ,
                os,
                arch,
                env,
                version,
                token,
            } => {
                writer.push(Self::GET_LIB);
                writer.push(*typ as u8);
                writer.push(os.len() as u8);
                writer.extend_from_slice(os.as_bytes());
                writer.push(arch.len() as u8);
                writer.extend_from_slice(arch.as_bytes());
                writer.push(env.len() as u8);
                writer.extend_from_slice(env.as_bytes());
                writer.push(version.len() as u8);
                writer.extend_from_slice(version.as_bytes());
                writer.push(token.len() as u8);
                writer.extend_from_slice(token.as_bytes());
            }
            _ => unreachable!()
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Frame::GetLib {
                os,
                arch,
                env,
                version,
                token, ..
            } => {
                1 + 1 + 1 + os.len() + 1 + arch.len() + 1 + env.len() + 1 + version.len() + 1 + token.len()
            }
            _ => unreachable!()
        }
    }
}
