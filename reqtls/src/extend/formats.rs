use crate::error::RlsResult;

#[allow(non_camel_case_types)]
#[derive(Debug, Clone)]
pub enum EcPointFormat {
    UNCOMPRESSED = 0x0,
    ANSI_X962_PRIME = 0x1,
    ANSI_X962_CHAR2 = 0x2,
}

impl EcPointFormat {
    pub fn from_u8(v: u8) -> Option<EcPointFormat> {
        match v {
            0x0 => Some(EcPointFormat::UNCOMPRESSED),
            0x1 => Some(EcPointFormat::ANSI_X962_PRIME),
            0x2 => Some(EcPointFormat::ANSI_X962_CHAR2),
            _ => None,
        }
    }

    pub fn as_u8(&self) -> u8 {
        self.clone() as u8
    }
}

#[derive(Debug)]
pub struct EcPointFormats {
    len: u8,
    formats: Vec<EcPointFormat>,
}

impl EcPointFormats {
    pub fn new() -> EcPointFormats {
        EcPointFormats {
            len: 0,
            formats: vec![],
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> RlsResult<EcPointFormats> {
        let mut res = EcPointFormats::new();
        res.len = bytes[0];
        for v in &bytes[1..] {
            res.formats.push(EcPointFormat::from_u8(*v).ok_or("EcPointFormat Unknown")?);
        }
        Ok(res)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = vec![0];
        for format in &self.formats {
            res.push(format.as_u8());
        }
        res[0] = (res.len() - 1) as u8;
        res
    }

    pub fn add_format(&mut self, format: EcPointFormat) {
        self.formats.push(format);
    }

    pub fn formats(&self) -> &Vec<EcPointFormat> {
        &self.formats
    }
}