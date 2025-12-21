use crate::error::HlsResult;

#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum PskKeyType {
    PSK_DHE_KE = 0x1
}

impl PskKeyType {
    pub fn from_u8(value: u8) -> Option<PskKeyType> {
        match value {
            0x1 => Some(PskKeyType::PSK_DHE_KE),
            _ => None
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

#[derive(Debug)]
pub struct PskKey {
    len: u8,
    mode: PskKeyType,
}

impl PskKey {
    pub fn new() -> PskKey {
        PskKey {
            len: 0,
            mode: PskKeyType::PSK_DHE_KE,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> HlsResult<Self> {
        let mut res = PskKey::new();
        res.len = bytes[0];
        res.mode = PskKeyType::from_u8(bytes[1]).ok_or("PskKeyType Unknown")?;
        Ok(res)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        vec![1, self.mode.as_u8()]
    }
}