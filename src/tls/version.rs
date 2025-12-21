use std::fmt::{Debug, Formatter};

#[allow(non_camel_case_types)]
#[derive(Debug, Clone)]
pub enum VersionKind {
    TLS_1_0 = 0x301,
    TLS_1_1 = 0x302,
    TLS_1_2 = 0x303,
    TLS_1_3 = 0x304,
}

impl VersionKind {
    pub fn from_u16(v: u16) -> Option<VersionKind> {
        match v {
            0x301 => Some(VersionKind::TLS_1_0),
            0x302 => Some(VersionKind::TLS_1_1),
            0x303 => Some(VersionKind::TLS_1_2),
            0x304 => Some(VersionKind::TLS_1_3),
            _ => None
        }
    }
}

pub struct Version(u16);

impl Version {
    pub fn new(v: u16) -> Version {
        Version(v)
    }

    pub fn as_bytes(&self) -> [u8; 2] {
        self.0.to_be_bytes()
    }

    pub fn as_u16(&self) -> u16 {
        self.0
    }
}

impl Debug for Version {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match VersionKind::from_u16(self.0) {
            None => f.write_str(&format!("Reserved({})", self.0)),
            Some(kind) => f.write_str(&format!("{:?}", kind))
        }
    }
}