use std::fmt::{Debug, Formatter};
use crate::error::RlsResult;

pub struct GroupType(u16);

impl GroupType {
    pub fn new(v: u16) -> GroupType {
        GroupType(v)
    }

    pub fn as_bytes(&self) -> [u8; 2] {
        self.0.to_be_bytes()
    }

    pub fn as_u16(&self) -> u16 {
        self.0
    }

    pub fn is_reserved(&self) -> bool {
        GroupKind::from_u16(self.0).is_none()
    }
}

impl Debug for GroupType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match GroupKind::from_u16(self.0) {
            None => f.write_str(&format!("Reserved({})", self.0)),
            Some(kind) => f.write_str(&format!("{:?}", kind))
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone)]
enum GroupKind {
    X25519 = 0x1d,
    X25519MLKEM768 = 0x11ec,
    SECP256r1 = 0x0017,
    SECP384r1 = 0x0018,
    SECP521r1 = 0x0019,
}

impl GroupKind {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x1d => Some(GroupKind::X25519),
            0x11ec => Some(GroupKind::X25519MLKEM768),
            0x0017 => Some(GroupKind::SECP256r1),
            0x0018 => Some(GroupKind::SECP384r1),
            0x0019 => Some(GroupKind::SECP521r1),
            _ => None
        }
    }
}


#[derive(Debug)]
pub struct SupportedGroups {
    len: u16,
    values: Vec<GroupType>,
}

impl SupportedGroups {
    pub fn new() -> SupportedGroups {
        SupportedGroups {
            len: 0,
            values: vec![],
        }
    }
    pub fn from_bytes(bytes: &[u8]) -> RlsResult<SupportedGroups> {
        let mut res = SupportedGroups::new();
        res.len = u16::from_be_bytes([bytes[0], bytes[1]]);
        for chuck in bytes[2..].chunks(2) {
            let v = u16::from_be_bytes(chuck.try_into()?);
            res.values.push(GroupType::new(v));
        }
        Ok(res)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res: Vec<u8> = vec![0, 0];
        for value in &self.values {
            res.extend(value.as_bytes())
        }
        let len = (res.len() - 2) as u16;
        res[0..2].copy_from_slice(len.to_be_bytes().as_slice());
        res
    }

    pub fn add_group(&mut self, group: GroupType) {
        self.values.push(group)
    }

    pub fn values(&self) -> &Vec<GroupType> { &self.values }
}