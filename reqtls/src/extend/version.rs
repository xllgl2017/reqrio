use crate::version::VersionKind;
use super::super::version::Version;

#[derive(Debug)]
pub struct Versions {
    len: u8,
    versions: Vec<Version>,
}

impl Versions {
    pub fn new() -> Self {
        Versions {
            len: 0,
            versions: vec![],
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut res = Versions::new();
        res.len = bytes[0];
        let mut index = 1;
        while index < bytes.len() {
            res.versions.push(Version::new(u16::from_be_bytes([bytes[index], bytes[index + 1]])));
            index += 2;
        }
        res
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = vec![0];
        for version in &self.versions {
            res.extend(version.as_bytes());
        }
        res[0] = (res.len() - 1) as u8;
        res
    }

    pub fn remove_tls13(&mut self) {
        let pos = self.versions.iter().position(|x| x.as_u16() == VersionKind::TLS_1_3 as u16);
        if let Some(pos) = pos {
            self.versions.remove(pos);
        }
    }
}
