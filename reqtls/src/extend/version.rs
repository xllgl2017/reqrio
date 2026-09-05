use super::super::version::Version;
use crate::{BufferError, Reader, Writer};
use crate::error::RlsResult;

#[derive(Debug, Default, Clone)]
pub struct SupportVersions {
    versions: Vec<Version>,
}


impl SupportVersions {
    pub fn new(versions:Vec<Version>) -> Self {
        SupportVersions { versions }
    }
    pub fn from_reader(mut reader: Reader<'_>, server: bool) -> RlsResult<SupportVersions> {
        if !server {
            reader.read_u8()?;
        }
        let mut versions = Vec::with_capacity(reader.unread_len());
        while reader.unread_len() > 0 {
            versions.push(Version::new(reader.read_u16()?));
        }
        Ok(SupportVersions {
            versions,
        })
    }

    pub fn len(&self, server: bool) -> usize {
        if !server { self.versions.len() * 2 + 1 } else { self.versions.len() * 2 }
    }

    pub fn write_to(self, writer: &mut Writer, server: bool) -> Result<(), BufferError> {
        if !server {
            writer.write_u8(self.len(server) as u8 - 1)?;
        }
        for version in self.versions {
            writer.write_u16(version.into_inner())?;
        }
        Ok(())
    }

    pub fn remove_tls13(&mut self) {
        let pos = self.versions.iter().position(|x| x == &Version::TLS_1_3);
        if let Some(pos) = pos {
            self.versions.remove(pos);
        }
    }

    pub fn versions(&self) -> &Vec<Version> { &self.versions }

    pub fn next(self) -> Option<Version> {
        self.versions.into_iter().next()
    }

    pub fn set_versions(&mut self, versions: Vec<Version>) { self.versions = versions }

    pub fn clear(&mut self) {
        self.versions.clear();
    }

    pub fn push(&mut self, version: Version) {
        self.versions.push(version);
    }
}
