use crate::error::RlsResult;
use crate::{BufferError, NamedCurve, Reader, Writer};
use std::fmt::Debug;


#[derive(Debug, Clone)]
pub struct SupportedGroups {
    values: Vec<NamedCurve>,
}

impl SupportedGroups {
    pub fn new(groups: Vec<NamedCurve>) -> SupportedGroups {
        SupportedGroups {
            values: groups
        }
    }
    pub fn from_reader(mut reader: Reader<'_>) -> RlsResult<SupportedGroups> {
        let len = reader.read_u16()?;
        let mut values = Vec::with_capacity(reader.unread_len());
        for _ in (0..len).step_by(2) {
            values.push(NamedCurve::new(reader.read_u16()?))
        }
        Ok(SupportedGroups { values })
    }

    pub fn len(&self) -> usize {
        self.values.len() * 2 + 2
    }

    pub fn write_to(self, writer: &mut Writer) -> Result<(), BufferError> {
        writer.write_u16(self.len() as u16 - 2)?;
        for value in self.values {
            writer.write_u16(value.into_inner())?;
        }
        Ok(())
    }

    pub fn clear(&mut self) {
        self.values.clear();
    }

    pub fn set_values(&mut self, values: Vec<NamedCurve>) {
        self.values = values;
    }
    pub fn add_group(&mut self, group: NamedCurve) {
        self.values.push(group)
    }

    pub fn values_mut(&mut self) -> &mut Vec<NamedCurve> {
        &mut self.values
    }

    pub fn values(&self) -> &Vec<NamedCurve> { &self.values }


    pub fn random() -> SupportedGroups {
        SupportedGroups::new(vec![
            NamedCurve::X25519.into(),
            NamedCurve::SecP256r1.into(),
            NamedCurve::SecP384r1.into(),
            NamedCurve::SecP521r1.into(),
        ])
    }
}