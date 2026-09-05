use crate::buffer::Buf;
use crate::{BufferError, NamedCurve, Reader, WriteExt};
use std::fmt::Debug;
use crate::error::RlsResult;

#[derive(Debug, Clone)]
pub struct KeyEntry<'a> {
    group: NamedCurve,
    exchange: Buf<'a>,
}

impl<'a> KeyEntry<'a> {
    fn new(group: NamedCurve) -> Self {
        KeyEntry {
            exchange: if group.is_reserved() { Buf::Ref(&[0]) } else { Buf::Ref(&[]) },
            group,
        }
    }

    fn from_reader(reader: &mut Reader<'a>) -> RlsResult<KeyEntry<'a>> {
        let group = reader.read_u16()?.into();
        if reader.unread_len() == 0 {
            return Ok(KeyEntry {
                group,
                exchange: Buf::Ref(&[]),
            });
        }
        let len = reader.read_u16()?;
        Ok(KeyEntry {
            group,
            exchange: Buf::Ref(reader.read_slice(len as usize)?),
        })
    }

    pub fn len(&self) -> usize {
        4 + self.exchange.len()
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) -> Result<(), BufferError> {
        writer.write_u16(self.group.into_inner())?;
        writer.write_u16(self.exchange.len() as u16)?;
        writer.write_slice(self.exchange.as_ref())
    }

    pub fn name_curve(&self) -> &NamedCurve {
        &self.group
    }

    pub fn exchange_key(&self) -> &Buf<'_> {
        &self.exchange
    }

    pub fn set_exchange_key(&mut self, exchange: Buf<'a>) {
        self.exchange = exchange;
    }
}

#[derive(Debug, Default, Clone)]
pub struct KeyShare<'a> {
    entries: Vec<KeyEntry<'a>>,
}


impl<'a> KeyShare<'a> {
    pub fn new(groups: Vec<NamedCurve>) -> Self {
        KeyShare {
            entries: groups.into_iter().map(KeyEntry::new).collect(),
        }
    }
    pub fn from_reader(mut reader: Reader<'a>, server: bool) -> RlsResult<KeyShare<'a>> {
        if !server { reader.read_u16()?; }
        let mut entries = Vec::with_capacity(reader.unread_len());
        while reader.unread_len() > 0 {
            entries.push(KeyEntry::from_reader(&mut reader)?);
        }
        Ok(KeyShare {
            entries,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.iter().map(|x| x.len()).sum::<usize>() + 2
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) -> Result<(), BufferError> {
        writer.write_u16(self.len() as u16 - 2)?;
        for entry in self.entries {
            entry.write_to(writer)?;
        }
        Ok(())
    }

    pub fn add_entry(&mut self, name_curve: impl Into<NamedCurve>, pub_key: Buf<'a>) {
        let entry = KeyEntry {
            group: name_curve.into(),
            exchange: pub_key,
        };
        self.entries.push(entry);
    }

    pub fn key_entry(&self) -> &KeyEntry<'_> {
        &self.entries[0]
    }

    pub fn key_entries(&self) -> &[KeyEntry<'_>] {
        &self.entries
    }

    pub fn key_entries_mut(&mut self) -> &mut Vec<KeyEntry<'a>> {
        &mut self.entries
    }
}

