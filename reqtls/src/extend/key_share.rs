use crate::buffer::Buf;
use crate::error::RlsResult;
use crate::{BufferError, NamedCurve, Reader, Writer};
#[cfg(debug_assertions)]
use std::fmt::{Debug, Formatter};
use std::ptr::null;
use std::slice;

#[repr(C)]
#[derive(Default, Clone)]
pub struct KeyEntry {
    group: u16,
    key_len: u16,
    key: *const u8,
}

impl KeyEntry {
    pub const X25519: KeyEntry = KeyEntry::new(NamedCurve::X25519);
    pub const fn new(group: NamedCurve) -> KeyEntry {
        KeyEntry {
            group: group.into_inner(),
            key_len: 0,
            key: null(),
        }
    }

    pub fn group(&self) -> NamedCurve {
        NamedCurve::new(self.group)
    }

    pub fn set_key(&mut self, key: Buf) {
        self.key_len = key.len() as u16;
        self.key = key.as_ptr();
    }

    pub fn is_empty(&self) -> bool {
        self.key.is_null()
    }

    pub fn key(&self) -> Buf<'_> {
        Buf::Ref(unsafe { slice::from_raw_parts(self.key, self.key_len as usize) })
    }
}

#[cfg(debug_assertions)]
impl Debug for KeyEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut struct_debug = f.debug_struct("KeyEntry");
        struct_debug.field("group", &NamedCurve::new(self.group));
        struct_debug.field("key_len", &self.key_len);
        struct_debug.field("key", &hex::encode(self.key()));
        struct_debug.finish()
    }
}

unsafe impl Sync for KeyEntry {}
unsafe impl Send for KeyEntry {}

#[derive(Default, Clone)]
#[cfg_attr(debug_assertions, derive(Debug))]
pub struct KeyShare {
    entries: Vec<KeyEntry>,
}


impl KeyShare {
    pub fn new(groups: Vec<NamedCurve>) -> Self {
        KeyShare {
            entries: groups.into_iter().map(KeyEntry::new).collect(),
        }
    }
    pub fn from_reader(mut reader: Reader, server: bool) -> RlsResult<KeyShare> {
        if !server { reader.read_u16()?; }
        let mut entries = Vec::with_capacity(reader.unread_len());
        while reader.unread_len() > 0 {
            let group = reader.read_u16()?;
            if reader.unread_len() == 0 {
                entries.push(KeyEntry::new(NamedCurve::new(group)));
                break;
            }
            let key_len = reader.read_u16()?;
            entries.push(KeyEntry {
                group,
                key_len,
                key: reader.read_ptr(key_len as usize)?,
            });
        }
        Ok(KeyShare {
            entries,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.iter().map(|x| 4 + x.key_len as usize).sum::<usize>() + 2
    }

    pub fn write_to(self, writer: &mut Writer) -> Result<(), BufferError> {
        writer.write_u16(self.len() as u16 - 2)?;
        for entry in self.entries {
            writer.write_u16(entry.group)?;
            writer.write_u16(entry.key_len)?;
            writer.write_slice(entry.key().as_ref())?;
        }
        Ok(())
    }

    pub fn add_entry(&mut self, name_curve: impl Into<NamedCurve>, pub_key: Buf) {
        let entry = KeyEntry {
            group: name_curve.into().as_u16(),
            key_len: pub_key.len() as u16,
            key: pub_key.as_ptr(),
        };
        self.entries.push(entry);
    }

    pub fn key_entry(&self) -> &KeyEntry {
        &self.entries[0]
    }

    pub fn key_entries(&self) -> &[KeyEntry] {
        &self.entries
    }

    pub fn key_entries_mut(&mut self) -> &mut Vec<KeyEntry> {
        &mut self.entries
    }
}

