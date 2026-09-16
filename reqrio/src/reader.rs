use crate::error::HlsResult;
use reqtls::Writer;
use std::fmt::{Debug, Formatter};
use std::io::{Cursor, Read};
use std::ops::Deref;

pub struct RefReader<R> {
    bufs: Vec<Cursor<R>>,
    pos: usize,
    wrote: bool,
}

impl<R: AsRef<[u8]>> Default for RefReader<R> {
    fn default() -> Self {
        RefReader {
            bufs: vec![],
            pos: 0,
            wrote: false,
        }
    }
}

impl<'a> RefReader<StrCow<'a>> {
    pub fn add_str(&mut self, s: &'a str) {
        self.bufs.push(Cursor::new(StrCow::Borrowed(s)))
    }

    pub fn add_string(&mut self, s: String) {
        self.bufs.push(Cursor::new(StrCow::Owned(s)))
    }
}

impl<R: AsRef<[u8]>> RefReader<R> {
    pub fn new_buf(buf: R) -> RefReader<R> {
        RefReader {
            bufs: vec![Cursor::new(buf)],
            pos: 0,
            wrote: false,
        }
    }
    pub fn add_buf(&mut self, buf: R) {
        self.bufs.push(Cursor::new(buf));
    }

    pub fn wrote(&self) -> bool {
        self.wrote
    }
}

impl<R: AsRef<[u8]>> ReadExt for RefReader<R> {
    fn wrote(&self) -> bool {
        self.wrote
    }
    fn len(&self) -> usize {
        self.bufs.iter().map(|x| x.get_ref().as_ref().len()).sum()
    }
    fn read(&mut self, buf: &mut Writer) -> HlsResult<usize> {
        let start = buf.offset().end;
        for (index, reader) in self.bufs.iter_mut().enumerate() {
            if index < self.pos {
                continue;
            }
            loop {
                if buf.unfilled().is_empty() {
                    return Ok(buf.offset().end - start);
                }
                let len = reader.read(buf.unfilled())?;
                buf.add_len(len);
                if reader.position() as usize == reader.get_ref().as_ref().len() {
                    self.pos += 1;
                    break;
                }
            }
        }
        self.wrote = true;
        Ok(buf.offset().end - start)
    }
}

pub trait ReadExt {
    fn wrote(&self) -> bool;
    fn len(&self) -> usize;
    fn read(&mut self, buf: &mut Writer) -> HlsResult<usize>;
}

pub enum StrCow<'a> {
    Borrowed(&'a str),
    Owned(String),
}

impl<'a> StrCow<'a> {
    pub fn len(&self) -> usize {
        match self {
            StrCow::Borrowed(b) => b.len(),
            StrCow::Owned(o) => o.len(),
        }
    }
}

impl<'a> AsRef<[u8]> for StrCow<'a> {
    fn as_ref(&self) -> &[u8] {
        match self {
            StrCow::Borrowed(v) => v.as_bytes(),
            StrCow::Owned(o) => o.as_bytes(),
        }
    }
}

impl<'a> AsRef<str> for StrCow<'a> {
    fn as_ref(&self) -> &str {
        match self {
            StrCow::Borrowed(b) => b,
            StrCow::Owned(o) => o.as_str(),
        }
    }
}

impl<'a> Debug for StrCow<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            StrCow::Borrowed(b) => write!(f, "{}", b),
            StrCow::Owned(o) => write!(f, "{}", o),
        }
    }
}

#[derive(Debug)]
pub enum HCow<'a, T> {
    Borrowed(&'a T),
    Owned(T),
}

impl<'a, T> Deref for HCow<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match self {
            HCow::Borrowed(v) => v,
            HCow::Owned(o) => o,
        }
    }
}


impl<'a, T> AsRef<T> for HCow<'a, T> {
    fn as_ref(&self) -> &T {
        match self {
            HCow::Borrowed(v) => v,
            HCow::Owned(o) => o,
        }
    }
}