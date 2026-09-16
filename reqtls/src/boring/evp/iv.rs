use std::borrow::Cow;

#[repr(C)]
pub struct Iv {
    raw: [u8; 16],
    size: usize,
}

impl Iv {
    pub fn new() -> Iv {
        Iv {
            raw: [0; 16],
            size: 0,
        }
    }

    pub fn init(&mut self, iv: &[u8]) {
        self.raw[..iv.len()].copy_from_slice(iv);
        self.size = iv.len();
    }

    pub fn as_array(&self, seq: u64, explicit: Option<&[u8]>) -> Cow<'_, [u8]> {
        let mut buf = self.raw[..self.size].to_vec();
        match self.size {
            12 => if let Some(explicit) = explicit { buf[4..12].copy_from_slice(explicit); },
            16 => return Cow::Borrowed(&self.raw),
            _ => panic!("invalid fix iv length")
        }

        let sbs = seq.to_be_bytes();
        for (i, b) in buf[4..12].iter_mut().enumerate() {
            *b ^= sbs[i];
        }
        buf.truncate(12);
        Cow::Owned(buf)
    }

    pub fn decrypting_iv<'a>(&'a self, explicit: Option<&'a [u8]>) -> Cow<'a, [u8]> {
        match (self.size, explicit) {
            (4 | 12, Some(explicit)) => Cow::Owned([&self.raw[..4], explicit].concat()),
            (16, Some(explicit)) => Cow::Borrowed(explicit),
            (16, None) => Cow::Borrowed(&self.raw),
            _ => panic!("invalid iv length-{}-{:?}", self.size, explicit)
        }
    }
}