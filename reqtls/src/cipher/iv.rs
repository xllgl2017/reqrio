#[derive(Debug)]
pub struct Iv {
    fix_iv: Vec<u8>,
    explicit: Vec<u8>,
}

impl Iv {
    pub fn new(fix_iv: Vec<u8>, explicit: Vec<u8>) -> Iv {
        Iv {
            fix_iv,
            explicit,
        }
    }

    pub fn as_array(&self, seq: u64) -> [u8; 12] {
        let mut buf = [0; 12];
        buf[0..4].copy_from_slice(&self.fix_iv);
        buf[4..12].copy_from_slice(&self.explicit);
        let sbs = seq.to_be_bytes();
        for (i, b) in buf[4..12].iter_mut().enumerate() {
            *b ^= sbs[i];
        }
        buf
    }

    pub fn as_ref(&self) -> [u8; 12] {
        let mut buf = [0; 12];
        buf[0..4].copy_from_slice(&self.fix_iv);
        buf[4..12].copy_from_slice(&self.explicit);
        buf
    }

    pub fn set_explicit(&mut self, explicit: Vec<u8>) {
        self.explicit = explicit;
    }
}