#[derive(Debug)]
pub struct Iv {
    fix_iv: Vec<u8>,
    explicit: Vec<u8>,
}

impl Iv {
    pub fn new(fix_iv: &[u8], explicit: Vec<u8>) -> Iv {
        Iv {
            fix_iv: fix_iv.to_vec(),
            explicit: explicit.to_vec(),
        }
    }

    pub fn as_array(&self, seq: u64) -> [u8; 12] {
        let mut buf = [0; 12];
        match self.fix_iv.len() {
            4 => {
                buf[0..4].copy_from_slice(&self.fix_iv);
                buf[4..12].copy_from_slice(&self.explicit);
            }
            12 => {
                buf[0..12].copy_from_slice(&self.fix_iv);
            }
            _ => panic!("invalid fix iv length")
        }

        let sbs = seq.to_be_bytes();
        for (i, b) in buf[4..12].iter_mut().enumerate() {
            *b ^= sbs[i];
        }
        buf
    }

    pub fn as_ref(&self) -> [u8; 12] {
        let mut buf = [0; 12];
        if self.fix_iv.len()==12 {
            buf.copy_from_slice(&self.fix_iv);
        }else {
            buf[0..4].copy_from_slice(&self.fix_iv);
            buf[4..12].copy_from_slice(&self.explicit);
        }
        buf
    }

    pub fn set_explicit(&mut self, explicit: Vec<u8>) {
        self.explicit = explicit;
    }
}