use std::fmt::{Debug, Formatter};

#[derive(Clone, Default)]
pub struct Bytes(Vec<u8>);

impl Bytes {
    pub fn none() -> Bytes {
        Bytes(vec![])
    }

    pub fn new(v: Vec<u8>) -> Self {
        Bytes(v)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    pub fn as_mut(&mut self) -> &mut Vec<u8> {
        self.0.as_mut()
    }

    pub fn to_bytes(self) -> Vec<u8> {
        self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Debug for Bytes {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(&self.0))
    }
}