use std::fmt::{Debug, Formatter};
use std::os::raw::c_int;

#[derive(PartialEq)]
pub struct CertType(c_int);
impl CertType {
    pub const RSA: CertType = CertType(1);
    pub const ECDSA: CertType = CertType(64);
    //未知
    pub const ED25519: CertType = CertType(0);


    pub const fn spec(&self) -> &str {
        match *self {
            CertType::RSA => "RSA",
            CertType::ECDSA => "ECDSA",
            _ => "Reserved"
        }
    }
    pub const fn new(v: c_int) -> CertType {
        CertType(v)
    }
}

impl Debug for CertType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}(0x{})", self.spec(), self.0)
    }
}