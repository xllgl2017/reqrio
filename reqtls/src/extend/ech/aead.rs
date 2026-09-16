#[derive(Debug, Clone, Copy)]
#[allow(non_camel_case_types)]
#[repr(C)]
pub enum Aead {
    AES_128_GCM = 0x1,
    AES_256_GCM = 0x2,
    ChaCha20_POLY1305 = 0x3,
    AES_128_CCM = 0x4,
    AES_128_CCM_8 = 0x5,
    AES_128_CBC_SHA = 0xFF,
    AES_128_CBC_SHA256 = 0xFE,
    AES_256_CBC_SHA = 0xFD,
    AES_256_CBC_SHA256 = 0xFC,
    AES_256_CBC_SHA384 = 0xFB,
    SM4_GCM = 0xFA,
    SM4_CBC_SM3 = 0xF9,
}

impl Aead {
    pub(crate) fn from_u16(v: u16) -> Option<Aead> {
        match v {
            0x01 => Some(Aead::AES_128_GCM),
            0x02 => Some(Aead::AES_256_GCM),
            0x03 => Some(Aead::ChaCha20_POLY1305),
            0x04 => Some(Aead::AES_128_CCM),
            0x05 => Some(Aead::AES_128_CCM_8),
            _ => None
        }
    }

    // pub(crate) fn is_cbc(&self) -> bool {
    //     match self {
    //         Aead::AES_128_GCM |
    //         Aead::AES_256_GCM |
    //         Aead::ChaCha20_POLY1305 |
    //         Aead::AES_128_CCM |
    //         Aead::AES_128_CCM_8 |
    //         Aead::SM4_GCM => false,
    //         Aead::AES_128_CBC_SHA |
    //         Aead::AES_128_CBC_SHA256 |
    //         Aead::AES_256_CBC_SHA |
    //         Aead::AES_256_CBC_SHA256 |
    //         Aead::AES_256_CBC_SHA384 |
    //         Aead::SM4_CBC_SM3 => true,
    //     }
    // }
}