use crate::{Aead, HashType, NamedCurve};

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct HpkeSuite {
    pub(crate) curve: NamedCurve,
    pub(crate) hash: HashType,
    aead: Aead,
    pub(crate) kem_id: u16,
    pub(crate) kdf_id: u16,
    pub(crate) aead_id: u16,
    pub(crate) key_size: usize,
    pub(crate) iv_size: usize,
    pub(crate) exp_size: usize,
}

impl HpkeSuite {
    pub const X25519_AES_128_GCM_SHA256: HpkeSuite = HpkeSuite {
        curve: NamedCurve::X25519,
        hash: HashType::Sha256,
        aead: Aead::AES_128_GCM,
        kem_id: 32,
        kdf_id: 1,
        aead_id: 1,
        key_size: 16,
        iv_size: 12,
        exp_size: 32,
    };

    pub const X25519_CHACHA20_POLY1305_SHA256: HpkeSuite = HpkeSuite {
        curve: NamedCurve::X25519,
        hash: HashType::Sha256,
        aead: Aead::ChaCha20_POLY1305,
        kem_id: 32,
        kdf_id: 1,
        aead_id: 3,
        key_size: 32,
        iv_size: 12,
        exp_size: 32,
    };
    pub const P256_AES_128_GCM_SHA256: HpkeSuite = HpkeSuite {
        curve: NamedCurve::SecP256r1,
        hash: HashType::Sha256,
        aead: Aead::AES_128_GCM,
        kem_id: 16,
        kdf_id: 1,
        aead_id: 1,
        key_size: 16,
        iv_size: 12,
        exp_size: 32,
    };

    pub const P256_AES_128_GCM_SHA512: HpkeSuite = HpkeSuite {
        curve: NamedCurve::SecP256r1,
        hash: HashType::Sha512,
        aead: Aead::AES_128_GCM,
        kem_id: 16,
        kdf_id: 3,
        aead_id: 1,
        key_size: 16,
        iv_size: 12,
        exp_size: 32,
    };

    pub const P256_CHACHA20_POLY1305_SHA256: HpkeSuite = HpkeSuite {
        curve: NamedCurve::SecP256r1,
        hash: HashType::Sha256,
        aead: Aead::ChaCha20_POLY1305,
        kem_id: 16,
        kdf_id: 1,
        aead_id: 3,
        key_size: 32,
        iv_size: 12,
        exp_size: 32,
    };

    pub const P521_AES_256_GCM_SHA512: HpkeSuite = HpkeSuite {
        curve: NamedCurve::SecP521r1,
        hash: HashType::Sha256,
        aead: Aead::AES_256_GCM,
        kem_id: 18,
        kdf_id: 3,
        aead_id: 2,
        key_size: 32,
        iv_size: 12,
        exp_size: 32,
    };

    pub const fn find(kem: u16, kdf: u16, aead: u16) -> &'static HpkeSuite {
        match (kem, kdf, aead) {
            (32, 1, 1) => &HpkeSuite::X25519_AES_128_GCM_SHA256,
            (32, 1, 3) => &HpkeSuite::X25519_CHACHA20_POLY1305_SHA256,
            (16, 1, 1) => &HpkeSuite::P256_AES_128_GCM_SHA256,
            (16, 3, 1) => &HpkeSuite::P256_AES_128_GCM_SHA512,
            (16, 1, 3) => &HpkeSuite::P256_CHACHA20_POLY1305_SHA256,
            (18, 3, 2) => &HpkeSuite::P521_AES_256_GCM_SHA512,
            (_, _, _) => unreachable!()
        }
    }
}