use std::cmp::max;
use crate::extend::Aead;
use crate::hash::HashType;
use crate::Version;
use std::fmt::{Debug, Formatter};

#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
pub enum KeyExchangeAlg {
    NULL = 0,
    ECDHE_ECDSA = 1,
    ECDHE_RSA = 2,
    DHE_DSS = 3,
    DHE_RSA = 4,
    DH_ANON = 5,
    DH_DSS = 6,
    DH_RSA = 7,
    RSA = 8,
    ECC = 9,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct CipherSuite {
    value: u16,
    aead: Aead,
    exchange: KeyExchangeAlg,
    mac: HashType,
    hash: HashType,
    pub(crate) key_size: usize,
    pub(crate) fix_iv_size: usize,
    pub(crate) explict_iv_size: usize,
    pub(crate) trans_iv_len: usize,
    pub(crate) mac_key_size: usize,
    ///3des-8; aes-16
    pub(crate) block_size: usize,
    pub(crate) version: &'static Version,
    spec: &'static str,
}

impl CipherSuite {
    //ecdhe-ecdsa
    pub const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: CipherSuite = CipherSuite {
        value: 0xc02b,
        aead: Aead::AES_128_GCM,
        exchange: KeyExchangeAlg::ECDHE_ECDSA,
        mac: HashType::Sha256,
        hash: HashType::Sha256,
        key_size: 16,
        fix_iv_size: 4,
        explict_iv_size: 8,
        trans_iv_len: 8,
        mac_key_size: 0,
        block_size: 16,
        spec: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        version: &Version::TLS_1_2,

    };
    pub const TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: CipherSuite = CipherSuite {
        value: 0xc02c,
        aead: Aead::AES_256_GCM,
        exchange: KeyExchangeAlg::ECDHE_ECDSA,
        mac: HashType::Sha384,
        hash: HashType::Sha384,
        key_size: 32,
        fix_iv_size: 4,
        explict_iv_size: 8,
        trans_iv_len: 8,
        mac_key_size: 0,
        spec: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        version: &Version::TLS_1_2,
        block_size: 16,
    };
    pub const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: CipherSuite = CipherSuite {
        value: 0xc023,
        aead: Aead::AES_128_CBC_SHA256,
        exchange: KeyExchangeAlg::ECDHE_ECDSA,
        mac: HashType::Sha256,
        hash: HashType::Sha256,
        key_size: 16,
        fix_iv_size: 16,
        explict_iv_size: 0,
        trans_iv_len: 16,
        mac_key_size: 32,
        block_size: 16,
        spec: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        version: &Version::TLS_1_2,
    };
    pub const TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384: CipherSuite = CipherSuite {
        value: 0xc024,
        aead: Aead::AES_256_CBC_SHA384,
        exchange: KeyExchangeAlg::ECDHE_ECDSA,
        mac: HashType::Sha384,
        hash: HashType::Sha384,
        key_size: 32,
        fix_iv_size: 16,
        explict_iv_size: 0,
        trans_iv_len: 16,
        mac_key_size: 48,
        block_size: 16,
        spec: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        version: &Version::TLS_1_2,
    };
    pub const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: CipherSuite = CipherSuite {
        value: 0xc009,
        aead: Aead::AES_128_CBC_SHA,
        exchange: KeyExchangeAlg::ECDHE_ECDSA,
        mac: HashType::Sha1,
        hash: HashType::Sha256,
        key_size: 16,
        fix_iv_size: 16,
        explict_iv_size: 0,
        trans_iv_len: 16,
        mac_key_size: 20,
        block_size: 16,
        spec: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        version: &Version::TLS_1_2,
    };
    pub const TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: CipherSuite = CipherSuite {
        value: 0xc00a,
        aead: Aead::AES_256_CBC_SHA,
        exchange: KeyExchangeAlg::ECDHE_ECDSA,
        mac: HashType::Sha1,
        hash: HashType::Sha256,
        key_size: 32,
        fix_iv_size: 16,
        explict_iv_size: 0,
        trans_iv_len: 16,
        mac_key_size: 20,
        block_size: 16,
        spec: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        version: &Version::TLS_1_2,
    };
    pub const TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: CipherSuite = CipherSuite {
        value: 0xcca9,
        aead: Aead::ChaCha20_POLY1305,
        exchange: KeyExchangeAlg::ECDHE_ECDSA,
        mac: HashType::Sha256,
        hash: HashType::Sha256,
        key_size: 32,
        fix_iv_size: 12,
        explict_iv_size: 0,
        trans_iv_len: 0,
        mac_key_size: 0,
        block_size: 0,
        spec: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        version: &Version::TLS_1_2,
    };

    //ecdhe-rsa
    pub const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: CipherSuite = CipherSuite {
        value: 0xc02f,
        aead: Aead::AES_128_GCM,
        exchange: KeyExchangeAlg::ECDHE_RSA,
        mac: HashType::Sha256,
        hash: HashType::Sha256,
        key_size: 16,
        fix_iv_size: 4,
        explict_iv_size: 8,
        trans_iv_len: 8,
        mac_key_size: 0,
        block_size: 16,
        spec: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        version: &Version::TLS_1_2,
    };
    pub const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: CipherSuite = CipherSuite {
        value: 0xc030,
        aead: Aead::AES_256_GCM,
        exchange: KeyExchangeAlg::ECDHE_RSA,
        mac: HashType::Sha384,
        hash: HashType::Sha384,
        key_size: 32,
        fix_iv_size: 4,
        explict_iv_size: 8,
        trans_iv_len: 8,
        mac_key_size: 0,
        block_size: 16,
        spec: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        version: &Version::TLS_1_2,
    };
    pub const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256: CipherSuite = CipherSuite {
        value: 0xc027,
        aead: Aead::AES_128_CBC_SHA256,
        exchange: KeyExchangeAlg::ECDHE_RSA,
        mac: HashType::Sha256,
        hash: HashType::Sha256,
        key_size: 16,
        fix_iv_size: 16,
        explict_iv_size: 0,
        trans_iv_len: 16,
        mac_key_size: 32,
        block_size: 16,
        spec: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        version: &Version::TLS_1_2,
    };
    pub const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384: CipherSuite = CipherSuite {
        value: 0xc028,
        aead: Aead::AES_256_CBC_SHA384,
        exchange: KeyExchangeAlg::ECDHE_RSA,
        mac: HashType::Sha384,
        hash: HashType::Sha384,
        key_size: 32,
        fix_iv_size: 16,
        explict_iv_size: 0,
        trans_iv_len: 16,
        mac_key_size: 48,
        block_size: 16,
        spec: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        version: &Version::TLS_1_2,
    };
    pub const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: CipherSuite = CipherSuite {
        value: 0xc013,
        aead: Aead::AES_128_CBC_SHA,
        exchange: KeyExchangeAlg::ECDHE_RSA,
        mac: HashType::Sha1,
        hash: HashType::Sha256,
        key_size: 16,
        fix_iv_size: 16,
        explict_iv_size: 0,
        trans_iv_len: 16,
        mac_key_size: 20,
        block_size: 16,
        spec: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        version: &Version::TLS_1_2,
    };
    pub const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: CipherSuite = CipherSuite {
        value: 0xc014,
        aead: Aead::AES_256_CBC_SHA,
        exchange: KeyExchangeAlg::ECDHE_RSA,
        mac: HashType::Sha1,
        hash: HashType::Sha256,
        key_size: 32,
        fix_iv_size: 16,
        explict_iv_size: 0,
        trans_iv_len: 16,
        mac_key_size: 20,
        block_size: 16,
        spec: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        version: &Version::TLS_1_2,
    };
    pub const TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: CipherSuite = CipherSuite {
        value: 0xcca8,
        aead: Aead::ChaCha20_POLY1305,
        exchange: KeyExchangeAlg::ECDHE_RSA,
        mac: HashType::Sha256,
        hash: HashType::Sha256,
        key_size: 32,
        fix_iv_size: 12,
        explict_iv_size: 0,
        trans_iv_len: 0,
        mac_key_size: 0,
        block_size: 0,
        spec: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        version: &Version::TLS_1_2,
    };

    //dhe-rsa
    pub const TLS_DHE_RSA_WITH_AES_128_GCM_SHA256: CipherSuite = CipherSuite {
        value: 0x009e,
        aead: Aead::AES_128_GCM,
        exchange: KeyExchangeAlg::DHE_RSA,
        mac: HashType::Sha256,
        hash: HashType::Sha256,
        key_size: 16,
        fix_iv_size: 4,
        explict_iv_size: 8,
        trans_iv_len: 8,
        mac_key_size: 0,
        block_size: 16,
        spec: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        version: &Version::TLS_1_2,
    };
    pub const TLS_DHE_RSA_WITH_AES_256_GCM_SHA384: CipherSuite = CipherSuite {
        value: 0x009f,
        aead: Aead::AES_256_GCM,
        exchange: KeyExchangeAlg::DHE_RSA,
        mac: HashType::Sha384,
        hash: HashType::Sha384,
        key_size: 32,
        fix_iv_size: 4,
        explict_iv_size: 8,
        trans_iv_len: 8,
        mac_key_size: 0,
        block_size: 16,
        spec: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        version: &Version::TLS_1_2,
    };
    pub const TLS_DHE_RSA_WITH_AES_128_CBC_SHA256: CipherSuite = CipherSuite {
        value: 0x0067,
        aead: Aead::AES_128_CBC_SHA256,
        exchange: KeyExchangeAlg::DHE_RSA,
        mac: HashType::Sha256,
        hash: HashType::Sha256,
        key_size: 16,
        fix_iv_size: 16,
        explict_iv_size: 0,
        trans_iv_len: 16,
        mac_key_size: 32,
        block_size: 16,
        spec: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
        version: &Version::TLS_1_2,
    };
    pub const TLS_DHE_RSA_WITH_AES_256_CBC_SHA256: CipherSuite = CipherSuite {
        value: 0x006b,
        aead: Aead::AES_256_CBC_SHA256,
        exchange: KeyExchangeAlg::DHE_RSA,
        mac: HashType::Sha256,
        hash: HashType::Sha256,
        key_size: 32,
        fix_iv_size: 16,
        explict_iv_size: 0,
        trans_iv_len: 16,
        mac_key_size: 32,
        block_size: 16,
        spec: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
        version: &Version::TLS_1_2,
    };
    pub const TLS_DHE_RSA_WITH_AES_128_CBC_SHA: CipherSuite = CipherSuite {
        value: 0x0033,
        aead: Aead::AES_128_CBC_SHA,
        exchange: KeyExchangeAlg::DHE_RSA,
        mac: HashType::Sha1,
        hash: HashType::Sha256,
        key_size: 16,
        fix_iv_size: 16,
        explict_iv_size: 0,
        trans_iv_len: 16,
        mac_key_size: 20,
        block_size: 16,
        spec: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        version: &Version::TLS_1_2,
    };
    pub const TLS_DHE_RSA_WITH_AES_256_CBC_SHA: CipherSuite = CipherSuite {
        value: 0x0039,
        aead: Aead::AES_256_CBC_SHA,
        exchange: KeyExchangeAlg::DHE_RSA,
        mac: HashType::Sha1,
        hash: HashType::Sha256,
        key_size: 32,
        fix_iv_size: 16,
        explict_iv_size: 0,
        trans_iv_len: 16,
        mac_key_size: 20,
        block_size: 16,
        spec: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        version: &Version::TLS_1_2,
    };
    pub const TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256: CipherSuite = CipherSuite {
        value: 0xccaa,
        aead: Aead::ChaCha20_POLY1305,
        exchange: KeyExchangeAlg::DHE_RSA,
        mac: HashType::Sha256,
        hash: HashType::Sha256,
        key_size: 32,
        fix_iv_size: 12,
        explict_iv_size: 0,
        trans_iv_len: 0,
        mac_key_size: 0,
        block_size: 0,
        spec: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        version: &Version::TLS_1_2,
    };


    //rsa
    pub const TLS_RSA_WITH_AES_128_GCM_SHA256: CipherSuite = CipherSuite {
        value: 0x009c,
        aead: Aead::AES_128_GCM,
        exchange: KeyExchangeAlg::RSA,
        mac: HashType::Sha256,
        hash: HashType::Sha256,
        key_size: 16,
        fix_iv_size: 4,
        explict_iv_size: 8,
        trans_iv_len: 8,
        mac_key_size: 0,
        block_size: 16,
        spec: "TLS_RSA_WITH_AES_128_GCM_SHA256",
        version: &Version::TLS_1_2,
    };
    pub const TLS_RSA_WITH_AES_256_GCM_SHA384: CipherSuite = CipherSuite {
        value: 0x009d,
        aead: Aead::AES_256_GCM,
        exchange: KeyExchangeAlg::RSA,
        mac: HashType::Sha384,
        hash: HashType::Sha384,
        key_size: 32,
        fix_iv_size: 4,
        explict_iv_size: 8,
        trans_iv_len: 8,
        mac_key_size: 0,
        block_size: 16,
        spec: "TLS_RSA_WITH_AES_256_GCM_SHA384",
        version: &Version::TLS_1_2,
    };
    pub const TLS_RSA_WITH_AES_128_CBC_SHA256: CipherSuite = CipherSuite {
        value: 0x003c,
        aead: Aead::AES_128_CBC_SHA256,
        exchange: KeyExchangeAlg::RSA,
        mac: HashType::Sha256,
        hash: HashType::Sha256,
        key_size: 16,
        fix_iv_size: 16,
        explict_iv_size: 0,
        trans_iv_len: 16,
        mac_key_size: 32,
        block_size: 16,
        spec: "TLS_RSA_WITH_AES_128_CBC_SHA256",
        version: &Version::TLS_1_2,
    };
    pub const TLS_RSA_WITH_AES_256_CBC_SHA256: CipherSuite = CipherSuite {
        value: 0x003d,
        aead: Aead::AES_256_CBC_SHA256,
        exchange: KeyExchangeAlg::RSA,
        mac: HashType::Sha256,
        hash: HashType::Sha256,
        key_size: 32,
        fix_iv_size: 16,
        explict_iv_size: 0,
        trans_iv_len: 16,
        mac_key_size: 32,
        block_size: 16,
        spec: "TLS_RSA_WITH_AES_256_CBC_SHA256",
        version: &Version::TLS_1_2,
    };
    pub const TLS_RSA_WITH_AES_128_CBC_SHA: CipherSuite = CipherSuite {
        value: 0x002f,
        aead: Aead::AES_128_CBC_SHA,
        exchange: KeyExchangeAlg::RSA,
        mac: HashType::Sha1,
        hash: HashType::Sha256,
        key_size: 16,
        fix_iv_size: 16,
        explict_iv_size: 0,
        trans_iv_len: 16,
        mac_key_size: 20,
        block_size: 16,
        spec: "TLS_RSA_WITH_AES_128_CBC_SHA",
        version: &Version::TLS_1_2,
    };
    pub const TLS_RSA_WITH_AES_256_CBC_SHA: CipherSuite = CipherSuite {
        value: 0x0035,
        aead: Aead::AES_256_CBC_SHA,
        exchange: KeyExchangeAlg::RSA,
        mac: HashType::Sha1,
        hash: HashType::Sha256,
        key_size: 32,
        fix_iv_size: 16,
        explict_iv_size: 0,
        trans_iv_len: 16,
        mac_key_size: 20,
        block_size: 16,
        spec: "TLS_RSA_WITH_AES_256_CBC_SHA",
        version: &Version::TLS_1_2,
    };

    //tls1.3
    pub const TLS_AES_128_GCM_SHA256: CipherSuite = CipherSuite {
        value: 0x1301,
        aead: Aead::AES_128_GCM,
        exchange: KeyExchangeAlg::NULL,
        mac: HashType::Sha256,
        hash: HashType::Sha256,
        key_size: 16,
        fix_iv_size: 12,
        explict_iv_size: 0,
        trans_iv_len: 0,
        mac_key_size: 0,
        block_size: 16,
        spec: "TLS_AES_128_GCM_SHA256",
        version: &Version::TLS_1_3,
    };
    pub const TLS_AES_256_GCM_SHA384: CipherSuite = CipherSuite {
        value: 0x1302,
        aead: Aead::AES_256_GCM,
        exchange: KeyExchangeAlg::NULL,
        mac: HashType::Sha384,
        hash: HashType::Sha384,
        key_size: 32,
        fix_iv_size: 12,
        explict_iv_size: 0,
        trans_iv_len: 0,
        mac_key_size: 0,
        block_size: 16,
        spec: "TLS_AES_256_GCM_SHA384",
        version: &Version::TLS_1_3,
    };
    pub const TLS_CHACHA20_POLY1305_SHA256: CipherSuite = CipherSuite {
        value: 0x1303,
        aead: Aead::ChaCha20_POLY1305,
        exchange: KeyExchangeAlg::NULL,
        mac: HashType::Sha256,
        hash: HashType::Sha256,
        key_size: 32,
        fix_iv_size: 12,
        explict_iv_size: 0,
        trans_iv_len: 0,
        mac_key_size: 0,
        block_size: 0,
        spec: "TLS_CHACHA20_POLY1305_SHA256",
        version: &Version::TLS_1_3,
    };

    pub const TLS_SM4_GCM_SM3: CipherSuite = CipherSuite {
        value: 0x00c6,
        aead: Aead::SM4_GCM,
        exchange: KeyExchangeAlg::NULL,
        mac: HashType::Sm3,
        hash: HashType::Sm3,
        key_size: 16,
        fix_iv_size: 12,
        explict_iv_size: 0,
        trans_iv_len: 0,
        mac_key_size: 0,
        block_size: 16,
        version: &Version::TLS_1_3,
        spec: "TLS_SM4_GCM_SM3",
    };

    pub const ECC_SM4_CBC_SM3: CipherSuite = CipherSuite {
        value: 0xe013,
        aead: Aead::SM4_CBC_SM3,
        exchange: KeyExchangeAlg::ECC,
        mac: HashType::Sm3,
        hash: HashType::Sm3,
        key_size: 16,
        fix_iv_size: 16,
        explict_iv_size: 0,
        trans_iv_len: 16,
        mac_key_size: 32,
        block_size: 16,
        version: &Version::TLCP,
        spec: "ECC_SM4_CBC_SM3",
    };

    pub const TLS_EMPTY_RENEGOTIATION_INFO_SCSV: CipherSuite = CipherSuite {
        value: 0x00ff,
        aead: Aead::AES_128_CBC_SHA,
        exchange: KeyExchangeAlg::ECDHE_ECDSA,
        mac: HashType::MD5,
        hash: HashType::MD5,
        key_size: 0,
        fix_iv_size: 0,
        explict_iv_size: 0,
        trans_iv_len: 0,
        mac_key_size: 0,
        block_size: 16,
        spec: "",
        version: &Version::TLS_1_0,
    };

    pub(crate) const UNKNOWN: CipherSuite = CipherSuite {
        value: 0,
        aead: Aead::AES_128_CBC_SHA,
        exchange: KeyExchangeAlg::NULL,
        mac: HashType::MD5,
        hash: HashType::MD5,
        key_size: 0,
        fix_iv_size: 0,
        explict_iv_size: 0,
        trans_iv_len: 0,
        mac_key_size: 0,
        block_size: 0,
        spec: "",
        version: &Version::TLS_1_0,
    };

    pub const ALL: [CipherSuite; 32] = [
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,

        //ecdhe-rsa
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,

        //dhe-rsa
        CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite::TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
        CipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
        CipherSuite::TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
        CipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
        CipherSuite::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,


        //rsa
        CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA256,
        CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA256,
        CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
        CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA,

        //empty
        CipherSuite::TLS_AES_128_GCM_SHA256,
        CipherSuite::TLS_AES_256_GCM_SHA384,
        CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
        CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
        CipherSuite::ECC_SM4_CBC_SM3
    ];

    pub fn spec(&self) -> &str {
        self.spec
    }

    pub fn exchange_alg(&self) -> KeyExchangeAlg {
        self.exchange
    }

    pub fn mac_hash(&self) -> HashType {
        self.mac
    }

    pub fn aead(&self) -> &Aead {
        &self.aead
    }

    pub fn hash(&self) -> HashType {
        self.hash
    }
}

impl PartialEq for CipherSuite {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl PartialEq<CipherSuite> for &CipherSuite {
    fn eq(&self, other: &CipherSuite) -> bool {
        self.value == other.value
    }
}
impl From<u16> for CipherSuite {
    fn from(value: u16) -> Self {
        let suite = CipherSuite::ALL.into_iter().find(|x| x.value == value);
        if let Some(suite) = suite {
            suite
        } else {
            let mut suite = CipherSuite::UNKNOWN;
            suite.value = value;
            suite.spec = if crate::REVERSED.contains(&suite.value) { "Reversed" } else { "Custom" };
            suite
        }
    }
}

impl Debug for CipherSuite {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}(0x{:04x})", self.spec, self.value)
    }
}

impl CipherSuite {
    pub fn find(v: u16) -> Option<&'static CipherSuite> {
        Self::ALL.as_ref().iter().find(|suite| suite.value == v)
    }

    pub fn is_reserved(&self) -> bool {
        crate::REVERSED.contains(&self.value)
    }

    pub fn into_inner(self) -> u16 { self.value }

    pub fn value(&self) -> u16 {
        self.value
    }

    pub fn tag_len(&self, pd_len: usize) -> usize {
        let pad_len = self.block_size - ((pd_len + self.mac.hash_size()) & (max(self.block_size, 1) - 1));
        match self.aead {
            Aead::AES_128_GCM |
            Aead::AES_256_GCM |
            Aead::ChaCha20_POLY1305 => 16,
            Aead::AES_128_CBC_SHA |
            Aead::AES_128_CBC_SHA256 |
            Aead::AES_256_CBC_SHA |
            Aead::AES_256_CBC_SHA256 |
            Aead::AES_256_CBC_SHA384 |
            Aead::SM4_CBC_SM3 => self.mac.hash_size() + pad_len,
            _ => unreachable!()
        }
    }
}


#[cfg(test)]
mod tests {
    use crate::CipherSuite;

    #[test]
    fn test_cipher_suite() {
        let suite = CipherSuite::from(0xc02b);
        assert_eq!(suite, CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
    }
}