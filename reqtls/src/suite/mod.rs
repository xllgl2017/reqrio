use crate::extend::Aead;
use crate::hash::HashType;
use crate::{CipherType, Version};
pub use cipher::TlsCipher;
use std::fmt::{Debug, Formatter};

pub mod iv;
mod cipher;

#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
pub enum KeyExchangeAlg {
    NULL,
    ECDHE_ECDSA,
    ECDHE_RSA,
    DHE_DSS,
    DHE_RSA,
    DH_ANON,
    DH_DSS,
    DH_RSA,
    RSA,
    ECC,
}

#[derive(Copy, Clone)]
pub struct CipherSuite {
    value: u16,
    cipher: CipherType,
    exchange: KeyExchangeAlg,
    mac: HashType,
    hash: HashType,
    pub(crate) key_size: usize,
    pub(crate) fix_iv_size: usize,
    pub(crate) explict_iv_size: usize,
    pub(crate) trans_iv_len: usize,
    pub(crate) mac_key_size: usize,
    pub(crate) version: &'static Version,
    spec: &'static str,
}

impl CipherSuite {
    //ecdhe-ecdsa
    pub const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: CipherSuite = CipherSuite {
        value: 0xc02b,
        cipher: CipherType::AES_128_GCM,
        exchange: KeyExchangeAlg::ECDHE_ECDSA,
        mac: HashType::Sha256,
        hash: HashType::Sha256,
        key_size: 16,
        fix_iv_size: 4,
        explict_iv_size: 8,
        trans_iv_len: 8,
        mac_key_size: 0,
        spec: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        version: &Version::TLS_1_2,
    };
    pub const TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: CipherSuite = CipherSuite {
        value: 0xc02c,
        cipher: CipherType::AES_256_GCM,
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
    };
    pub const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: CipherSuite = CipherSuite {
        value: 0xc023,
        cipher: CipherType::AES_128_CBC,
        exchange: KeyExchangeAlg::ECDHE_ECDSA,
        mac: HashType::Sha256,
        hash: HashType::Sha256,
        key_size: 16,
        fix_iv_size: 16,
        explict_iv_size: 0,
        trans_iv_len: 16,
        mac_key_size: 32,
        spec: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        version: &Version::TLS_1_2,
    };
    pub const TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384: CipherSuite = CipherSuite {
        value: 0xc024,
        cipher: CipherType::AES_256_CBC,
        exchange: KeyExchangeAlg::ECDHE_ECDSA,
        mac: HashType::Sha384,
        hash: HashType::Sha384,
        key_size: 32,
        fix_iv_size: 16,
        explict_iv_size: 0,
        trans_iv_len: 16,
        mac_key_size: 48,
        spec: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        version: &Version::TLS_1_2,
    };
    pub const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: CipherSuite = CipherSuite {
        value: 0xc009,
        cipher: CipherType::AES_128_CBC,
        exchange: KeyExchangeAlg::ECDHE_ECDSA,
        mac: HashType::Sha1,
        hash: HashType::Sha256,
        key_size: 16,
        fix_iv_size: 16,
        explict_iv_size: 0,
        trans_iv_len: 16,
        mac_key_size: 20,
        spec: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        version: &Version::TLS_1_2,
    };
    pub const TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: CipherSuite = CipherSuite {
        value: 0xc00a,
        cipher: CipherType::AES_256_CBC,
        exchange: KeyExchangeAlg::ECDHE_ECDSA,
        mac: HashType::Sha1,
        hash: HashType::Sha256,
        key_size: 32,
        fix_iv_size: 16,
        explict_iv_size: 0,
        trans_iv_len: 16,
        mac_key_size: 20,
        spec: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        version: &Version::TLS_1_2,
    };
    pub const TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: CipherSuite = CipherSuite {
        value: 0xcca9,
        cipher: CipherType::CHACHA20_POLY1305,
        exchange: KeyExchangeAlg::ECDHE_ECDSA,
        mac: HashType::Sha256,
        hash: HashType::Sha256,
        key_size: 32,
        fix_iv_size: 12,
        explict_iv_size: 0,
        trans_iv_len: 0,
        mac_key_size: 0,
        spec: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        version: &Version::TLS_1_2,
    };

    //ecdhe-rsa
    pub const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: CipherSuite = CipherSuite {
        value: 0xc02f,
        cipher: CipherType::AES_128_GCM,
        exchange: KeyExchangeAlg::ECDHE_RSA,
        mac: HashType::Sha256,
        hash: HashType::Sha256,
        key_size: 16,
        fix_iv_size: 4,
        explict_iv_size: 8,
        trans_iv_len: 8,
        mac_key_size: 0,
        spec: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        version: &Version::TLS_1_2,
    };
    pub const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: CipherSuite = CipherSuite {
        value: 0xc030,
        cipher: CipherType::AES_256_GCM,
        exchange: KeyExchangeAlg::ECDHE_RSA,
        mac: HashType::Sha384,
        hash: HashType::Sha384,
        key_size: 32,
        fix_iv_size: 4,
        explict_iv_size: 8,
        trans_iv_len: 8,
        mac_key_size: 0,
        spec: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        version: &Version::TLS_1_2,
    };
    pub const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256: CipherSuite = CipherSuite {
        value: 0xc027,
        cipher: CipherType::AES_128_CBC,
        exchange: KeyExchangeAlg::ECDHE_RSA,
        mac: HashType::Sha256,
        hash: HashType::Sha256,
        key_size: 16,
        fix_iv_size: 16,
        explict_iv_size: 0,
        trans_iv_len: 16,
        mac_key_size: 32,
        spec: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        version: &Version::TLS_1_2,
    };
    pub const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384: CipherSuite = CipherSuite {
        value: 0xc028,
        cipher: CipherType::AES_256_CBC,
        exchange: KeyExchangeAlg::ECDHE_RSA,
        mac: HashType::Sha384,
        hash: HashType::Sha384,
        key_size: 32,
        fix_iv_size: 16,
        explict_iv_size: 0,
        trans_iv_len: 16,
        mac_key_size: 48,
        spec: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        version: &Version::TLS_1_2,
    };
    pub const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: CipherSuite = CipherSuite {
        value: 0xc013,
        cipher: CipherType::AES_128_CBC,
        exchange: KeyExchangeAlg::ECDHE_RSA,
        mac: HashType::Sha1,
        hash: HashType::Sha256,
        key_size: 16,
        fix_iv_size: 16,
        explict_iv_size: 0,
        trans_iv_len: 16,
        mac_key_size: 20,
        spec: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        version: &Version::TLS_1_2,
    };
    pub const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: CipherSuite = CipherSuite {
        value: 0xc014,
        cipher: CipherType::AES_256_CBC,
        exchange: KeyExchangeAlg::ECDHE_RSA,
        mac: HashType::Sha1,
        hash: HashType::Sha256,
        key_size: 32,
        fix_iv_size: 16,
        explict_iv_size: 0,
        trans_iv_len: 16,
        mac_key_size: 20,
        spec: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        version: &Version::TLS_1_2,
    };
    pub const TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: CipherSuite = CipherSuite {
        value: 0xcca8,
        cipher: CipherType::CHACHA20_POLY1305,
        exchange: KeyExchangeAlg::ECDHE_RSA,
        mac: HashType::Sha256,
        hash: HashType::Sha256,
        key_size: 32,
        fix_iv_size: 12,
        explict_iv_size: 0,
        trans_iv_len: 0,
        mac_key_size: 0,
        spec: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        version: &Version::TLS_1_2,
    };

    //dhe-rsa
    pub const TLS_DHE_RSA_WITH_AES_128_GCM_SHA256: CipherSuite = CipherSuite {
        value: 0x009e,
        cipher: CipherType::AES_128_GCM,
        exchange: KeyExchangeAlg::DHE_RSA,
        mac: HashType::Sha256,
        hash: HashType::Sha256,
        key_size: 16,
        fix_iv_size: 4,
        explict_iv_size: 8,
        trans_iv_len: 8,
        mac_key_size: 0,
        spec: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        version: &Version::TLS_1_2,
    };
    pub const TLS_DHE_RSA_WITH_AES_256_GCM_SHA384: CipherSuite = CipherSuite {
        value: 0x009f,
        cipher: CipherType::AES_256_GCM,
        exchange: KeyExchangeAlg::DHE_RSA,
        mac: HashType::Sha384,
        hash: HashType::Sha384,
        key_size: 32,
        fix_iv_size: 4,
        explict_iv_size: 8,
        trans_iv_len: 8,
        mac_key_size: 0,
        spec: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        version: &Version::TLS_1_2,
    };
    pub const TLS_DHE_RSA_WITH_AES_128_CBC_SHA256: CipherSuite = CipherSuite {
        value: 0x0067,
        cipher: CipherType::AES_128_CBC,
        exchange: KeyExchangeAlg::DHE_RSA,
        mac: HashType::Sha256,
        hash: HashType::Sha256,
        key_size: 16,
        fix_iv_size: 16,
        explict_iv_size: 0,
        trans_iv_len: 16,
        mac_key_size: 32,
        spec: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
        version: &Version::TLS_1_2,
    };
    pub const TLS_DHE_RSA_WITH_AES_256_CBC_SHA256: CipherSuite = CipherSuite {
        value: 0x006b,
        cipher: CipherType::AES_256_CBC,
        exchange: KeyExchangeAlg::DHE_RSA,
        mac: HashType::Sha256,
        hash: HashType::Sha256,
        key_size: 32,
        fix_iv_size: 16,
        explict_iv_size: 0,
        trans_iv_len: 16,
        mac_key_size: 32,
        spec: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
        version: &Version::TLS_1_2,
    };
    pub const TLS_DHE_RSA_WITH_AES_128_CBC_SHA: CipherSuite = CipherSuite {
        value: 0x0033,
        cipher: CipherType::AES_128_CBC,
        exchange: KeyExchangeAlg::DHE_RSA,
        mac: HashType::Sha1,
        hash: HashType::Sha256,
        key_size: 16,
        fix_iv_size: 16,
        explict_iv_size: 0,
        trans_iv_len: 16,
        mac_key_size: 20,
        spec: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        version: &Version::TLS_1_2,
    };
    pub const TLS_DHE_RSA_WITH_AES_256_CBC_SHA: CipherSuite = CipherSuite {
        value: 0x0039,
        cipher: CipherType::AES_256_CBC,
        exchange: KeyExchangeAlg::DHE_RSA,
        mac: HashType::Sha1,
        hash: HashType::Sha256,
        key_size: 32,
        fix_iv_size: 16,
        explict_iv_size: 0,
        trans_iv_len: 16,
        mac_key_size: 20,
        spec: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        version: &Version::TLS_1_2,
    };
    pub const TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256: CipherSuite = CipherSuite {
        value: 0xccaa,
        cipher: CipherType::CHACHA20_POLY1305,
        exchange: KeyExchangeAlg::DHE_RSA,
        mac: HashType::Sha256,
        hash: HashType::Sha256,
        key_size: 32,
        fix_iv_size: 12,
        explict_iv_size: 0,
        trans_iv_len: 0,
        mac_key_size: 0,
        spec: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        version: &Version::TLS_1_2,
    };


    //rsa
    pub const TLS_RSA_WITH_AES_128_GCM_SHA256: CipherSuite = CipherSuite {
        value: 0x009c,
        cipher: CipherType::AES_128_GCM,
        exchange: KeyExchangeAlg::RSA,
        mac: HashType::Sha256,
        hash: HashType::Sha256,
        key_size: 16,
        fix_iv_size: 4,
        explict_iv_size: 8,
        trans_iv_len: 8,
        mac_key_size: 0,
        spec: "TLS_RSA_WITH_AES_128_GCM_SHA256",
        version: &Version::TLS_1_2,
    };
    pub const TLS_RSA_WITH_AES_256_GCM_SHA384: CipherSuite = CipherSuite {
        value: 0x009d,
        cipher: CipherType::AES_256_GCM,
        exchange: KeyExchangeAlg::RSA,
        mac: HashType::Sha384,
        hash: HashType::Sha384,
        key_size: 32,
        fix_iv_size: 4,
        explict_iv_size: 8,
        trans_iv_len: 8,
        mac_key_size: 0,
        spec: "TLS_RSA_WITH_AES_256_GCM_SHA384",
        version: &Version::TLS_1_2,
    };
    pub const TLS_RSA_WITH_AES_128_CBC_SHA256: CipherSuite = CipherSuite {
        value: 0x003c,
        cipher: CipherType::AES_128_CBC,
        exchange: KeyExchangeAlg::RSA,
        mac: HashType::Sha256,
        hash: HashType::Sha256,
        key_size: 16,
        fix_iv_size: 16,
        explict_iv_size: 0,
        trans_iv_len: 16,
        mac_key_size: 32,
        spec: "TLS_RSA_WITH_AES_128_CBC_SHA256",
        version: &Version::TLS_1_2,
    };
    pub const TLS_RSA_WITH_AES_256_CBC_SHA256: CipherSuite = CipherSuite {
        value: 0x003d,
        cipher: CipherType::AES_256_CBC,
        exchange: KeyExchangeAlg::RSA,
        mac: HashType::Sha384,
        hash: HashType::Sha384,
        key_size: 32,
        fix_iv_size: 16,
        explict_iv_size: 0,
        trans_iv_len: 16,
        mac_key_size: 32,
        spec: "TLS_RSA_WITH_AES_256_CBC_SHA256",
        version: &Version::TLS_1_2,
    };
    pub const TLS_RSA_WITH_AES_128_CBC_SHA: CipherSuite = CipherSuite {
        value: 0x002f,
        cipher: CipherType::AES_128_CBC,
        exchange: KeyExchangeAlg::RSA,
        mac: HashType::Sha1,
        hash: HashType::Sha256,
        key_size: 16,
        fix_iv_size: 16,
        explict_iv_size: 0,
        trans_iv_len: 16,
        mac_key_size: 20,
        spec: "TLS_RSA_WITH_AES_128_CBC_SHA",
        version: &Version::TLS_1_2,
    };
    pub const TLS_RSA_WITH_AES_256_CBC_SHA: CipherSuite = CipherSuite {
        value: 0x0035,
        cipher: CipherType::AES_256_CBC,
        exchange: KeyExchangeAlg::RSA,
        mac: HashType::Sha1,
        hash: HashType::Sha256,
        key_size: 32,
        fix_iv_size: 16,
        explict_iv_size: 0,
        trans_iv_len: 16,
        mac_key_size: 20,
        spec: "TLS_RSA_WITH_AES_256_CBC_SHA",
        version: &Version::TLS_1_2,
    };

    //tls1.3
    pub const TLS_AES_128_GCM_SHA256: CipherSuite = CipherSuite {
        value: 0x1301,
        cipher: CipherType::AES_128_GCM,
        exchange: KeyExchangeAlg::NULL,
        mac: HashType::Sha256,
        hash: HashType::Sha256,
        key_size: 16,
        fix_iv_size: 12,
        explict_iv_size: 0,
        trans_iv_len: 0,
        mac_key_size: 0,
        spec: "TLS_AES_128_GCM_SHA256",
        version: &Version::TLS_1_3,
    };
    pub const TLS_AES_256_GCM_SHA384: CipherSuite = CipherSuite {
        value: 0x1302,
        cipher: CipherType::AES_256_GCM,
        exchange: KeyExchangeAlg::NULL,
        mac: HashType::Sha384,
        hash: HashType::Sha384,
        key_size: 32,
        fix_iv_size: 12,
        explict_iv_size: 0,
        trans_iv_len: 0,
        mac_key_size: 0,
        spec: "TLS_AES_256_GCM_SHA384",
        version: &Version::TLS_1_3,
    };
    pub const TLS_CHACHA20_POLY1305_SHA256: CipherSuite = CipherSuite {
        value: 0x1303,
        cipher: CipherType::CHACHA20_POLY1305,
        exchange: KeyExchangeAlg::NULL,
        mac: HashType::Sha256,
        hash: HashType::Sha256,
        key_size: 32,
        fix_iv_size: 12,
        explict_iv_size: 0,
        trans_iv_len: 0,
        mac_key_size: 0,
        spec: "TLS_CHACHA20_POLY1305_SHA256",
        version: &Version::TLS_1_3,
    };

    pub const TLS_SM4_GCM_SM3: CipherSuite = CipherSuite {
        value: 0x00c6,
        cipher: CipherType::SM4_GCM,
        exchange: KeyExchangeAlg::NULL,
        mac: HashType::Sm3,
        hash: HashType::Sm3,
        key_size: 16,
        fix_iv_size: 12,
        explict_iv_size: 0,
        trans_iv_len: 0,
        mac_key_size: 0,
        version: &Version::TLS_1_3,
        spec: "TLS_SM4_GCM_SM3",
    };

    pub const ECC_SM4_CBC_SM3: CipherSuite = CipherSuite {
        value: 0xe013,
        cipher: CipherType::SM4_CBC,
        exchange: KeyExchangeAlg::ECC,
        mac: HashType::Sm3,
        hash: HashType::Sm3,
        key_size: 16,
        fix_iv_size: 16,
        explict_iv_size: 0,
        trans_iv_len: 16,
        mac_key_size: 32,
        version: &Version::TLCP,
        spec: "ECC_SM4_CBC_SM3",
    };

    pub const TLS_EMPTY_RENEGOTIATION_INFO_SCSV: CipherSuite = CipherSuite {
        value: 0x00ff,
        cipher: CipherType::AES_128_CBC,
        exchange: KeyExchangeAlg::ECDHE_ECDSA,
        mac: HashType::MD5,
        hash: HashType::MD5,
        key_size: 0,
        fix_iv_size: 0,
        explict_iv_size: 0,
        trans_iv_len: 0,
        mac_key_size: 0,
        spec: "",
        version: &Version::TLS_1_0,
    };

    pub(crate) const UNKNOWN: CipherSuite = CipherSuite {
        value: 0,
        cipher: CipherType::AES_128_CBC,
        exchange: KeyExchangeAlg::NULL,
        mac: HashType::MD5,
        hash: HashType::MD5,
        key_size: 0,
        fix_iv_size: 0,
        explict_iv_size: 0,
        trans_iv_len: 0,
        mac_key_size: 0,
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

    pub fn cipher(&self) -> CipherType {
        self.cipher
    }

    pub fn exchange_alg(&self) -> KeyExchangeAlg {
        self.exchange
    }


    pub fn mac_hash(&self) -> HashType {
        self.mac
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

    pub fn aead(&self) -> Option<Aead> {
        Aead::from_cipher_kind(self.spec())
    }

    pub fn hash(&self) -> HashType {
        self.hash
    }

    pub fn value(&self) -> u16 {
        self.value
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