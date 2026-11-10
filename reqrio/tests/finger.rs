#![allow(unused)]
use std::{env, fs};
use std::sync::LazyLock;
use reqrio::{Fingerprint, H2Finger};
use reqtls::*;

pub const JA3: &str = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,18-45-5-10-11-16-23-27-0-13-35-65281-43-51-17613,29-23-24,0";
pub const JA4: &str = "t13d1515h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,ff01_0804,0403,0401,0303,0402,080b,0201,0203,0202,0302,0502,0301,0503,0602,0806,0809";
pub static TOKEN: LazyLock<String> = LazyLock::new(|| fs::read_to_string("../TOKEN").unwrap_or(env::var("REQRIO_TOKEN").unwrap_or("".to_string())));


pub fn build_finger(
    suites: Vec<CipherSuite>,
    groups: Vec<NamedCurve>,
    sig_algs: Vec<SignatureAlgorithm>,
    alps: Vec<ALPN>,
    versions: Vec<Version>,
) -> Fingerprint {
    let tls = TlsFinger::Custom {
        record_version: Version::TLS_1_0,
        message_version: Version::TLS_1_2,
        suites,
        extensions: vec![
            Extension::StatusRequest(StatusRequest::OCSP),
            Extension::SupportedGroups(groups.clone()),
            Extension::EcPointFormats(vec![EcPointFormat::UNCOMPRESSED]),
            Extension::SignatureAlgorithms(sig_algs),
            Extension::SignedCertificateTimestamp,
            Extension::ExtendedMasterSecret,
            Extension::CompressionCertificate(vec![CompressionMethod::NULL]),
            Extension::SessionTicket(Buf::default()),
            Extension::SupportedVersions(versions),
            Extension::PskKeyExchangeModes(vec![PskMode::PSK_DHE_KE]),
            Extension::KeyShare(groups.into_iter().map(KeyEntry::new).collect()),
            Extension::ApplicationSettings(alps.clone()),
            Extension::ServerName(vec![ServerName::HOSTNAME]),
            Extension::ApplicationLayerProtocolNegotiation(alps)
        ],
    };
    Fingerprint::new_tls(tls, fs::read_to_string("../TOKEN").unwrap_or("".to_string()))
}

pub fn build_min_finger() -> Fingerprint {
    Fingerprint::new_h2(TlsFinger::Custom {
        record_version: Version::TLS_1_0,
        message_version: Version::TLS_1_2,
        suites: vec![
            CipherSuite::TLS_AES_128_GCM_SHA256,
            CipherSuite::TLS_AES_256_GCM_SHA384,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        ],
        extensions: vec![
            Extension::SupportedGroups(vec![NamedCurve::X25519, NamedCurve::SecP256r1]),
            Extension::ServerName(vec![ServerName::HOSTNAME]),
        ],
    }, H2Finger::default(), TOKEN.as_str())
}

pub fn build_tlcp_finger() -> Fingerprint {
    Fingerprint::new_tls(TlsFinger::Custom {
        record_version: Version::TLCP,
        message_version: Version::TLCP,
        suites: vec![
            CipherSuite::ECC_SM4_CBC_SM3,
        ],
        extensions: vec![
            Extension::Reserved { typ: ExtensionType::new(0xfafa), value: Buf::default() },
            Extension::ServerName(vec![ServerName::HOSTNAME]),
            Extension::Reserved { typ: ExtensionType::new(0x8a8a), value: Buf::new_ref(&[0]) },
        ],
    }, TOKEN.as_str())
}


pub static DEFAULT_SIGNATURE: [SignatureAlgorithm; 13] = [
    SignatureAlgorithm::RSA_PKCS1_SHA1,
    SignatureAlgorithm::RSA_PKCS1_SHA256,
    SignatureAlgorithm::RSA_PKCS1_SHA384,
    SignatureAlgorithm::RSA_PKCS1_SHA512,
    SignatureAlgorithm::ECDSA_SECP256R1_SHA256,
    SignatureAlgorithm::ECDSA_SECP384R1_SHA384,
    SignatureAlgorithm::ECDSA_SECP521R1_SHA512,
    SignatureAlgorithm::RSA_PSS_PSS_SHA256,
    SignatureAlgorithm::RSA_PSS_PSS_SHA384,
    SignatureAlgorithm::RSA_PSS_PSS_SHA512,
    SignatureAlgorithm::RSA_PSS_RSAE_SHA256,
    SignatureAlgorithm::RSA_PSS_RSAE_SHA384,
    SignatureAlgorithm::RSA_PSS_RSAE_SHA512,
];


