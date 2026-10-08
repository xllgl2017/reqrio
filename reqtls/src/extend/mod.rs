mod formats;
mod server_name;
mod status;
mod key_share;
mod client_hello;
mod certificate;
mod psk_key;
mod pre_share_key;
mod ech;
#[cfg(feature = "quic")]
mod quic;

use crate::{rand, Buf, NamedCurve, SignatureAlgorithm, Version, ALPN, REVERSED};
pub use certificate::CompressCertificate;
pub use certificate::CompressionMethod;
pub use client_hello::EncryptClientHello;
pub use ech::{Aead, EchConfig};
pub use formats::EcPointFormat;
pub use key_share::KeyEntry;
pub use psk_key::PskMode;
#[cfg(feature = "quic")]
pub use quic::QUICParameter;
pub use server_name::ServerName;
pub use status::StatusRequest;
#[cfg(debug_assertions)]
use std::fmt::Debug;

#[repr(C)]
#[derive(PartialEq, Copy, Clone)]
#[cfg_attr(debug_assertions, derive(Debug))]
pub struct ExtensionType(u16);
#[allow(non_upper_case_globals)]
impl ExtensionType {
    pub const ServerName: ExtensionType = ExtensionType(0x0);
    pub const StatusRequest: ExtensionType = ExtensionType(0x5);
    pub const SupportedGroup: ExtensionType = ExtensionType(0xa);
    pub const EcPointFormats: ExtensionType = ExtensionType(0xb);
    pub const SignatureAlgorithms: ExtensionType = ExtensionType(0xd);
    pub const ApplicationLayerProtocolNegotiation: ExtensionType = ExtensionType(0x10);
    pub const SignedCertificateTimestamp: ExtensionType = ExtensionType(0x12);
    pub const Padding: ExtensionType = ExtensionType(0x15);
    pub const EncryptTheMac: ExtensionType = ExtensionType(0x16);
    pub const ExtendedMasterSecret: ExtensionType = ExtensionType(0x17);
    pub const SessionTicket: ExtensionType = ExtensionType(0x23);
    pub const CompressionCertificate: ExtensionType = ExtensionType(0x1b);
    pub const SupportedVersions: ExtensionType = ExtensionType(0x2b);
    pub const PskKeyExchangeMode: ExtensionType = ExtensionType(0x2d);
    pub const PostHandshakeAuth: ExtensionType = ExtensionType(0x31);
    pub const KeyShare: ExtensionType = ExtensionType(0x33);
    pub const RenegotiationInfo: ExtensionType = ExtensionType(0xff01);
    pub const EncryptedClientHello: ExtensionType = ExtensionType(0xfe0d);
    pub const ApplicationSetting: ExtensionType = ExtensionType(0x44cd);
    pub const PreSharedKey: ExtensionType = ExtensionType(0x29);
    pub const ApplicationSettingOld: ExtensionType = ExtensionType(0x4469);
    pub const QuicTrpParameters: ExtensionType = ExtensionType(0x0039);

    pub fn spec(&self) -> &str {
        match self.0 {
            0 => "ServerName",
            5 => "StatusRequest",
            0xa => "SupportedGroup",
            0xb => "EcPointFormats",
            0xd => "SignatureAlgorithms",
            0x10 => "ApplicationLayerProtocolNegotiation",
            0x12 => "SignedCertificateTimestamp",
            0x15 => "Padding",
            0x16 => "EncryptTheMac",
            0x17 => "ExtendMasterSecret",
            0x23 => "SessionTicket",
            0x1b => "CompressionCertificate",
            0x2b => "SupportedVersions",
            0x2d => "PskKeyExchangeMode",
            0x31 => "PostHandshakeAuth",
            0x33 => "KeyShare",
            0xff01 => "RenegotiationInfo",
            0xfe0d => "EncryptedClientHello",
            0x44cd => "ApplicationSetting",
            0x29 => "PreSharedKey",
            0x4469 => "ApplicationSettingOld",
            0x0039 => "QuicTrpParameters",
            _ => "Reversed"
        }
    }

    pub const fn new(value: u16) -> ExtensionType {
        ExtensionType(value)
    }

    pub const fn inner(&self) -> u16 { self.0 }

    pub const fn into_inner(self) -> u16 { self.0 }

    pub fn is_reversed(&self) -> bool {
        REVERSED.contains(&self.0)
    }
}

#[cfg_attr(debug_assertions, derive(Debug))]
pub enum Extension {
    KeyShare(Vec<KeyEntry>),
    StatusRequest(StatusRequest),
    ServerName(Vec<ServerName>),
    SupportedGroups(Vec<NamedCurve>),
    SupportedVersions(Vec<Version>),
    ApplicationLayerProtocolNegotiation(Vec<ALPN>),
    ApplicationSettings(Vec<ALPN>),
    ApplicationSettingOld(Vec<ALPN>),
    CompressionCertificate(Vec<CompressionMethod>),
    EcPointFormats(Vec<EcPointFormat>),
    PskKeyExchangeModes(Vec<PskMode>),
    SignatureAlgorithms(Vec<SignatureAlgorithm>),
    #[cfg(feature = "quic")]
    QuicTrpParameters(Vec<QUICParameter<'static>>),
    SessionTicket(Buf<'static>),
    EncryptedClientHello(Buf<'static>),
    RenegotiationInfo(Buf<'static>),
    Padding(usize),
    ExtendedMasterSecret,
    SignedCertificateTimestamp,
    EncryptTheMac,
    Reserved { typ: ExtensionType, value: Buf<'static> },
}

impl PartialEq<ExtensionType> for Extension {
    fn eq(&self, other: &ExtensionType) -> bool {
        match (self, *other) {
            (Extension::KeyShare(_), ExtensionType::KeyShare) => true,
            (Extension::StatusRequest(_), ExtensionType::StatusRequest) => true,
            (Extension::ServerName(_), ExtensionType::ServerName) => true,
            (Extension::SupportedGroups(_), ExtensionType::SupportedGroup) => true,
            (Extension::SupportedVersions(_), ExtensionType::SupportedVersions) => true,
            (Extension::ApplicationLayerProtocolNegotiation(_), ExtensionType::ApplicationLayerProtocolNegotiation) => true,
            (Extension::ApplicationSettings(_), ExtensionType::ApplicationSetting) => true,
            (Extension::ApplicationSettingOld(_), ExtensionType::ApplicationSettingOld) => true,
            (Extension::CompressionCertificate(_), ExtensionType::CompressionCertificate) => true,
            (Extension::EcPointFormats(_), ExtensionType::EcPointFormats) => true,
            (Extension::PskKeyExchangeModes(_), ExtensionType::PskKeyExchangeMode) => true,
            (Extension::SignatureAlgorithms(_), ExtensionType::SignatureAlgorithms) => true,
            (Extension::SessionTicket(_), ExtensionType::SessionTicket) => true,
            (Extension::EncryptedClientHello(_), ExtensionType::EncryptedClientHello) => true,
            (Extension::RenegotiationInfo(_), ExtensionType::RenegotiationInfo) => true,
            (Extension::Padding(_), ExtensionType::Padding) => true,
            (Extension::ExtendedMasterSecret, ExtensionType::ExtendedMasterSecret) => true,
            (Extension::SignedCertificateTimestamp, ExtensionType::SignedCertificateTimestamp) => true,
            (Extension::EncryptTheMac, ExtensionType::EncryptTheMac) => true,
            (Extension::Reserved { typ, .. }, typ2) => *typ == typ2,
            _ => false,
        }
    }
}

impl Extension {
    pub const RENEGOTIATION_INFO: Extension = Extension::RenegotiationInfo(Buf::new_ref(&[0]));
    pub const STATUS_REQUEST: Extension = Extension::StatusRequest(StatusRequest::OCSP);

    pub fn default_value(ty: ExtensionType) -> Option<Extension> {
        match ty {
            ExtensionType::ServerName => Some(Extension::ServerName(vec![ServerName::HOSTNAME])),
            ExtensionType::StatusRequest => Some(Extension::StatusRequest(StatusRequest::OCSP)),
            ExtensionType::SupportedGroup => Some(Extension::SupportedGroups(vec![
                NamedCurve::X25519,
                NamedCurve::SecP256r1,
                NamedCurve::SecP384r1,
                NamedCurve::SecP521r1,
            ])),
            ExtensionType::EcPointFormats => Some(Extension::EcPointFormats(vec![EcPointFormat::UNCOMPRESSED])),
            ExtensionType::SignatureAlgorithms => Some(Extension::SignatureAlgorithms(Extension::random_sign_algos())),
            ExtensionType::ApplicationLayerProtocolNegotiation => Some(Extension::ApplicationLayerProtocolNegotiation(vec![ALPN::HTTP20, ALPN::HTTP11])),
            ExtensionType::SignedCertificateTimestamp => Some(Extension::SignedCertificateTimestamp),
            ExtensionType::EncryptTheMac => Some(Extension::EncryptTheMac),
            ExtensionType::ExtendedMasterSecret => Some(Extension::ExtendedMasterSecret),
            ExtensionType::SessionTicket => Some(Extension::SessionTicket(Buf::default())),
            ExtensionType::CompressionCertificate => Some(Extension::CompressionCertificate(vec![CompressionMethod::NULL])),
            ExtensionType::SupportedVersions => Some(Extension::SupportedVersions(vec![
                Version::TLS_1_3,
                Version::TLS_1_2,
            ])),
            ExtensionType::PskKeyExchangeMode => Some(Extension::PskKeyExchangeModes(vec![PskMode::PSK_DHE_KE])),
            ExtensionType::KeyShare => Some(Extension::KeyShare(vec![])),
            ExtensionType::RenegotiationInfo => Some(Extension::RENEGOTIATION_INFO),
            // ExtensionType::EncryptedClientHello => Some(Extension::EncryptedClientHello(EncryptClientHello::new())),
            ExtensionType::ApplicationSetting => Some(Extension::ApplicationSettings(vec![ALPN::HTTP20, ALPN::HTTP11])),
            ExtensionType::ApplicationSettingOld => Some(Extension::ApplicationSettingOld(vec![ALPN::HTTP20, ALPN::HTTP11])),
            // ExtensionType::PreSharedKey => Some(Extension::PreSharedKey(extend::pre_share_key::PreSharedKey::random())),
            ExtensionType::Padding => Some(Extension::Padding(202)),
            _ => None
        }
    }
}

impl Extension {
    pub fn random_sign_algos() -> Vec<SignatureAlgorithm> {
        let mut res = vec![
            SignatureAlgorithm::RSA_PSS_RSAE_SHA256,
            SignatureAlgorithm::ECDSA_SECP256R1_SHA256,
            SignatureAlgorithm::RSA_PKCS1_SHA256,
        ];
        let all_sign = SignatureAlgorithm::ALL;
        while res.len() < 10 {
            let index = rand::random::<usize>() % all_sign.len();
            if res.contains(&all_sign[index]) { continue; }
            res.push(all_sign[index]);
        }
        res
    }
}