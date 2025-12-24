use std::fmt::{Debug, Formatter};
use key_share::KeyShare;
use algorithm::SignatureAlgorithms;
use formats::EcPointFormats;
use server_name::ServerName;
use status::StatusRequest;
use group::SupportedGroups;
use version::Versions;
use alps::ALPS;
use certificate::CompressionCertificate;
use client_hello::EncryptClientHello;
use psk_key::PskKey;
use super::bytes::Bytes;

mod version;
pub mod formats;
mod server_name;
pub mod algorithm;
mod status;
pub mod group;
pub mod key_share;
pub mod alps;
mod client_hello;
mod certificate;
mod psk_key;

pub use client_hello::Aead;
use crate::error::RlsResult;

pub struct ExtensionType(u16);

impl ExtensionType {
    pub fn new(value: u16) -> ExtensionType {ExtensionType(value)}
    pub fn kind(&self) -> Option<ExtensionKind> {
        ExtensionKind::from_u16(self.0)
    }

    pub fn as_bytes(&self) -> [u8; 2] {
        self.0.to_be_bytes()
    }

    pub fn is_reserved(&self) -> bool {
        ExtensionKind::from_u16(self.0).is_none()
    }

    pub fn as_u16(&self) -> u16 { self.0 }
}

impl Debug for ExtensionType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match ExtensionKind::from_u16(self.0) {
            None => f.write_str(&format!("Reserved({})", self.0)),
            Some(kind) => f.write_str(&format!("{:?}", kind))
        }
    }
}

#[repr(u16)]
#[derive(Debug, Clone)]
pub enum ExtensionKind {
    ServerName = 0x0,
    StatusRequest = 0x5,
    SupportedGroup = 0xa,
    EcPointFormats = 0xb,
    SignatureAlgorithms = 0xd,
    ApplicationLayerProtocolNegotiation = 0x10,
    SignedCertificateTimestamp = 0x12,
    EncryptTheMac = 0x16,
    MasterSecret = 0x17,
    SessionTicket = 0x23,
    CompressionCertificate = 0x1b,
    SupportedVersions = 0x2b,
    PskKeyExchangeMode = 0x2d,
    KeyShare = 0x33,
    RenegotiationInfo = 0xff01,
    EncryptedClientHello = 0xfe0d,
    ApplicationSetting = 0x44cd,
}

impl ExtensionKind {
    pub fn from_u16(byte: u16) -> Option<ExtensionKind> {
        match byte {
            0x0 => Some(ExtensionKind::ServerName),
            0x5 => Some(ExtensionKind::StatusRequest),
            0xa => Some(ExtensionKind::SupportedGroup),
            0xb => Some(ExtensionKind::EcPointFormats),
            0xd => Some(ExtensionKind::SignatureAlgorithms),
            0x10 => Some(ExtensionKind::ApplicationLayerProtocolNegotiation),
            0x12 => Some(ExtensionKind::SignedCertificateTimestamp),
            0x16 => Some(ExtensionKind::EncryptTheMac),
            0x17 => Some(ExtensionKind::MasterSecret),
            0x23 => Some(ExtensionKind::SessionTicket),
            0x1b => Some(ExtensionKind::CompressionCertificate),
            0x2b => Some(ExtensionKind::SupportedVersions),
            0x2d => Some(ExtensionKind::PskKeyExchangeMode),
            0x33 => Some(ExtensionKind::KeyShare),
            0xff01 => Some(ExtensionKind::RenegotiationInfo),
            0xfe0d => Some(ExtensionKind::EncryptedClientHello),
            0x44cd => Some(ExtensionKind::ApplicationSetting),
            _ => None
        }
    }

    pub fn default_value(&self) -> ExtensionValue {
        match self {
            ExtensionKind::ServerName => ExtensionValue::ServerName(ServerName::new()),
            ExtensionKind::StatusRequest => ExtensionValue::StatusRequest(StatusRequest::new()),
            ExtensionKind::SupportedGroup => ExtensionValue::SupportedGroups(SupportedGroups::new()),
            ExtensionKind::EcPointFormats => ExtensionValue::EcPointFormats(EcPointFormats::new()),
            ExtensionKind::SignatureAlgorithms => ExtensionValue::SignatureAlgorithms(SignatureAlgorithms::new()),
            ExtensionKind::ApplicationLayerProtocolNegotiation => ExtensionValue::ApplicationLayerProtocolNegotiation(ALPS::new()),
            ExtensionKind::SignedCertificateTimestamp => ExtensionValue::SignedCertificateTimestamp,
            ExtensionKind::EncryptTheMac => ExtensionValue::EncryptTheMac,
            ExtensionKind::MasterSecret => ExtensionValue::MasterSecret,
            ExtensionKind::SessionTicket => ExtensionValue::SessionTicket,
            ExtensionKind::CompressionCertificate => ExtensionValue::CompressionCertificate(CompressionCertificate::new()),
            ExtensionKind::SupportedVersions => ExtensionValue::SupportedVersions(Versions::new()),
            ExtensionKind::PskKeyExchangeMode => ExtensionValue::PskKeyExchangeMode(PskKey::new()),
            ExtensionKind::KeyShare => ExtensionValue::KeyShare(KeyShare::new()),
            ExtensionKind::RenegotiationInfo => ExtensionValue::RenegotiationInfo(RenegotiationInfo::new()),
            ExtensionKind::EncryptedClientHello => ExtensionValue::EncryptedClientHello(EncryptClientHello::new()),
            ExtensionKind::ApplicationSetting => ExtensionValue::ApplicationSetting(ALPS::new())
        }
    }
}

#[derive(Debug)]
pub struct RenegotiationInfo {
    len: u8,
}

impl RenegotiationInfo {
    pub fn new() -> RenegotiationInfo {
        RenegotiationInfo { len: 0 }
    }
    pub fn from_bytes(byte: &[u8]) -> RenegotiationInfo {
        RenegotiationInfo {
            len: byte[0]
        }
    }

    pub fn as_u8(&self) -> u8 {
        self.len
    }
}

#[derive(Debug)]
pub enum ExtensionValue {
    PskKeyExchangeMode(PskKey),
    KeyShare(KeyShare),
    SupportedGroups(SupportedGroups),
    StatusRequest(StatusRequest),
    SignatureAlgorithms(SignatureAlgorithms),
    ServerName(ServerName),
    EcPointFormats(EcPointFormats),
    SupportedVersions(Versions),
    RenegotiationInfo(RenegotiationInfo),
    ApplicationSetting(ALPS),
    EncryptedClientHello(EncryptClientHello),
    CompressionCertificate(CompressionCertificate),
    ApplicationLayerProtocolNegotiation(ALPS),
    SessionTicket,
    EncryptTheMac,
    MasterSecret,
    SignedCertificateTimestamp,
    Unknown(Bytes),
}

impl ExtensionValue {
    pub fn from_bytes(t: &ExtensionType, bytes: &[u8]) -> RlsResult<Self> {
        match t.kind() {
            Some(ExtensionKind::ServerName) => Ok(ExtensionValue::ServerName(ServerName::from_bytes(bytes)?)),
            Some(ExtensionKind::StatusRequest) => Ok(ExtensionValue::StatusRequest(StatusRequest::from_bytes(bytes)?)),
            Some(ExtensionKind::SupportedGroup) => Ok(ExtensionValue::SupportedGroups(SupportedGroups::from_bytes(bytes)?)),
            Some(ExtensionKind::EcPointFormats) => Ok(ExtensionValue::EcPointFormats(EcPointFormats::from_bytes(bytes)?)),
            Some(ExtensionKind::SignatureAlgorithms) => Ok(ExtensionValue::SignatureAlgorithms(SignatureAlgorithms::from_bytes(bytes)?)),
            Some(ExtensionKind::EncryptTheMac) => Ok(ExtensionValue::EncryptTheMac),
            Some(ExtensionKind::MasterSecret) => Ok(ExtensionValue::MasterSecret),
            Some(ExtensionKind::SessionTicket) => Ok(ExtensionValue::SessionTicket),
            Some(ExtensionKind::RenegotiationInfo) => Ok(ExtensionValue::RenegotiationInfo(RenegotiationInfo::from_bytes(bytes))),
            Some(ExtensionKind::SupportedVersions) => Ok(ExtensionValue::SupportedVersions(Versions::from_bytes(bytes))),
            Some(ExtensionKind::PskKeyExchangeMode) => Ok(ExtensionValue::PskKeyExchangeMode(PskKey::from_bytes(bytes)?)),
            Some(ExtensionKind::CompressionCertificate) => Ok(ExtensionValue::CompressionCertificate(CompressionCertificate::from_bytes(bytes)?)),
            Some(ExtensionKind::EncryptedClientHello) => Ok(ExtensionValue::EncryptedClientHello(EncryptClientHello::from_bytes(bytes)?)),
            Some(ExtensionKind::SignedCertificateTimestamp) => Ok(ExtensionValue::SignedCertificateTimestamp),
            Some(ExtensionKind::ApplicationSetting) => Ok(ExtensionValue::ApplicationSetting(ALPS::from_bytes(bytes)?)),
            Some(ExtensionKind::KeyShare) => Ok(ExtensionValue::KeyShare(KeyShare::from_bytes(bytes))),
            Some(ExtensionKind::ApplicationLayerProtocolNegotiation) => Ok(ExtensionValue::ApplicationLayerProtocolNegotiation(ALPS::from_bytes(bytes)?)),
            _ => Ok(ExtensionValue::Unknown(Bytes::new(bytes.to_vec())))
        }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        match self {
            ExtensionValue::PskKeyExchangeMode(v) => v.as_bytes(),
            ExtensionValue::KeyShare(v) => v.as_bytes(),
            ExtensionValue::SupportedGroups(v) => v.as_bytes(),
            ExtensionValue::StatusRequest(v) => v.as_bytes(),
            ExtensionValue::SignatureAlgorithms(v) => v.as_bytes(),
            ExtensionValue::ServerName(v) => v.as_bytes(),
            ExtensionValue::EcPointFormats(v) => v.as_bytes(),
            ExtensionValue::SupportedVersions(v) => v.as_bytes(),
            ExtensionValue::RenegotiationInfo(v) => vec![v.as_u8()],
            ExtensionValue::SessionTicket => vec![],
            ExtensionValue::EncryptTheMac => vec![],
            ExtensionValue::MasterSecret => vec![],
            ExtensionValue::CompressionCertificate(v) => v.as_bytes(),
            ExtensionValue::EncryptedClientHello(v) => v.as_bytes(),
            ExtensionValue::ApplicationSetting(v) => v.as_bytes(),
            ExtensionValue::ApplicationLayerProtocolNegotiation(v) => v.as_bytes(),
            ExtensionValue::Unknown(v) => v.as_bytes(),
            ExtensionValue::SignedCertificateTimestamp => vec![]
        }
    }
}

#[derive(Debug)]
pub struct Extension {
    type_: ExtensionType,
    len: u16,
    value: ExtensionValue,
}

impl Extension {
    pub fn new() -> Extension {
        Extension {
            type_: ExtensionType(0),
            len: 0,
            value: ExtensionValue::Unknown(Bytes::none()),
        }
    }

    pub fn from_type(t: ExtensionType) -> Extension {
        let mut res = Extension::new();
        if let Some(kind) = t.kind() {
            res.value = kind.default_value();
        };
        res.type_ = t;
        res
    }

    pub fn from_bytes(bytes: &[u8]) -> RlsResult<Vec<Extension>> {
        let mut res = vec![];
        let mut index = 0;
        while index < bytes.len() {
            let tv = u16::from_be_bytes([bytes[index], bytes[index + 1]].try_into()?);
            let mut v = Extension::new();
            v.type_ = ExtensionType(tv);
            v.len = u16::from_be_bytes([bytes[index + 2], bytes[index + 3]].try_into()?);
            v.value = ExtensionValue::from_bytes(&v.type_, &bytes[index + 4..index + 4 + v.len as usize])?;
            index += 4 + v.len as usize;
            res.push(v);
        }
        Ok(res)
    }

    pub fn extension_type(&self) -> &ExtensionType { &self.type_ }

    pub fn supported_groups(&self) -> Option<&SupportedGroups> {
        match &self.value {
            ExtensionValue::SupportedGroups(v) => Some(v),
            _ => None
        }
    }

    pub fn supported_groups_mut(&mut self) -> Option<&mut SupportedGroups> {
        match self.value {
            ExtensionValue::SupportedGroups(ref mut v) => Some(v),
            _ => None
        }
    }

    pub fn ex_point_formats(&self) -> Option<&EcPointFormats> {
        match &self.value {
            ExtensionValue::EcPointFormats(v) => Some(v),
            _ => None
        }
    }

    pub fn ex_point_formats_mut(&mut self) -> Option<&mut EcPointFormats> {
        match self.value {
            ExtensionValue::EcPointFormats(ref mut v) => Some(v),
            _ => None
        }
    }

    pub fn application_layer_protocol_negotiation(&self) -> Option<&ALPS> {
        match &self.value {
            ExtensionValue::ApplicationLayerProtocolNegotiation(v) => Some(v),
            _ => None
        }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = self.type_.as_bytes().to_vec();
        let vbs = self.value.as_bytes();
        res.extend((vbs.len() as u16).to_be_bytes());
        res.extend(vbs);
        res
    }

    pub fn set_server_name(&mut self, value: &str) {
        match self.value {
            ExtensionValue::ServerName(ref mut v) => v.set_value(value),
            _ => {}
        }
    }

    pub fn remove_h2_alpn(&mut self) {
        match self.value {
            ExtensionValue::ApplicationSetting(ref mut v) => v.remove_h2_alpn(),
            ExtensionValue::ApplicationLayerProtocolNegotiation(ref mut v) => v.remove_h2_alpn(),
            _ => {}
        }
    }

    pub fn add_h2_alpn(&mut self) {
        match self.value {
            ExtensionValue::ApplicationSetting(ref mut v) => v.add_h2_alpn(),
            ExtensionValue::ApplicationLayerProtocolNegotiation(ref mut v) => v.add_h2_alpn(),
            _ => {}
        }
    }
}