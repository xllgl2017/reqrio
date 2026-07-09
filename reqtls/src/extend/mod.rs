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
mod pre_share_key;
pub mod ech;

use crate::buffer::Buf;
use crate::error::RlsResult;
use crate::{BufferError, ReadExt, Reader, Version, WriteExt, ALPN};
use algorithm::SignatureAlgorithms;
use alps::ALPS;
pub use certificate::CompressCertificate;
pub use certificate::CompressionMethod;
use client_hello::EncryptClientHello;
pub use ech::Aead;
use formats::EcPointFormats;
use group::SupportedGroups;
pub use key_share::KeyShare;
use pre_share_key::PreSharedKey;
pub use psk_key::PskKey;
pub use psk_key::PskMode;
pub use server_name::ServerName;
pub use status::StatusRequest;
use std::fmt::{Debug, Formatter};
pub use version::SupportVersions;

#[derive(PartialEq, Clone, Copy)]
pub struct ExtensionType(u16);

impl ExtensionType {
    pub fn new(value: u16) -> ExtensionType { ExtensionType(value) }

    pub fn into_inner(self) -> u16 { self.0 }

    pub fn is_reserved(&self) -> bool {
        crate::REVERSED.contains(&self.0)
    }

    pub fn as_u16(&self) -> u16 { self.0 }
}

#[allow(non_upper_case_globals)]
impl ExtensionType {
    pub const ServerName: u16 = 0x0;
    pub const StatusRequest: u16 = 0x5;
    pub const SupportedGroup: u16 = 0xa;
    pub const EcPointFormats: u16 = 0xb;
    pub const SignatureAlgorithms: u16 = 0xd;
    pub const ApplicationLayerProtocolNegotiation: u16 = 0x10;
    pub const SignedCertificateTimestamp: u16 = 0x12;
    pub const Padding: u16 = 0x15;
    pub const EncryptTheMac: u16 = 0x16;
    pub const ExtendMasterSecret: u16 = 0x17;
    pub const SessionTicket: u16 = 0x23;
    pub const CompressionCertificate: u16 = 0x1b;
    pub const SupportedVersions: u16 = 0x2b;
    pub const PskKeyExchangeMode: u16 = 0x2d;
    pub const PostHandshakeAuth: u16 = 0x31;
    pub const KeyShare: u16 = 0x33;
    pub const RenegotiationInfo: u16 = 0xff01;
    pub const EncryptedClientHello: u16 = 0xfe0d;
    pub const ApplicationSetting: u16 = 0x44cd;
    pub const PreSharedKey: u16 = 0x29;
    pub const ApplicationSettingOld: u16 = 0x4469;

    pub const EXTENSIONS: [u16; 21] = [0x0, 0x5, 0xa, 0xb, 0xd, 0x10, 0x12, 0x15, 0x16, 0x17, 0x23, 0x1b, 0x2b, 0x2d, 0x31, 0x33, 0xff01, 0xfe0d, 0x44cd, 0x29, 0x4469];

    pub fn spec(&self) -> &'static str {
        match self.0 {
            0x0 => "ServerName",
            0x5 => "StatusRequest",
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
            _ => "Reserved"
        }
    }
}

impl Debug for ExtensionType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}(0x{:04x})", self.spec(), self.0)
    }
}

impl From<u16> for ExtensionType {
    fn from(value: u16) -> Self { ExtensionType(value) }
}

impl PartialEq<u16> for ExtensionType {
    fn eq(&self, other: &u16) -> bool {
        &self.0 == other
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
    pub fn from_reader(mut reader: Reader<'_>) -> RlsResult<RenegotiationInfo> {
        Ok(RenegotiationInfo {
            len: reader.read_u8()?
        })
    }

    pub fn len(&self) -> usize { 1 }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) -> Result<(), BufferError> {
        writer.write_u8(self.len)
    }
}

pub enum ExtensionValue<'a> {
    PskKeyExchangeMode(PskKey),
    KeyShare(KeyShare<'a>),
    SupportedGroups(SupportedGroups),
    StatusRequest(StatusRequest),
    SignatureAlgorithms(SignatureAlgorithms),
    ServerName(ServerName<'a>),
    EcPointFormats(EcPointFormats),
    SupportedVersions(SupportVersions),
    RenegotiationInfo(RenegotiationInfo),
    ApplicationSetting(ALPS),
    ApplicationSettingOld(ALPS),
    EncryptedClientHello(EncryptClientHello<'a>),
    CompressionCertificate(CompressCertificate),
    ApplicationLayerProtocolNegotiation(ALPS),
    SessionTicket(Buf<'a>),
    EncryptTheMac,
    MasterSecret,
    SignedCertificateTimestamp,
    PreSharedKey(PreSharedKey<'a>),
    Padding(usize),
    Unknown(Buf<'a>),
}

impl<'a> ExtensionValue<'a> {
    pub fn from_reader(t: &ExtensionType, reader: Reader<'a>, server: bool) -> RlsResult<Self> {
        match t.0 {
            ExtensionType::ServerName => Ok(ExtensionValue::ServerName(ServerName::from_reader(reader)?)),
            ExtensionType::StatusRequest => Ok(ExtensionValue::StatusRequest(StatusRequest::from_reader(reader)?)),
            ExtensionType::SupportedGroup => Ok(ExtensionValue::SupportedGroups(SupportedGroups::from_reader(reader)?)),
            ExtensionType::EcPointFormats => Ok(ExtensionValue::EcPointFormats(EcPointFormats::from_reader(reader)?)),
            ExtensionType::SignatureAlgorithms => Ok(ExtensionValue::SignatureAlgorithms(SignatureAlgorithms::from_reader(reader)?)),
            ExtensionType::EncryptTheMac => Ok(ExtensionValue::EncryptTheMac),
            ExtensionType::ExtendMasterSecret => Ok(ExtensionValue::MasterSecret),
            ExtensionType::SessionTicket => Ok(ExtensionValue::SessionTicket(Buf::Ref(reader.into_inner()))),
            ExtensionType::RenegotiationInfo => Ok(ExtensionValue::RenegotiationInfo(RenegotiationInfo::from_reader(reader)?)),
            ExtensionType::SupportedVersions => Ok(ExtensionValue::SupportedVersions(SupportVersions::from_reader(reader, server)?)),
            ExtensionType::PskKeyExchangeMode => Ok(ExtensionValue::PskKeyExchangeMode(PskKey::from_reader(reader)?)),
            ExtensionType::CompressionCertificate => Ok(ExtensionValue::CompressionCertificate(CompressCertificate::from_reader(reader)?)),
            ExtensionType::EncryptedClientHello => {
                if server {
                    Ok(ExtensionValue::Unknown(Buf::Ref(reader.into_inner())))
                } else {
                    Ok(ExtensionValue::EncryptedClientHello(EncryptClientHello::from_reader(reader)?))
                }
            }
            ExtensionType::SignedCertificateTimestamp => Ok(ExtensionValue::SignedCertificateTimestamp),
            ExtensionType::ApplicationSetting => Ok(ExtensionValue::ApplicationSetting(ALPS::from_reader(reader)?)),
            ExtensionType::KeyShare => Ok(ExtensionValue::KeyShare(KeyShare::from_reader(reader, server)?)),
            ExtensionType::ApplicationLayerProtocolNegotiation => Ok(ExtensionValue::ApplicationLayerProtocolNegotiation(ALPS::from_reader(reader)?)),
            ExtensionType::PreSharedKey => Ok(ExtensionValue::PreSharedKey(PreSharedKey::from_reader(reader)?)),
            ExtensionType::ApplicationSettingOld => Ok(ExtensionValue::ApplicationSetting(ALPS::from_reader(reader)?)),
            ExtensionType::Padding => Ok(ExtensionValue::Padding(reader.unread_len())),
            _ => Ok(ExtensionValue::Unknown(Buf::Ref(reader.into_inner())))
        }
    }

    pub fn len(&self, server: bool) -> usize {
        match self {
            ExtensionValue::PskKeyExchangeMode(v) => v.len(),
            ExtensionValue::KeyShare(v) => v.len(),
            ExtensionValue::SupportedGroups(v) => v.len(),
            ExtensionValue::StatusRequest(v) => if server { 0 } else { v.len() },
            ExtensionValue::SignatureAlgorithms(v) => v.len(),
            ExtensionValue::ServerName(v) => v.len(),
            ExtensionValue::EcPointFormats(v) => v.len(),
            ExtensionValue::SupportedVersions(v) => v.len(server),
            ExtensionValue::RenegotiationInfo(v) => v.len(),
            ExtensionValue::ApplicationSetting(v) => v.len(),
            ExtensionValue::ApplicationSettingOld(v) => v.len(),
            ExtensionValue::EncryptedClientHello(v) => v.len(),
            ExtensionValue::CompressionCertificate(v) => v.len(),
            ExtensionValue::ApplicationLayerProtocolNegotiation(v) => v.len(),
            ExtensionValue::SessionTicket(v) => v.len(),
            ExtensionValue::EncryptTheMac => 0,
            ExtensionValue::MasterSecret => 0,
            ExtensionValue::SignedCertificateTimestamp => 0,
            ExtensionValue::PreSharedKey(v) => v.len(),
            ExtensionValue::Unknown(v) => v.len(),
            ExtensionValue::Padding(v) => *v,
        }
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W, server: bool) -> Result<(), BufferError> {
        match self {
            ExtensionValue::PskKeyExchangeMode(v) => v.write_to(writer),
            ExtensionValue::KeyShare(v) => v.write_to(writer),
            ExtensionValue::SupportedGroups(v) => v.write_to(writer),
            ExtensionValue::StatusRequest(v) => if !server { v.write_to(writer) } else { Ok(()) },
            ExtensionValue::SignatureAlgorithms(v) => v.write_to(writer),
            ExtensionValue::ServerName(v) => v.write_to(writer),
            ExtensionValue::EcPointFormats(v) => v.write_to(writer),
            ExtensionValue::SupportedVersions(v) => v.write_to(writer, server),
            ExtensionValue::RenegotiationInfo(v) => v.write_to(writer),
            ExtensionValue::SessionTicket(v) => writer.write_slice(v.as_ref()),
            ExtensionValue::EncryptTheMac => Ok(()),
            ExtensionValue::MasterSecret => Ok(()),
            ExtensionValue::CompressionCertificate(v) => v.write_to(writer),
            ExtensionValue::EncryptedClientHello(v) => v.write_to(writer),
            ExtensionValue::ApplicationSetting(v) => v.write_to(writer),
            ExtensionValue::ApplicationLayerProtocolNegotiation(v) => v.write_to(writer),
            ExtensionValue::Unknown(v) => writer.write_slice(v.as_ref()),
            ExtensionValue::SignedCertificateTimestamp => Ok(()),
            ExtensionValue::PreSharedKey(v) => v.write_to(writer),
            ExtensionValue::ApplicationSettingOld(v) => v.write_to(writer),
            ExtensionValue::Padding(size) => writer.write_slice(&vec![0u8; size]),
        }
    }
}

impl<'a> Debug for ExtensionValue<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ExtensionValue::PskKeyExchangeMode(v) => if f.alternate() { write!(f, "{:#?}", v) } else { write!(f, "{:?}", v) },
            ExtensionValue::KeyShare(v) => if f.alternate() { write!(f, "{:#?}", v) } else { write!(f, "{:?}", v) },
            ExtensionValue::SupportedGroups(v) => if f.alternate() { write!(f, "{:#?}", v) } else { write!(f, "{:?}", v) },
            ExtensionValue::StatusRequest(v) => if f.alternate() { write!(f, "{:#?}", v) } else { write!(f, "{:?}", v) },
            ExtensionValue::SignatureAlgorithms(v) => if f.alternate() { write!(f, "{:#?}", v) } else { write!(f, "{:?}", v) },
            ExtensionValue::ServerName(v) => if f.alternate() { write!(f, "{:#?}", v) } else { write!(f, "{:?}", v) },
            ExtensionValue::EcPointFormats(v) => if f.alternate() { write!(f, "{:#?}", v) } else { write!(f, "{:?}", v) },
            ExtensionValue::SupportedVersions(v) => if f.alternate() { write!(f, "{:#?}", v) } else { write!(f, "{:?}", v) },
            ExtensionValue::RenegotiationInfo(v) => if f.alternate() { write!(f, "{:#?}", v) } else { write!(f, "{:?}", v) },
            ExtensionValue::ApplicationSetting(v) => if f.alternate() { write!(f, "{:#?}", v) } else { write!(f, "{:?}", v) },
            ExtensionValue::ApplicationSettingOld(v) => if f.alternate() { write!(f, "{:#?}", v) } else { write!(f, "{:?}", v) },
            ExtensionValue::EncryptedClientHello(v) => if f.alternate() { write!(f, "{:#?}", v) } else { write!(f, "{:?}", v) },
            ExtensionValue::CompressionCertificate(v) => if f.alternate() { write!(f, "{:#?}", v) } else { write!(f, "{:?}", v) },
            ExtensionValue::ApplicationLayerProtocolNegotiation(v) => if f.alternate() { write!(f, "{:#?}", v) } else { write!(f, "{:?}", v) },
            ExtensionValue::SessionTicket(v) => write!(f, "{:#?}", v),
            ExtensionValue::EncryptTheMac => write!(f, "EncryptTheMac"),
            ExtensionValue::MasterSecret => write!(f, "MasterSecret"),
            ExtensionValue::SignedCertificateTimestamp => write!(f, "SignedCertificateTimestamp"),
            ExtensionValue::PreSharedKey(v) => if f.alternate() { write!(f, "{:#?}", v) } else { write!(f, "{:?}", v) },
            ExtensionValue::Unknown(v) => if f.alternate() { write!(f, "{:#?}", v) } else { write!(f, "{:?}", v) },
            ExtensionValue::Padding(size) => write!(f, "Padding({})", size),
        }
    }
}


#[derive(Debug)]
pub struct Extension<'a> {
    type_: ExtensionType,
    value: ExtensionValue<'a>,
}

impl<'a> Default for Extension<'a> {
    fn default() -> Self {
        Extension {
            type_: ExtensionType(0),
            value: ExtensionValue::Unknown(Buf::Ref(&[])),
        }
    }
}

impl<'a> Extension<'a> {
    pub fn new(typ: impl Into<ExtensionType>, value: ExtensionValue) -> Extension {
        Extension {
            type_: typ.into(),
            value,
        }
    }

    pub fn default_value(ty: ExtensionType) -> Option<ExtensionValue<'a>> {
        match ty.0 {
            ExtensionType::ServerName => Some(ExtensionValue::ServerName(ServerName::new())),
            ExtensionType::StatusRequest => Some(ExtensionValue::StatusRequest(StatusRequest::new())),
            ExtensionType::SupportedGroup => Some(ExtensionValue::SupportedGroups(SupportedGroups::random())),
            ExtensionType::EcPointFormats => Some(ExtensionValue::EcPointFormats(EcPointFormats::random())),
            ExtensionType::SignatureAlgorithms => Some(ExtensionValue::SignatureAlgorithms(SignatureAlgorithms::random())),
            ExtensionType::ApplicationLayerProtocolNegotiation => Some(ExtensionValue::ApplicationLayerProtocolNegotiation(ALPS::new(vec![ALPN::Http20, ALPN::Http11]))),
            ExtensionType::SignedCertificateTimestamp => Some(ExtensionValue::SignedCertificateTimestamp),
            ExtensionType::EncryptTheMac => Some(ExtensionValue::EncryptTheMac),
            ExtensionType::ExtendMasterSecret => Some(ExtensionValue::MasterSecret),
            ExtensionType::SessionTicket => Some(ExtensionValue::SessionTicket(Buf::Ref(&[]))),
            ExtensionType::CompressionCertificate => {
                let mut cp_cer = CompressCertificate::new();
                cp_cer.push(CompressionMethod::NULL);
                Some(ExtensionValue::CompressionCertificate(cp_cer))
            }
            ExtensionType::SupportedVersions => {
                let mut supported_versions = SupportVersions::default();
                supported_versions.push(Version::TLS_1_3);
                supported_versions.push(Version::TLS_1_2);
                Some(ExtensionValue::SupportedVersions(supported_versions))
            }
            ExtensionType::PskKeyExchangeMode => Some(ExtensionValue::PskKeyExchangeMode(PskKey::new())),
            ExtensionType::KeyShare => Some(ExtensionValue::KeyShare(KeyShare::default())),
            ExtensionType::RenegotiationInfo => Some(ExtensionValue::RenegotiationInfo(RenegotiationInfo::new())),
            ExtensionType::EncryptedClientHello => Some(ExtensionValue::EncryptedClientHello(EncryptClientHello::new())),
            ExtensionType::ApplicationSetting => Some(ExtensionValue::ApplicationSetting(ALPS::new(vec![ALPN::Http20, ALPN::Http11]))),
            ExtensionType::ApplicationSettingOld => Some(ExtensionValue::ApplicationSettingOld(ALPS::new(vec![ALPN::Http20, ALPN::Http11]))),
            ExtensionType::PreSharedKey => Some(ExtensionValue::PreSharedKey(PreSharedKey::random())),
            ExtensionType::Padding=>Some(ExtensionValue::Padding(202)),
            _ => None
        }
    }

    pub fn from_type(t: ExtensionType) -> Extension<'a> {
        let mut res = Extension::default();
        if let Some(value) = Extension::default_value(t) {
            res.value = value;
        }
        res.type_ = t;
        res
    }

    pub fn from_reader(mut reader: Reader<'a>, server: bool) -> RlsResult<Vec<Extension<'a>>> {
        if reader.unread_len() == 0 { return Ok(vec![]); }
        let mut res = Vec::with_capacity(reader.unread_len());
        while reader.unread_len() > 0 {
            let type_ = ExtensionType::new(reader.read_u16()?);
            let len = reader.read_u16()?;
            res.push(Extension {
                value: ExtensionValue::from_reader(&type_, reader.read_reader(len as usize)?, server)?,
                type_,

            });
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

    pub fn signature_algorithms(&self) -> Option<&SignatureAlgorithms> {
        match &self.value {
            ExtensionValue::SignatureAlgorithms(v) => Some(v),
            _ => None
        }
    }

    pub fn signature_algorithms_mut(&mut self) -> Option<&mut SignatureAlgorithms> {
        match &mut self.value {
            ExtensionValue::SignatureAlgorithms(v) => Some(v),
            _ => None
        }
    }

    pub fn supported_versions(&self) -> Option<&SupportVersions> {
        match &self.value {
            ExtensionValue::SupportedVersions(v) => Some(v),
            _ => None
        }
    }

    pub fn supported_versions_mut(&mut self) -> Option<&mut SupportVersions> {
        match &mut self.value {
            ExtensionValue::SupportedVersions(v) => Some(v),
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

    // pub fn application_layer_protocol_negotiation(&self) -> Option<&ALPS> {
    //     match &self.value {
    //         ExtensionValue::ApplicationLayerProtocolNegotiation(v) => Some(v),
    //         _ => None
    //     }
    // }

    pub fn len(&self, server: bool) -> usize { 4 + self.value.len(server) }

    pub fn write_to<W: WriteExt>(self, writer: &mut W, server: bool) -> Result<(), BufferError> {
        writer.write_u16(self.type_.into_inner())?;
        writer.write_u16(self.value.len(server) as u16)?;
        self.value.write_to(writer, server)
    }

    pub fn set_server_name(&mut self, value: &'a str) {
        if let ExtensionValue::ServerName(ref mut v) = self.value { v.set_value(value) }
    }

    pub fn set_key_share(&mut self, key_share: KeyShare<'a>) {
        if let ExtensionValue::KeyShare(ref mut key) = self.value {
            *key = key_share;
        }
    }

    pub fn key_share(&self) -> Option<&KeyShare<'a>> {
        if let ExtensionValue::KeyShare(ref key) = self.value {
            Some(key)
        } else { None }
    }

    pub fn key_share_mut(&mut self) -> Option<&mut KeyShare<'a>> {
        if let ExtensionValue::KeyShare(ref mut key) = self.value {
            Some(key)
        } else { None }
    }

    pub fn server_name(&self) -> Option<&ServerName<'a>> {
        match self.value {
            ExtensionValue::ServerName(ref v) => Some(v),
            _ => None
        }
    }

    pub fn alps(&self) -> Option<&ALPS> {
        match self.value {
            ExtensionValue::ApplicationLayerProtocolNegotiation(ref v) => Some(v),
            _ => None
        }
    }

    pub fn alps_mut(&mut self) -> Option<&mut ALPS> {
        match self.value {
            ExtensionValue::ApplicationLayerProtocolNegotiation(ref mut v) => Some(v),
            _ => None
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

    pub fn remove_tls13(&mut self) {
        if let ExtensionValue::SupportedVersions(ref mut v) = self.value { v.remove_tls13() }
    }

    pub fn value(&self) -> &ExtensionValue<'_> { &self.value }
    
    pub fn value_mut(&mut self) -> &mut ExtensionValue<'a> { &mut self.value }

    pub fn into_value(self) -> ExtensionValue<'a> { self.value }
}