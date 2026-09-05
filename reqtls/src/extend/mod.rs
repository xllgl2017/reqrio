mod version;
mod formats;
mod server_name;
mod algorithm;
mod status;
pub mod group;
mod key_share;
pub mod alps;
mod client_hello;
mod certificate;
mod psk_key;
mod pre_share_key;
mod ech;
#[cfg(feature = "quic")]
mod quic;

use crate::error::RlsResult;
use crate::*;
pub use algorithm::SignatureAlgorithms;
pub use alps::ALPS;
pub use certificate::CompressCertificate;
pub use certificate::CompressionMethod;
pub use client_hello::EncryptClientHello;
pub use ech::{Aead, EchConfig};
pub use formats::{EcPointFormats, EcPointFormat};
pub use group::SupportedGroups;
pub use key_share::KeyShare;
use pre_share_key::PreSharedKey;
pub use psk_key::PskMode;
#[cfg(feature = "quic")]
pub use quic::Parameter;
pub use server_name::SNType;
pub use status::StatusRequest;
use std::fmt::{Debug, Display, Formatter};
pub use version::SupportVersions;

#[derive(Debug, Clone)]
pub enum Extension<'a> {
    ServerName(Vec<SNType<'a>>),
    StatusRequest(StatusRequest),
    SupportedGroups(SupportedGroups),
    EcPointFormats(EcPointFormats),
    SignatureAlgorithms(SignatureAlgorithms),
    ApplicationLayerProtocolNegotiation(ALPS),
    SignedCertificateTimestamp,
    Padding(usize),
    EncryptTheMac,
    ExtendMasterSecret,
    SessionTicket(Buf<'a>),
    CompressionCertificate(CompressCertificate),
    SupportedVersions(SupportVersions),
    PskKeyExchangeMode(Vec<PskMode>),
    PostHandshakeAuth,
    KeyShare(KeyShare<'a>),
    RenegotiationInfo,
    EncryptedClientHello(EncryptClientHello<'a>),
    ApplicationSetting(ALPS),
    PreSharedKey(PreSharedKey<'a>),
    ApplicationSettingOld(ALPS),
    #[cfg(feature = "quic")]
    QUICTrpParameters(Vec<Parameter<'a>>),
    Reserved {
        typ: u16,
        value: Buf<'a>,
    },
}


impl<'a> Extension<'a> {
    pub const SERVER_NAME: u16 = 0x0;
    pub const STATUS_REQUEST: u16 = 0x5;
    pub const SUPPORTED_GROUP: u16 = 0xa;
    pub const EC_POINT_FORMATS: u16 = 0xb;
    pub const SIGNATURE_ALGORITHMS: u16 = 0xd;
    pub const APPLICATION_LAYER_PROTOCOL_NEGOTIATION: u16 = 0x10;
    pub const SIGNED_CERTIFICATE_TIMESTAMP: u16 = 0x12;
    pub const PADDING: u16 = 0x15;
    pub const ENCRYPT_THE_MAC: u16 = 0x16;
    pub const EXTEND_MASTER_SECRET: u16 = 0x17;
    pub const SESSION_TICKET: u16 = 0x23;
    pub const COMPRESSION_CERTIFICATE: u16 = 0x1b;
    pub const SUPPORTED_VERSIONS: u16 = 0x2b;
    pub const PSK_KEY_EXCHANGE_MODE: u16 = 0x2d;
    pub const POST_HANDSHAKE_AUTH: u16 = 0x31;
    pub const KEY_SHARE: u16 = 0x33;
    pub const RENEGOTIATION_INFO: u16 = 0xff01;
    pub const ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
    pub const APPLICATION_SETTING: u16 = 0x44cd;
    pub const PRE_SHARED_KEY: u16 = 0x29;
    pub const APPLICATION_SETTING_OLD: u16 = 0x4469;
    pub const QUIC_TRP_PARAMETERS: u16 = 0x0039;

    pub fn default_value(ty: u16) -> Option<Extension<'a>> {
        match ty {
            Extension::SERVER_NAME => Some(Extension::ServerName(vec![])),
            Extension::STATUS_REQUEST => Some(Extension::StatusRequest(StatusRequest::new())),
            Extension::SUPPORTED_GROUP => Some(Extension::SupportedGroups(SupportedGroups::random())),
            Extension::EC_POINT_FORMATS => Some(Extension::EcPointFormats(EcPointFormats::random())),
            Extension::SIGNATURE_ALGORITHMS => Some(Extension::SignatureAlgorithms(SignatureAlgorithms::random())),
            Extension::APPLICATION_LAYER_PROTOCOL_NEGOTIATION => Some(Extension::ApplicationLayerProtocolNegotiation(ALPS::new(vec![ALPN::Http20, ALPN::Http11]))),
            Extension::SIGNED_CERTIFICATE_TIMESTAMP => Some(Extension::SignedCertificateTimestamp),
            Extension::ENCRYPT_THE_MAC => Some(Extension::EncryptTheMac),
            Extension::EXTEND_MASTER_SECRET => Some(Extension::ExtendMasterSecret),
            Extension::SESSION_TICKET => Some(Extension::SessionTicket(Buf::Ref(&[]))),
            Extension::COMPRESSION_CERTIFICATE => Some(Extension::CompressionCertificate(CompressCertificate::new(vec![CompressionMethod::NULL]))),
            Extension::SUPPORTED_VERSIONS => {
                let mut supported_versions = SupportVersions::default();
                supported_versions.push(Version::TLS_1_3);
                supported_versions.push(Version::TLS_1_2);
                Some(Extension::SupportedVersions(supported_versions))
            }
            Extension::PSK_KEY_EXCHANGE_MODE => Some(Extension::PskKeyExchangeMode(vec![PskMode::new(PskMode::PSK_DHE_KE)])),
            Extension::KEY_SHARE => Some(Extension::KeyShare(KeyShare::default())),
            Extension::RENEGOTIATION_INFO => Some(Extension::RenegotiationInfo),
            Extension::ENCRYPTED_CLIENT_HELLO => Some(Extension::EncryptedClientHello(EncryptClientHello::new())),
            Extension::APPLICATION_SETTING => Some(Extension::ApplicationSetting(ALPS::new(vec![ALPN::Http20, ALPN::Http11]))),
            Extension::APPLICATION_SETTING_OLD => Some(Extension::ApplicationSettingOld(ALPS::new(vec![ALPN::Http20, ALPN::Http11]))),
            Extension::PRE_SHARED_KEY => Some(Extension::PreSharedKey(PreSharedKey::random())),
            Extension::PADDING => Some(Extension::Padding(202)),
            _ => None
        }
    }

    pub fn from_reader(mut reader: Reader<'a>, server: bool) -> RlsResult<Vec<Extension<'a>>> {
        let mut extensions = Vec::with_capacity(15);
        if reader.unread_len() == 0 { return Ok(extensions); }
        while reader.unread_len() > 0 {
            let typ = reader.read_u16()?;
            let len = reader.read_u16()? as usize;
            extensions.push(match typ {
                Extension::SERVER_NAME => {
                    let mut res = Vec::with_capacity(10);
                    if len > 0 {
                        let mut reader = reader.read_reader(len)?;
                        let list_len = reader.read_u16()? as usize;
                        let mut reader = reader.read_reader(list_len)?;
                        while reader.unread_len() > 0 {
                            match reader.read_u8()? {
                                SNType::HOST_NAME => {
                                    let len = reader.read_u16()? as usize;
                                    res.push(SNType::HostName(reader.read_str(len)?));
                                }
                                _ => {
                                    #[cfg(feature = "log")]
                                    warn!("[Extension] unknown SNType!")
                                }
                            }
                        }
                    }
                    Extension::ServerName(res)
                }
                Extension::STATUS_REQUEST => Extension::StatusRequest(StatusRequest::from_reader(reader.read_reader(len)?)?),
                Extension::SUPPORTED_GROUP => Extension::SupportedGroups(SupportedGroups::from_reader(reader.read_reader(len)?)?),
                Extension::EC_POINT_FORMATS => Extension::EcPointFormats(EcPointFormats::from_reader(reader.read_reader(len)?)?),
                Extension::SIGNATURE_ALGORITHMS => Extension::SignatureAlgorithms(SignatureAlgorithms::from_reader(reader.read_reader(len)?)?),
                Extension::ENCRYPT_THE_MAC => Extension::EncryptTheMac,
                Extension::EXTEND_MASTER_SECRET => Extension::ExtendMasterSecret,
                Extension::SESSION_TICKET => Extension::SessionTicket(Buf::Ref(reader.read_slice(len)?)),
                Extension::RENEGOTIATION_INFO => {
                    reader.read_u8()?;
                    Extension::RenegotiationInfo
                }
                Extension::SUPPORTED_VERSIONS => Extension::SupportedVersions(SupportVersions::from_reader(reader.read_reader(len)?, server)?),
                Extension::PSK_KEY_EXCHANGE_MODE => {
                    let mut reader = reader.read_reader(len)?;
                    let len = reader.read_u8()? as usize;
                    let mut reader = reader.read_reader(len)?;
                    let mut res = Vec::with_capacity(10);
                    while reader.unread_len() > 0 {
                        res.push(PskMode::new(reader.read_u8()?))
                    }
                    Extension::PskKeyExchangeMode(res)
                }
                Extension::COMPRESSION_CERTIFICATE => Extension::CompressionCertificate(CompressCertificate::from_reader(reader.read_reader(len)?)?),
                Extension::ENCRYPTED_CLIENT_HELLO => {
                    if server {
                        Extension::Reserved {
                            typ,
                            value: Buf::Ref(reader.read_slice(len)?),
                        }
                    } else {
                        Extension::EncryptedClientHello(EncryptClientHello::from_reader(reader.read_reader(len)?)?)
                    }
                }
                Extension::SIGNED_CERTIFICATE_TIMESTAMP => Extension::SignedCertificateTimestamp,
                Extension::APPLICATION_SETTING => Extension::ApplicationSetting(ALPS::from_reader(reader.read_reader(len)?)?),
                Extension::KEY_SHARE => Extension::KeyShare(KeyShare::from_reader(reader.read_reader(len)?, server)?),
                Extension::APPLICATION_LAYER_PROTOCOL_NEGOTIATION => Extension::ApplicationLayerProtocolNegotiation(ALPS::from_reader(reader.read_reader(len)?)?),
                Extension::PRE_SHARED_KEY => Extension::PreSharedKey(PreSharedKey::from_reader(reader.read_reader(len)?)?),
                Extension::APPLICATION_SETTING_OLD => Extension::ApplicationSetting(ALPS::from_reader(reader.read_reader(len)?)?),
                Extension::PADDING => Extension::Padding(len),
                #[cfg(feature = "quic")]
                Extension::QUIC_TRP_PARAMETERS => {
                    let mut res = Vec::with_capacity(10);
                    let mut reader = reader.read_reader(len)?;
                    while reader.unread_len() > 0 {
                        res.push(Parameter::from_reader(&mut reader)?);
                    }
                    Extension::QUICTrpParameters(res)
                }
                _ => {
                    Extension::Reserved {
                        typ,
                        value: Buf::Ref(reader.read_slice(len)?),
                    }
                }
            });
        }
        Ok(extensions)
    }

    pub fn as_u16(&self) -> u16 {
        match self {
            Extension::ServerName(_) => Extension::SERVER_NAME,
            Extension::StatusRequest(_) => Extension::STATUS_REQUEST,
            Extension::SupportedGroups(_) => Extension::SUPPORTED_GROUP,
            Extension::EcPointFormats(_) => Extension::EC_POINT_FORMATS,
            Extension::SignatureAlgorithms(_) => Extension::SIGNATURE_ALGORITHMS,
            Extension::ApplicationLayerProtocolNegotiation(_) => Extension::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
            Extension::SignedCertificateTimestamp => Extension::SIGNED_CERTIFICATE_TIMESTAMP,
            Extension::Padding(_) => Extension::PADDING,
            Extension::EncryptTheMac => Extension::ENCRYPT_THE_MAC,
            Extension::ExtendMasterSecret => Extension::EXTEND_MASTER_SECRET,
            Extension::SessionTicket(_) => Extension::SESSION_TICKET,
            Extension::CompressionCertificate(_) => Extension::COMPRESSION_CERTIFICATE,
            Extension::SupportedVersions(_) => Extension::SUPPORTED_VERSIONS,
            Extension::PskKeyExchangeMode(_) => Extension::PSK_KEY_EXCHANGE_MODE,
            Extension::PostHandshakeAuth => Extension::POST_HANDSHAKE_AUTH,
            Extension::KeyShare(_) => Extension::KEY_SHARE,
            Extension::RenegotiationInfo => Extension::RENEGOTIATION_INFO,
            Extension::EncryptedClientHello(_) => Extension::ENCRYPTED_CLIENT_HELLO,
            Extension::ApplicationSetting(_) => Extension::APPLICATION_SETTING,
            Extension::PreSharedKey(_) => Extension::PRE_SHARED_KEY,
            Extension::ApplicationSettingOld(_) => Extension::APPLICATION_SETTING_OLD,
            #[cfg(feature = "quic")]
            Extension::QUICTrpParameters(_) => Extension::QUIC_TRP_PARAMETERS,
            Extension::Reserved { typ, .. } => *typ
        }
    }

    pub fn supported_groups(&self) -> Option<&SupportedGroups> {
        match &self {
            Extension::SupportedGroups(v) => Some(v),
            _ => None
        }
    }

    pub fn signature_algorithms(&self) -> Option<&SignatureAlgorithms> {
        match &self {
            Extension::SignatureAlgorithms(v) => Some(v),
            _ => None
        }
    }

    pub fn signature_algorithms_mut(&mut self) -> Option<&mut SignatureAlgorithms> {
        match self {
            Extension::SignatureAlgorithms(v) => Some(v),
            _ => None
        }
    }

    pub fn supported_versions(&self) -> Option<&SupportVersions> {
        match &self {
            Extension::SupportedVersions(v) => Some(v),
            _ => None
        }
    }

    pub fn supported_versions_mut(&mut self) -> Option<&mut SupportVersions> {
        match self {
            Extension::SupportedVersions(v) => Some(v),
            _ => None
        }
    }

    pub fn supported_groups_mut(&mut self) -> Option<&mut SupportedGroups> {
        match self {
            Extension::SupportedGroups(v) => Some(v),
            _ => None
        }
    }

    pub fn ec_point_formats(&self) -> Option<&EcPointFormats> {
        match self {
            Extension::EcPointFormats(v) => Some(v),
            _ => None
        }
    }

    pub fn ex_point_formats_mut(&mut self) -> Option<&mut EcPointFormats> {
        match self {
            Extension::EcPointFormats(v) => Some(v),
            _ => None
        }
    }

    pub fn is_reserved(&self) -> bool {
        match self {
            Extension::Reserved { typ, .. } => REVERSED.contains(typ),
            _ => false
        }
    }

    pub fn len(&self, server: bool) -> usize {
        4 + match self {
            Extension::ServerName(value) => 2 + value.iter().map(|x| x.len()).sum::<usize>(),
            Extension::StatusRequest(value) => value.len(),
            Extension::SupportedGroups(value) => value.len(),
            Extension::EcPointFormats(value) => value.len(),
            Extension::SignatureAlgorithms(value) => value.len(),
            Extension::ApplicationLayerProtocolNegotiation(value) => value.len(),
            Extension::SignedCertificateTimestamp => 0,
            Extension::Padding(value) => *value,
            Extension::EncryptTheMac => 0,
            Extension::ExtendMasterSecret => 0,
            Extension::SessionTicket(value) => value.len(),
            Extension::CompressionCertificate(value) => value.len(),
            Extension::SupportedVersions(value) => value.len(server),
            Extension::PskKeyExchangeMode(value) => 1 + value.len(),
            Extension::PostHandshakeAuth => 0,
            Extension::KeyShare(value) => value.len(),
            Extension::RenegotiationInfo => 1,
            Extension::EncryptedClientHello(value) => value.len(),
            Extension::ApplicationSetting(value) => value.len(),
            Extension::PreSharedKey(value) => value.len(),
            Extension::ApplicationSettingOld(value) => value.len(),
            #[cfg(feature = "quic")]
            Extension::QUICTrpParameters(value) => value.iter().map(|x| x.len()).sum::<usize>(),
            Extension::Reserved { value, .. } => value.len(),
        }
    }

    pub fn write_to(self, writer: &mut Writer, server: bool) -> Result<(), BufferError> {
        match self {
            Extension::ServerName(value) => {
                writer.write_u16(Extension::SERVER_NAME)?;
                let len = value.iter().map(|x| x.len()).sum::<usize>();
                writer.write_u16((len + 2) as u16)?;
                writer.write_u16(len as u16)?;
                for sn_typ in value.iter() {
                    sn_typ.write_to(writer)?;
                }
            }
            Extension::StatusRequest(value) => {
                writer.write_u16(Extension::STATUS_REQUEST)?;
                writer.write_u16(value.len() as u16)?;
                value.write_to(writer)?
            }
            Extension::SupportedGroups(value) => {
                writer.write_u16(Extension::SUPPORTED_GROUP)?;
                writer.write_u16(value.len() as u16)?;
                value.write_to(writer)?
            }
            Extension::EcPointFormats(value) => {
                writer.write_u16(Extension::EC_POINT_FORMATS)?;
                writer.write_u16(value.len() as u16)?;
                value.write_to(writer)?
            }
            Extension::SignatureAlgorithms(value) => {
                writer.write_u16(Extension::SIGNATURE_ALGORITHMS)?;
                writer.write_u16(value.len() as u16)?;
                value.write_to(writer)?
            }
            Extension::ApplicationLayerProtocolNegotiation(value) => {
                writer.write_u16(Extension::APPLICATION_LAYER_PROTOCOL_NEGOTIATION)?;
                writer.write_u16(value.len() as u16)?;
                value.write_to(writer)?
            }
            Extension::SignedCertificateTimestamp => {
                writer.write_u16(Extension::SIGNED_CERTIFICATE_TIMESTAMP)?;
                writer.write_u16(0)?;
            }
            Extension::Padding(size) => {
                writer.write_u16(Extension::PADDING)?;
                writer.write_u16(size as u16)?;
                writer.write_slice(&vec![0u8; size])?
            }
            Extension::EncryptTheMac => {
                writer.write_u16(Extension::ENCRYPT_THE_MAC)?;
                writer.write_u16(0)?;
            }
            Extension::ExtendMasterSecret => {
                writer.write_u16(Extension::EXTEND_MASTER_SECRET)?;
                writer.write_u16(0)?;
            }
            Extension::SessionTicket(value) => {
                writer.write_u16(Extension::SESSION_TICKET)?;
                writer.write_u16(value.len() as u16)?;
                writer.write_slice(value.as_ref())?
            }
            Extension::CompressionCertificate(value) => {
                writer.write_u16(Extension::COMPRESSION_CERTIFICATE)?;
                writer.write_u16(value.len() as u16)?;
                value.write_to(writer)?
            }
            Extension::SupportedVersions(value) => {
                writer.write_u16(Extension::SUPPORTED_VERSIONS)?;
                writer.write_u16(value.len(server) as u16)?;
                value.write_to(writer, server)?
            }
            Extension::PskKeyExchangeMode(value) => {
                writer.write_u16(Extension::PSK_KEY_EXCHANGE_MODE)?;
                writer.write_u16((1 + value.len()) as u16)?;
                writer.write_u8(value.len() as u8)?;
                for v in value {
                    writer.write_u8(v.into_inner())?
                }
            }
            Extension::PostHandshakeAuth => {
                writer.write_u16(Extension::POST_HANDSHAKE_AUTH)?;
                writer.write_u16(0)?;
            }
            Extension::KeyShare(value) => {
                writer.write_u16(Extension::KEY_SHARE)?;
                writer.write_u16(value.len() as u16)?;
                value.write_to(writer)?
            }
            Extension::RenegotiationInfo => {
                writer.write_u16(Extension::RENEGOTIATION_INFO)?;
                writer.write_u16(1)?;
                writer.write_u8(0)?;
            }
            Extension::EncryptedClientHello(value) => {
                writer.write_u16(Extension::ENCRYPTED_CLIENT_HELLO)?;
                writer.write_u16(value.len() as u16)?;
                value.write_to(writer)?
            }
            Extension::ApplicationSetting(value) => {
                writer.write_u16(Extension::APPLICATION_SETTING)?;
                writer.write_u16(value.len() as u16)?;
                value.write_to(writer)?
            }
            Extension::PreSharedKey(value) => {
                writer.write_u16(Extension::PRE_SHARED_KEY)?;
                writer.write_u16(value.len() as u16)?;
                value.write_to(writer)?
            }
            Extension::ApplicationSettingOld(value) => {
                writer.write_u16(Extension::APPLICATION_SETTING_OLD)?;
                writer.write_u16(value.len() as u16)?;
                value.write_to(writer)?
            }
            #[cfg(feature = "quic")]
            Extension::QUICTrpParameters(value) => {
                writer.write_u16(Extension::QUIC_TRP_PARAMETERS)?;
                let len = value.iter().map(|x| x.len()).sum::<usize>();
                writer.write_u16(len as u16)?;
                for p in value {
                    p.write_to(writer)?;
                }
            }
            Extension::Reserved { typ, value } => {
                writer.write_u16(typ)?;
                writer.write_u16(value.len() as u16)?;
                writer.write_slice(value.as_ref())?;
            }
        }
        Ok(())
    }

    pub fn set_server_name(&mut self, value: &'a str) {
        if let Extension::ServerName(vs) = self {
            let name = vs.iter_mut().find(|x| matches!(x, SNType::HostName(_)));
            match name {
                Some(SNType::HostName(name)) => *name = value,
                None => vs.push(SNType::HostName(value))
            }
        }
    }

    pub fn set_key_share(&mut self, key_share: KeyShare<'a>) {
        if let Extension::KeyShare(key) = self {
            *key = key_share;
        }
    }

    pub fn key_share(&self) -> Option<&KeyShare<'a>> {
        if let Extension::KeyShare(key) = self {
            Some(key)
        } else { None }
    }

    pub fn key_share_mut(&mut self) -> Option<&mut KeyShare<'a>> {
        if let Extension::KeyShare(key) = self {
            Some(key)
        } else { None }
    }

    pub fn server_name(&self) -> Option<&Vec<SNType<'a>>> {
        match self {
            Extension::ServerName(v) => Some(v),
            _ => None
        }
    }

    pub fn alps(&self) -> Option<&ALPS> {
        match self {
            Extension::ApplicationLayerProtocolNegotiation(v) => Some(v),
            _ => None
        }
    }

    pub fn alps_mut(&mut self) -> Option<&mut ALPS> {
        match self {
            Extension::ApplicationLayerProtocolNegotiation(v) => Some(v),
            _ => None
        }
    }

    pub fn remove_h2_alpn(&mut self) {
        match self {
            Extension::ApplicationSetting(v) => v.remove_h2_alpn(),
            Extension::ApplicationLayerProtocolNegotiation(v) => v.remove_h2_alpn(),
            _ => {}
        }
    }

    pub fn add_h2_alpn(&mut self) {
        match self {
            Extension::ApplicationSetting(v) => v.add_h2_alpn(),
            Extension::ApplicationLayerProtocolNegotiation(v) => v.add_h2_alpn(),
            _ => {}
        }
    }

    pub fn remove_tls13(&mut self) {
        if let Extension::SupportedVersions(v) = self { v.remove_tls13() }
    }
}

impl<'a> PartialEq<u16> for Extension<'a> {
    fn eq(&self, other: &u16) -> bool {
        match self {
            Extension::ServerName(_) => other == &Extension::SERVER_NAME,
            Extension::StatusRequest(_) => other == &Extension::STATUS_REQUEST,
            Extension::SupportedGroups(_) => other == &Extension::SUPPORTED_GROUP,
            Extension::EcPointFormats(_) => other == &Extension::EC_POINT_FORMATS,
            Extension::SignatureAlgorithms(_) => other == &Extension::SIGNATURE_ALGORITHMS,
            Extension::ApplicationLayerProtocolNegotiation(_) => other == &Extension::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
            Extension::SignedCertificateTimestamp => other == &Extension::SIGNED_CERTIFICATE_TIMESTAMP,
            Extension::Padding(_) => other == &Extension::PADDING,
            Extension::EncryptTheMac => other == &Extension::ENCRYPT_THE_MAC,
            Extension::ExtendMasterSecret => other == &Extension::EXTEND_MASTER_SECRET,
            Extension::SessionTicket(_) => other == &Extension::SESSION_TICKET,
            Extension::CompressionCertificate(_) => other == &Extension::COMPRESSION_CERTIFICATE,
            Extension::SupportedVersions(_) => other == &Extension::SUPPORTED_VERSIONS,
            Extension::PskKeyExchangeMode(_) => other == &Extension::PSK_KEY_EXCHANGE_MODE,
            Extension::PostHandshakeAuth => other == &Extension::POST_HANDSHAKE_AUTH,
            Extension::KeyShare(_) => other == &Extension::KEY_SHARE,
            Extension::RenegotiationInfo => other == &Extension::RENEGOTIATION_INFO,
            Extension::EncryptedClientHello(_) => other == &Extension::ENCRYPTED_CLIENT_HELLO,
            Extension::ApplicationSetting(_) => other == &Extension::APPLICATION_SETTING,
            Extension::PreSharedKey(_) => other == &Extension::PRE_SHARED_KEY,
            Extension::ApplicationSettingOld(_) => other == &Extension::APPLICATION_SETTING_OLD,
            #[cfg(feature = "quic")]
            Extension::QUICTrpParameters(_) => other == &Extension::QUIC_TRP_PARAMETERS,
            Extension::Reserved { typ, .. } => typ == other,
        }
    }
}

impl<'a> Display for Extension<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Extension::ServerName(_) => write!(f, "ServerName(0x{:04x})", Extension::SERVER_NAME),
            Extension::StatusRequest(_) => write!(f, "StatusRequest(0x{:04x})", Extension::STATUS_REQUEST),
            Extension::SupportedGroups(_) => write!(f, "SupportedGroups(0x{:04x})", Extension::SUPPORTED_GROUP),
            Extension::EcPointFormats(_) => write!(f, "EcPointFormats(0x{:04x})", Extension::EC_POINT_FORMATS),
            Extension::SignatureAlgorithms(_) => write!(f, "SignatureAlgorithms(0x{:04x})", Extension::EC_POINT_FORMATS),
            Extension::ApplicationLayerProtocolNegotiation(_) => write!(f, "ApplicationLayerProtocolNegotiation(0x{:04x})", Extension::APPLICATION_LAYER_PROTOCOL_NEGOTIATION),
            Extension::SignedCertificateTimestamp => write!(f, "SignedCertificateTimestamp(0x{:04x})", Extension::SIGNED_CERTIFICATE_TIMESTAMP),
            Extension::Padding(_) => write!(f, "Padding(0x{:04x})", Extension::PADDING),
            Extension::EncryptTheMac => write!(f, "EncryptTheMac(0x{:04x})", Extension::ENCRYPT_THE_MAC),
            Extension::ExtendMasterSecret => write!(f, "ExtendMasterSecret(0x{:04x})", Extension::EXTEND_MASTER_SECRET),
            Extension::SessionTicket(_) => write!(f, "SessionTicket(0x{:04x})", Extension::SESSION_TICKET),
            Extension::CompressionCertificate(_) => write!(f, "CompressionCertificate(0x{:04x})", Extension::COMPRESSION_CERTIFICATE),
            Extension::SupportedVersions(_) => write!(f, "SupportedVersions(0x{:04x})", Extension::SUPPORTED_VERSIONS),
            Extension::PskKeyExchangeMode(_) => write!(f, "PskKeyExchangeMode(0x{:04x})", Extension::PSK_KEY_EXCHANGE_MODE),
            Extension::PostHandshakeAuth => write!(f, "PostHandshakeAuth(0x{:04x})", Extension::POST_HANDSHAKE_AUTH),
            Extension::KeyShare(_) => write!(f, "KeyShare(0x{:04x})", Extension::KEY_SHARE),
            Extension::RenegotiationInfo => write!(f, "RenegotiationInfo(0x{:04x})", Extension::RENEGOTIATION_INFO),
            Extension::EncryptedClientHello(_) => write!(f, "EncryptedClientHello(0x{:04x})", Extension::ENCRYPTED_CLIENT_HELLO),
            Extension::ApplicationSetting(_) => write!(f, "ApplicationSetting(0x{:04x})", Extension::APPLICATION_SETTING),
            Extension::PreSharedKey(_) => write!(f, "PreSharedKey(0x{:04x})", Extension::PRE_SHARED_KEY),
            Extension::ApplicationSettingOld(_) => write!(f, "ApplicationSettingOld(0x{:04x})", Extension::APPLICATION_SETTING_OLD),
            #[cfg(feature = "quic")]
            Extension::QUICTrpParameters(_) => write!(f, "QUICTrpParameters(0x{:04x})", Extension::QUIC_TRP_PARAMETERS),
            Extension::Reserved { typ, .. } => write!(f, "Reserved(0x{:04x})", typ),
        }
    }
}