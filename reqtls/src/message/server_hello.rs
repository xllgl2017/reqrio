use super::super::extend::{Extension, KeyShare};
use super::super::message::HandshakeType;
use super::super::suite::CipherSuite;
use super::super::version::Version;
use crate::buffer::Buf;
use crate::error::RlsResult;
use crate::extend::alps::ALPS;
use crate::extend::ExtensionValue;
use crate::{rand, u24, BufferError, ClientHello, ExtensionType, HandShakeError, ReadExt, Reader, WriteExt, ALPN};

#[derive(Debug)]
pub struct ServerHello<'a> {
    handshake_type: HandshakeType,
    len: u24,
    version: Version,
    pub(crate) random: Buf<'a>,
    session_id_len: u8,
    pub(crate) session_id: Buf<'a>,
    pub cipher_suite: &'static CipherSuite,
    compress_method: u8,
    extend_len: u16,
    extensions: Vec<Extension<'a>>,
}

impl<'a> Default for ServerHello<'a> {
    fn default() -> Self {
        ServerHello {
            handshake_type: HandshakeType::ServerHello,
            len: 0,
            version: Version::new(0),
            random: Buf::Ref(&[]),
            session_id_len: 0,
            session_id: Buf::Ref(&[]),
            cipher_suite: &CipherSuite::UNKNOWN,
            compress_method: 0,
            extend_len: 0,
            extensions: vec![],
        }
    }
}

impl<'a> ServerHello<'a> {
    pub fn from_reader(ht: HandshakeType, reader: &mut Reader<'a>) -> RlsResult<ServerHello<'a>> {
        let mut res = ServerHello::default();
        res.handshake_type = ht;
        res.len = reader.read_u24()?;
        res.version = Version::new(reader.read_u16()?);
        res.random = Buf::Ref(reader.read_slice(32)?);
        res.session_id_len = reader.read_u8()?;
        res.session_id = Buf::Ref(reader.read_slice(res.session_id_len as usize)?);
        let suite = reader.read_u16()?;
        res.cipher_suite = CipherSuite::find(suite).ok_or(HandShakeError::UnknownCipherSuite(suite))?;
        res.compress_method = reader.read_u8()?;
        res.extend_len = reader.read_u16()?;
        res.extensions = Extension::from_reader(reader.read_reader(res.extend_len as usize)?, true)?;
        Ok(res)
    }

    pub fn from_client_hello<'b: 'a>(mut client_hello: ClientHello<'b>, alpn: ALPN) -> RlsResult<ServerHello<'a>> {
        let mut res = ServerHello {
            version: Version::TLS_1_2,
            cipher_suite: &CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            session_id_len: 32,
            session_id: Buf::Vec(rand::random::<[u8; 32]>().to_vec()),
            ..Default::default()
        };
        for extension in client_hello.take_extensions() {
            match extension.extension_type().as_u16() {
                ExtensionType::SignatureAlgorithms => {
                    // let mut signature = SignatureAlgorithms::new();
                    // signature.push_hash(SignatureAlgorithm::RSA_PKCS1_SHA256);
                    // res.extensions.push(Extension::new(ExtensionType::SignatureAlgorithms, ExtensionValue::SignatureAlgorithms(signature)));
                }
                // ExtensionType::SignedCertificateTimestamp => res.extensions.push(extension),
                ExtensionType::EcPointFormats => {
                    // let mut ec_point_formats = EcPointFormats::new();
                    // ec_point_formats.add_format(EcPointFormat::UNCOMPRESSED);
                    // res.extensions.push(Extension::new(ExtensionType::EcPointFormats, ExtensionValue::EcPointFormats(ec_point_formats)));
                }
                ExtensionType::ApplicationLayerProtocolNegotiation => {
                    let mut alps = ALPS::new(vec![]);
                    alps.add_alpn(alpn.clone());
                    res.extensions.push(Extension::new(ExtensionType::ApplicationLayerProtocolNegotiation, ExtensionValue::ApplicationLayerProtocolNegotiation(alps)));
                }
                ExtensionType::ExtendMasterSecret => res.extensions.push(extension),
                ExtensionType::SupportedVersions => {
                    // let mut version = SupportVersions::new();
                    // version.push(Version::TLS_1_2);
                    // res.extensions.push(Extension::new(ExtensionType::SupportedVersions, ExtensionValue::SupportedVersions(version)));
                }
                ExtensionType::SupportedGroup => {
                    // let mut groups = SupportedGroups::new();
                    // groups.add_group(GroupType::X25519);
                    // res.extensions.push(Extension::new(ExtensionType::SupportedGroup, ExtensionValue::SupportedGroups(groups)));
                }
                ExtensionType::RenegotiationInfo => res.extensions.push(extension),
                ExtensionType::ServerName => {}
                ExtensionType::StatusRequest => res.extensions.push(extension),
                ExtensionType::SessionTicket => res.extensions.push(Extension::from_type(ExtensionType::SessionTicket.into())),
                _ => {}
            }
        }
        Ok(res)
    }

    pub fn use_ems(&self) -> bool {
        self.extensions.iter().any(|x| x.extension_type() == &ExtensionType::ExtendMasterSecret)
    }

    pub fn alpn(&self) -> Option<ALPN> {
        let extend = self.extensions.iter().find(|x| x.alps().is_some())?;
        let protocol = extend.alps()?;
        let alpn = protocol.values().first()?.clone();
        Some(alpn)
    }

    pub fn len(&self) -> usize {
        6 + self.random.len() + 1 + self.session_id.len() + 2 + 1 + 2 +
            self.extensions.iter().map(|x| x.len(true)).sum::<usize>()
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) -> Result<(), BufferError> {
        writer.write_u8(self.handshake_type as u8)?;
        writer.write_u24(self.len() as u24 - 4)?;
        writer.write_u16(self.version.into_inner())?;
        writer.write_slice(self.random.as_ref())?;
        writer.write_u8(self.session_id.len() as u8)?;
        writer.write_slice(self.session_id.as_ref())?;
        writer.write_u16(self.cipher_suite.value())?;
        writer.write_u8(self.compress_method)?;
        let len = self.extensions.iter().map(|x| x.len(true)).sum::<usize>();
        writer.write_u16(len as u16)?;
        for extension in self.extensions {
            extension.write_to(writer, true)?;
        }
        Ok(())
    }

    pub fn random(&self) -> &Buf<'a> {
        &self.random
    }

    pub fn set_random(&mut self, random: &'a [u8]) {
        self.random = Buf::Ref(random);
    }

    pub fn set_session_id(&mut self, session_id: &'a [u8]) {
        self.session_id = Buf::Ref(session_id);
    }

    pub fn supported_version(&self) -> Option<&Version> {
        let extend = self.extensions.iter().find(|x| x.extension_type() == &ExtensionType::SupportedVersions)?;
        if let ExtensionValue::SupportedVersions(version) = extend.value() {
            version.versions().first()
        } else { None }
    }

    pub fn key_share_extend(&self) -> Option<&KeyShare<'_>> {
        let extend = self.extensions.iter().find(|x| x.extension_type() == &ExtensionType::KeyShare)?;
        if let ExtensionValue::KeyShare(key) = extend.value() {
            Some(key)
        } else { None }
    }
}

#[derive(Debug)]
pub struct ServerHelloDone {
    handshake_type: HandshakeType,
    len: u24,
}

impl ServerHelloDone {
    pub fn new() -> ServerHelloDone {
        ServerHelloDone {
            handshake_type: HandshakeType::ServerHelloDone,
            len: 0,
        }
    }

    pub fn from_reader(ht: HandshakeType, reader: &mut Reader<'_>) -> RlsResult<ServerHelloDone> {
        Ok(ServerHelloDone {
            handshake_type: ht,
            len: reader.read_u24()?,
        })
    }

    pub fn len(&self) -> usize {
        4
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) -> Result<(), BufferError> {
        writer.write_u8(self.handshake_type as u8)?;
        writer.write_u24(self.len)
    }
}