use super::super::extend::Extension;
use super::super::suite::CipherSuite;
use super::super::version::Version;
use super::HandshakeType;
use crate::boring::hash;
use crate::buffer::Buf;
use crate::error::RlsResult;
use crate::extend::alps::ALPS;
#[cfg(feature = "quic")]
use crate::extend::Parameter;
use crate::extend::SNType;
use crate::*;
use std::mem;

#[derive(Debug)]
pub struct ClientHello<'a> {
    handshake_type: HandshakeType,
    len: u24,
    version: Version,
    random: Buf<'a>,
    session_id_len: u8,
    session_id: Buf<'a>,
    cipher_suites_len: u16,
    cipher_suites: Vec<CipherSuite>,
    compress_method_len: u8,
    compress_method: Buf<'a>,
    extend_len: u16,
    extensions: Vec<Extension<'a>>,
}

impl<'a> Default for ClientHello<'a> {
    fn default() -> Self {
        ClientHello {
            handshake_type: HandshakeType::ClientHello,
            len: 0,
            version: Version::TLS_1_2,
            random: Buf::Ref(&[]),
            session_id_len: 0,
            session_id: Buf::Ref(&[]),
            cipher_suites_len: 0,
            cipher_suites: vec![],
            compress_method_len: 1,
            compress_method: Buf::Ref(&[0]),
            extend_len: 0,
            extensions: vec![],
        }
    }
}

impl<'a> ClientHello<'a> {
    pub fn from_bytes(reader: &mut Reader<'a>) -> RlsResult<ClientHello<'a>> {
        let mut res = ClientHello::default();
        res.handshake_type = HandshakeType::ClientHello;
        res.len = reader.read_u24()?;
        res.version = Version::new(reader.read_u16()?);
        res.random = Buf::Ref(reader.read_slice(32)?);
        res.session_id_len = reader.read_u8()?;
        res.session_id = Buf::Ref(reader.read_slice(res.session_id_len as usize)?);
        res.cipher_suites_len = reader.read_u16()?;
        for _ in (0..res.cipher_suites_len).step_by(2) {
            res.cipher_suites.push(CipherSuite::from(reader.read_u16()?));
        }

        res.compress_method_len = reader.read_u8()?;
        res.compress_method = Buf::Ref(reader.read_slice(res.compress_method_len as usize)?);
        res.extend_len = reader.read_u16()?;
        res.extensions = Extension::from_reader(reader.read_reader(res.extend_len as usize)?, false)?;
        Ok(res)
    }

    pub fn is_empty(&self) -> bool { self.len() == 0 }

    pub fn len(&self) -> usize {
        6 + self.random.len() + 1 + self.session_id.len() + 2 +
            self.cipher_suites.len() * 2 + 1 + self.compress_method.len() + 2
            + self.extensions.iter().map(|x| x.len(false)).sum::<usize>()
    }

    pub fn write_to(self, writer: &mut Writer) -> Result<(), BufferError> {
        writer.write_u8(self.handshake_type as u8)?;
        writer.write_u24(self.len() as u24 - 4)?;
        writer.write_u16(self.version.into_inner())?;
        writer.write_slice(self.random.as_ref())?;
        writer.write_u8(self.session_id.len() as u8)?;
        writer.write_slice(self.session_id.as_ref())?;
        let len = self.cipher_suites.iter().map(|_| 2).sum::<usize>();
        writer.write_u16(len as u16)?;
        for cipher_suite in self.cipher_suites {
            writer.write_u16(cipher_suite.value())?;
        }
        writer.write_u8(self.compress_method.len() as u8)?;
        writer.write_slice(self.compress_method.as_ref())?;
        let len = self.extensions.iter().map(|x| x.len(false)).sum::<usize>();
        writer.write_u16(len as u16)?;
        for extension in self.extensions {
            extension.write_to(writer, false)?;
        }
        Ok(())
    }

    pub fn client_random(&self) -> &Buf<'a> { &self.random }

    ///### ja3计算方式为
    /// version+','+cipher_suite(u16)+','+extend_type(u16)+','+supported_groud值(u16)+','+ec_point_format(u8)
    /// tls1.3中移除了ec_point_format
    pub fn ja3(&self) -> String {
        //[JA3 Fullstring:
        // 771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,51-35-65281-0-23-17613-18-5-65037-43-27-13-10-11-45-16,4588-29-23-24,0]
        // 771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,51-35-65281-0-23-17613-18-5-65037-43-27-13-10-11-45-16,4588-29-23-24,0
        let ver = self.version.as_u16();
        let suite = self.cipher_suites.iter().filter_map(|x| if x.is_reserved() { None } else { Some(x.value().to_string()) }).collect::<Vec<_>>();
        let ext = self.extensions.iter().filter_map(|x| if x.is_reserved() { None } else { Some(x.as_u16().to_string()) }).collect::<Vec<_>>();
        let extend = self.extensions.iter().find(|x| x.supported_groups().is_some());
        let group = if let Some(extend) = extend && let Some(group) = extend.supported_groups() {
            group.values().iter().filter_map(|x| if x.is_reserved() { None } else { Some(x.as_u16().to_string()) }).collect::<Vec<_>>()
        } else { vec![] };
        let extend = self.extensions.iter().find(|x| x.ec_point_formats().is_some());
        let formats = if let Some(extend) = extend && let Some(formats) = extend.ec_point_formats() {
            formats.formats().iter().map(|x| (*x).into_inner().to_string()).collect::<Vec<_>>()
        } else {
            vec![]
        };
        let ja3_str = format!("{},{},{},{},{}", ver, suite.join("-"), ext.join("-"), group.join("-"), formats.join("-"));
        println!("{}", ja3_str);
        hex::encode(hash::md5(ja3_str).unwrap())
    }

    ///### ja4计算方式为
    /// 't'+version+'d'+len(cipher_suites)+len(extensions)+alpn+'_'+cipher_suite(u16)+','+ec_point_format(u8)
    /// tls1.3中移除了ec_point_format
    pub fn ja4(&self) -> String {
        let ver = self.extensions.iter().find(|x| matches!(x, Extension::SupportedVersions(_)));
        let ver = ver.map(|ext| {
            let versions = ext.supported_versions()?.versions();
            let vers = versions.iter().find(|x| x.is_reverse())?;
            Some(vers.as_ja4_str())
        }).unwrap_or(Some("00")).unwrap_or("00");
        let mut suite = self.cipher_suites.iter().filter_map(|x| if x.is_reserved() {
            None
        } else {
            Some(x.value())
        }).collect::<Vec<_>>();
        suite.sort();
        let mut exts = self.extensions.iter().filter_map(|x| if x.is_reserved() || x.alps().is_some() || x.server_name().is_some() {
            None
        } else {
            Some(x.as_u16())
        }).collect::<Vec<_>>();
        exts.sort();
        let ext = self.extensions.iter().find(|x| x.alps().is_some());
        let alps = ext.map(|ext| Some(ext.alps()?.values().first()?.value())).unwrap_or(Some("00")).unwrap_or("00");
        let ext = self.extensions.iter().find(|x| x.signature_algorithms().is_some());
        let sign_algo = ext.map(|x| Some(x.signature_algorithms()?.hashes().iter().map(|x| x.as_u16()).collect::<Vec<_>>()));
        let sign_algo = sign_algo.unwrap_or(Some(vec![])).unwrap_or(vec![]);
        let suite_str = suite.iter().map(|x| hex::encode(x.to_be_bytes())).collect::<Vec<_>>().join(",");
        println!("{}", suite_str);
        let suit_hash = hex::encode(hash::sha256(suite_str).unwrap());
        let c = format!("{}_{}", exts.iter().map(|x| hex::encode(x.to_be_bytes())).collect::<Vec<_>>().join(","),
                        sign_algo.iter().map(|x| hex::encode(x.to_be_bytes())).collect::<Vec<_>>().join(","));
        println!("{}", c);
        let c_hash = hex::encode(hash::sha256(c).unwrap());

        format!("t{}d{:.2}{:02}{}_{}_{}", ver, suite.len(), exts.len(), alps, &suit_hash[..12], &c_hash[..12])
    }

    pub fn set_random(&mut self, random: &'a [u8]) {
        self.random = Buf::Ref(random);
    }

    pub fn set_session_id(&mut self, session_id: &'a [u8]) {
        self.session_id = Buf::Ref(session_id);
    }

    pub fn set_server_name(&mut self, server_name: &'a str) {
        let extend = self.extensions.iter_mut().find(|x| matches!(x, Extension::ServerName(_)));
        match extend {
            None => {
                self.extensions.push(Extension::ServerName(vec![SNType::HostName(server_name)]));
            }
            Some(ext) => ext.set_server_name(server_name),
        }
    }

    pub fn set_version(&mut self, version: Version) {
        self.version = version;
    }

    pub fn version(&mut self) -> &Version {
        &self.version
    }

    pub fn set_cipher_suites(&mut self, suites: Vec<CipherSuite>) {
        self.cipher_suites = suites;
    }

    pub fn add_extension(&mut self, extension: Extension<'a>) {
        self.extensions.push(extension);
    }

    pub fn set_extension(&mut self, extension: Vec<Extension<'a>>) {
        self.extensions = extension;
    }

    pub fn server_name(&self) -> Option<&Vec<SNType<'a>>> {
        let extension = self.extensions.iter().find(|x| matches!(x, Extension::ServerName(_)))?;
        extension.server_name()
    }

    pub fn host_name(&self) -> Option<&'a str> {
        let server_name = self.server_name()?;
        let hostname = server_name.iter().find(|x| matches!(x, SNType::HostName(_)))?;
        match hostname { SNType::HostName(name) => Some(name) }
    }

    pub fn alps(&self) -> Option<&ALPS> {
        let extension = self.extensions.iter().find(|x| **x == Extension::APPLICATION_LAYER_PROTOCOL_NEGOTIATION)?;
        extension.alps()
    }

    pub fn remove_h2_alpn(&mut self) {
        let extend = self.extensions.iter_mut().find(|x| matches!(x, Extension::ApplicationLayerProtocolNegotiation(_)));
        if let Some(ext) = extend {
            ext.remove_h2_alpn();
        }
        let extend = self.extensions.iter_mut().find(|x| matches!(x, Extension::ApplicationSetting(_)));
        if let Some(ext) = extend {
            ext.remove_h2_alpn();
        }
    }

    pub fn add_h2_alpn(&mut self) {
        let mut handle_alps = |et: u16| {
            let extend = self.extensions.iter_mut().find(|x| **x == et);
            if let Some(extend) = extend {
                extend.add_h2_alpn();
            }
        };
        handle_alps(Extension::APPLICATION_LAYER_PROTOCOL_NEGOTIATION);
        handle_alps(Extension::APPLICATION_SETTING);
        handle_alps(Extension::APPLICATION_SETTING_OLD);
    }

    pub fn cipher_suites(&self) -> &Vec<CipherSuite> {
        &self.cipher_suites
    }

    pub fn take_extensions(&mut self) -> Vec<Extension<'a>> {
        mem::take(&mut self.extensions)
    }

    pub fn extensions(&self) -> &[Extension<'a>] {
        &self.extensions
    }

    pub fn extensions_mut(&mut self) -> &mut [Extension<'a>] { &mut self.extensions }

    pub fn set_key_share(&mut self, key_share: KeyShare<'a>) {
        let extend = self.extensions.iter_mut().find(|x| matches!(x, Extension::KeyShare(_)));
        match extend {
            None => self.extensions.push(Extension::KeyShare(key_share)),
            Some(extend) => extend.set_key_share(key_share),
        }
    }

    pub fn set_session_ticket(&mut self, ticket: &'a [u8]) {
        let extend = self.extensions.iter_mut().find(|x| matches!(x, Extension::SessionTicket(_)));
        if let Some(Extension::SessionTicket(value)) = extend {
            *value = Buf::Ref(ticket);
        }
    }

    pub fn padding(&self) -> usize {
        let extend = self.extensions.iter().find(|x| matches!(x, Extension::Padding(_)));
        if let Some(Extension::Padding(value)) = extend {
            *value
        } else { 0 }
    }

    pub fn set_padding(&mut self, padding: usize) {
        let extend = self.extensions.iter_mut().find(|x| matches!(x, Extension::Padding(_)));
        if let Some(Extension::Padding(value)) = extend {
            *value = padding;
        }
    }

    pub fn remove_padding(&mut self) {
        let extend = self.extensions.iter().position(|x| matches!(x, Extension::Padding(_)));
        if let Some(index) = extend {
            self.extensions.remove(index);
        }
    }

    pub fn key_share_mut(&mut self) -> Option<&mut KeyShare<'a>> {
        let extend = self.extensions.iter_mut().find(|x| matches!(x, Extension::KeyShare(_)))?;
        extend.key_share_mut()
    }

    pub fn remove_tls13(&mut self) {
        let pos = self.extensions.iter().position(|x| matches!(x, Extension::PreSharedKey(_)));
        if let Some(pos) = pos {
            self.extensions.remove(pos);
        }
        let extend = self.extensions.iter_mut().find(|x| matches!(x, Extension::SupportedVersions(_)));
        if let Some(ext) = extend {
            ext.remove_tls13()
        }
    }

    #[cfg(feature = "quic")]
    pub fn build_quic(&mut self) -> RlsResult<()> {
        if self.key_share_mut().is_none() { return Err(HandShakeError::QUICMissingKeyShare.into()); };
        let extend = self.extensions.iter_mut().find(|x| matches!(x, Extension::SupportedVersions(_)));
        let extend = extend.ok_or(HandShakeError::MissingSupportedVersions)?;
        let mut sv = SupportVersions::default();
        sv.push(Version::TLS_1_3);
        let sve = Extension::SupportedVersions(sv);
        *extend = sve;
        let extend = self.extensions.iter_mut().find(|x| matches!(x, Extension::QUICTrpParameters(_)));
        if extend.is_none() {
            let params = vec![
                Parameter::new(0x20, Buf::Ref(&[128, 1, 0, 0])),
                Parameter::new(0x11, Buf::Ref(&[0, 0, 0, 1, 170, 250, 234, 186, 0, 0, 0, 1])),
                Parameter::new(0x3127, Buf::Ref(&[128, 3, 51, 213])),
                Parameter::new(0x04, Buf::Ref(&[128, 240, 0, 0])),
                Parameter::new(0x07, Buf::Ref(&[128, 96, 0, 0])),
                Parameter::new(0x0f, Buf::Ref(&[])),
                Parameter::new(0x18277593fbc5055c, Buf::Ref(&[78, 94, 216, 125, 2, 63, 129, 138, 65, 161, 185, 105])),
                Parameter::new(0x06, Buf::Ref(&[128, 96, 0, 0])),
                Parameter::new(0x01, Buf::Ref(&[128, 0, 117, 48])),
                Parameter::new(0x09, Buf::Ref(&[64, 103])),
                Parameter::new(0x05, Buf::Ref(&[128, 96, 0, 0])),
                Parameter::new(0x08, Buf::Ref(&[64, 100])),
                Parameter::new(0x03, Buf::Ref(&[69, 192]))
            ];
            let qte = Extension::QUICTrpParameters(params);
            self.extensions.insert(0, qte);
        }
        if let Some(extend) = self.extensions.iter_mut().find(|x| **x == Extension::APPLICATION_LAYER_PROTOCOL_NEGOTIATION) {
            let alps = ALPS::new(vec![ALPN::Http30]);
            *extend = Extension::ApplicationLayerProtocolNegotiation(alps);
        }
        if let Some(extend) = self.extensions.iter_mut().find(|x| matches!(x, Extension::ApplicationSetting(_))) {
            let alps = ALPS::new(vec![ALPN::Http30]);
            *extend = Extension::ApplicationSetting(alps);
        }
        if let Some(extend) = self.extensions.iter_mut().find(|x| matches!(x, Extension::ApplicationSettingOld(_))) {
            let alps = ALPS::new(vec![ALPN::Http30]);
            *extend = Extension::ApplicationSettingOld(alps);
        }
        let mut suites = vec![];
        if self.cipher_suites.contains(&CipherSuite::TLS_AES_128_GCM_SHA256) {
            suites.push(CipherSuite::TLS_AES_128_GCM_SHA256);
        }
        if self.cipher_suites.contains(&CipherSuite::TLS_AES_256_GCM_SHA384) {
            suites.push(CipherSuite::TLS_AES_256_GCM_SHA384);
        }
        if self.cipher_suites.contains(&CipherSuite::TLS_CHACHA20_POLY1305_SHA256) {
            suites.push(CipherSuite::TLS_CHACHA20_POLY1305_SHA256);
        }
        let pos = self.extensions.iter().position(|x| matches!(x, Extension::EcPointFormats(_)));
        if let Some(pos) = pos {
            self.extensions.remove(pos);
        }
        let pos = self.extensions.iter().position(|x| matches!(x, Extension::ExtendMasterSecret));
        if let Some(pos) = pos {
            self.extensions.remove(pos);
        }
        let pos = self.extensions.iter().position(|x| matches!(x, Extension::SessionTicket(_)));
        if let Some(pos) = pos {
            self.extensions.remove(pos);
        }
        let pos = self.extensions.iter().position(|x| matches!(x, Extension::EncryptedClientHello(_)));
        if let Some(pos) = pos {
            self.extensions.remove(pos);
        }
        self.cipher_suites = suites;
        self.session_id = Buf::Ref(&[]);
        Ok(())
    }

    pub fn remove_server_name(&mut self) {
        let pos = self.extensions.iter_mut().position(|x| matches!(x, Extension::ServerName(_)));
        if let Some(pos) = pos {
            self.extensions.remove(pos);
        }
    }
}
