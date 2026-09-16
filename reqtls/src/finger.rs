use crate::buffer::Buf;
use crate::error::RlsResult;
use crate::extend::SignatureAlgorithms;
use crate::extend::alps::ALPS;
use crate::extend::group::SupportedGroups;
use crate::extend::{CompressCertificate, Extension, StatusRequest};
use crate::*;
#[cfg(debug_assertions)]
use std::fmt::Debug;

#[cfg_attr(debug_assertions, derive(Debug))]
pub enum TlsFinger {
    Default,
    ClientHello {
        ///record layer version
        record_version: Version,
        ///client hello bytes
        bytes: Buf<'static>,
    },
    Custom {
        ///record layer version
        record_version: Version,
        ///handshake message version
        message_version: Version,
        ///cipher suites
        suites: Vec<CipherSuite>,
        ///extension
        extensions: Vec<Extension<'static>>,
    },
}

impl TlsFinger {
    const DEFAULT_TLS: [u8; 1815] = [22, 3, 1, 7, 18, 1, 0, 7, 14, 3, 3, 72, 133, 60, 49, 150, 191, 27, 170, 23, 106, 202, 192, 176, 254, 96, 142, 56, 79, 100, 164, 140, 185, 209, 110, 177, 124, 82, 223, 185, 167, 59, 211, 32, 26, 94, 33, 117, 55, 188, 58, 243, 227, 20, 228, 216, 150, 57, 186, 118, 206, 37, 17, 64, 9, 220, 44, 34, 53, 102, 7, 48, 196, 227, 137, 154, 0, 32, 218, 218, 19, 1, 19, 2, 19, 3, 192, 43, 192, 47, 192, 44, 192, 48, 204, 169, 204, 168, 192, 19, 192, 20, 0, 156, 0, 157, 0, 47, 0, 53, 1, 0, 6, 165, 26, 26, 0, 0, 0, 45, 0, 2, 1, 1, 0, 11, 0, 2, 1, 0, 0, 5, 0, 5, 1, 0, 0, 0, 0, 0, 51, 4, 239, 4, 237, 250, 250, 0, 1, 0, 17, 236, 4, 192, 195, 153, 180, 75, 128, 46, 167, 137, 131, 30, 38, 37, 235, 214, 138, 19, 107, 113, 62, 128, 165, 2, 51, 162, 45, 188, 128, 2, 166, 170, 176, 123, 163, 175, 217, 53, 226, 243, 21, 221, 183, 45, 250, 74, 148, 247, 90, 116, 148, 218, 117, 155, 3, 120, 15, 85, 138, 61, 10, 6, 8, 163, 141, 138, 242, 18, 45, 28, 204, 163, 169, 18, 27, 83, 135, 233, 218, 70, 217, 19, 181, 57, 176, 201, 214, 180, 166, 138, 154, 21, 248, 37, 137, 43, 38, 206, 112, 129, 91, 21, 154, 125, 238, 119, 171, 126, 165, 180, 253, 48, 185, 242, 2, 129, 139, 166, 199, 85, 26, 101, 240, 17, 101, 67, 7, 179, 52, 113, 110, 102, 118, 81, 196, 231, 162, 165, 225, 79, 244, 59, 39, 31, 230, 39, 39, 50, 70, 38, 134, 40, 21, 123, 100, 26, 98, 117, 30, 48, 178, 99, 101, 127, 22, 8, 104, 216, 215, 184, 9, 84, 57, 217, 121, 65, 117, 152, 116, 148, 60, 106, 18, 218, 146, 183, 209, 70, 228, 232, 112, 164, 233, 5, 65, 162, 59, 124, 90, 177, 198, 68, 143, 113, 136, 86, 58, 9, 124, 95, 120, 163, 73, 7, 55, 55, 215, 163, 124, 219, 8, 188, 176, 156, 166, 220, 49, 180, 34, 146, 96, 216, 138, 147, 199, 169, 72, 65, 30, 125, 163, 179, 9, 196, 25, 135, 119, 27, 248, 199, 17, 81, 170, 155, 196, 54, 159, 21, 21, 70, 53, 135, 196, 35, 135, 187, 72, 197, 40, 70, 73, 27, 29, 146, 39, 192, 104, 111, 161, 84, 146, 70, 244, 68, 36, 170, 37, 142, 68, 59, 67, 16, 150, 236, 44, 205, 55, 122, 136, 226, 76, 152, 34, 146, 54, 250, 1, 107, 171, 129, 84, 102, 196, 14, 234, 225, 52, 202, 119, 112, 67, 72, 162, 182, 98, 124, 190, 213, 81, 209, 234, 13, 175, 99, 82, 6, 212, 37, 246, 0, 199, 62, 220, 75, 152, 192, 43, 223, 11, 94, 252, 123, 115, 206, 117, 162, 146, 64, 67, 226, 67, 108, 148, 71, 113, 99, 2, 89, 240, 81, 107, 48, 181, 41, 166, 64, 98, 179, 9, 141, 200, 52, 56, 82, 229, 152, 136, 124, 136, 219, 170, 11, 44, 112, 155, 26, 88, 148, 25, 22, 186, 78, 219, 156, 174, 201, 14, 182, 249, 48, 249, 218, 92, 181, 139, 184, 85, 134, 43, 89, 38, 62, 237, 163, 29, 42, 6, 168, 151, 99, 184, 56, 209, 15, 106, 12, 49, 153, 193, 177, 11, 204, 157, 21, 73, 176, 232, 96, 161, 240, 144, 22, 152, 195, 80, 183, 235, 94, 134, 16, 79, 246, 49, 54, 31, 214, 190, 236, 44, 119, 128, 99, 98, 131, 60, 46, 250, 48, 99, 129, 12, 134, 250, 167, 181, 171, 146, 56, 158, 171, 37, 131, 32, 38, 95, 178, 63, 13, 122, 43, 58, 154, 173, 3, 201, 70, 4, 203, 67, 213, 50, 55, 99, 20, 178, 232, 212, 207, 237, 218, 54, 181, 120, 181, 144, 230, 20, 110, 161, 140, 104, 71, 160, 86, 156, 131, 24, 166, 134, 32, 242, 148, 233, 217, 135, 93, 1, 69, 73, 105, 91, 211, 202, 104, 196, 48, 87, 112, 146, 163, 117, 172, 58, 55, 32, 58, 3, 54, 193, 225, 52, 180, 90, 242, 84, 139, 204, 200, 206, 7, 94, 78, 116, 163, 112, 241, 109, 75, 203, 201, 12, 140, 180, 46, 208, 155, 93, 208, 92, 98, 5, 40, 217, 218, 198, 104, 51, 188, 2, 231, 115, 73, 103, 198, 167, 204, 75, 235, 233, 91, 133, 215, 39, 91, 151, 108, 154, 192, 153, 126, 178, 100, 160, 166, 132, 212, 39, 149, 18, 5, 74, 50, 88, 163, 158, 96, 79, 30, 193, 72, 202, 33, 48, 210, 154, 26, 185, 43, 83, 193, 176, 171, 78, 227, 128, 95, 51, 146, 1, 233, 104, 132, 123, 120, 115, 145, 117, 253, 105, 81, 129, 183, 167, 206, 80, 11, 211, 26, 6, 133, 146, 110, 4, 213, 206, 109, 43, 97, 40, 69, 186, 104, 211, 159, 97, 124, 33, 175, 167, 95, 38, 188, 169, 92, 23, 80, 118, 152, 175, 40, 12, 12, 95, 33, 137, 10, 183, 138, 142, 86, 177, 233, 69, 9, 178, 38, 6, 102, 36, 167, 198, 112, 28, 58, 228, 97, 197, 65, 97, 231, 213, 118, 2, 121, 172, 193, 103, 204, 1, 144, 139, 125, 74, 25, 87, 100, 89, 233, 182, 39, 108, 226, 199, 145, 153, 8, 81, 251, 159, 139, 25, 124, 240, 201, 109, 225, 251, 97, 205, 28, 19, 194, 34, 197, 25, 65, 130, 237, 196, 105, 94, 41, 93, 84, 165, 6, 250, 9, 176, 136, 17, 105, 166, 243, 42, 138, 252, 10, 205, 86, 68, 135, 107, 94, 105, 129, 5, 243, 106, 86, 161, 106, 175, 73, 4, 30, 163, 74, 146, 97, 153, 105, 185, 131, 2, 93, 88, 94, 230, 241, 188, 250, 19, 30, 153, 84, 49, 178, 179, 166, 139, 81, 69, 52, 165, 153, 175, 28, 19, 173, 9, 93, 56, 203, 69, 138, 26, 138, 199, 245, 21, 36, 80, 49, 102, 166, 60, 246, 216, 150, 58, 168, 154, 32, 195, 112, 19, 152, 70, 114, 247, 154, 155, 225, 63, 147, 113, 157, 137, 231, 101, 168, 42, 71, 117, 213, 49, 179, 235, 203, 139, 76, 41, 53, 81, 11, 166, 167, 112, 188, 16, 168, 164, 236, 96, 240, 26, 154, 32, 37, 0, 80, 217, 108, 83, 84, 84, 245, 182, 155, 140, 248, 192, 12, 68, 121, 15, 57, 100, 161, 244, 178, 250, 188, 90, 133, 240, 97, 52, 140, 137, 227, 186, 23, 151, 192, 194, 107, 243, 187, 202, 215, 13, 147, 130, 47, 147, 42, 24, 202, 124, 160, 207, 134, 108, 107, 27, 77, 226, 87, 22, 6, 240, 30, 178, 229, 171, 59, 231, 25, 201, 19, 112, 242, 147, 99, 162, 24, 170, 207, 64, 40, 77, 198, 195, 197, 150, 113, 223, 75, 98, 213, 228, 78, 129, 3, 156, 52, 152, 36, 138, 118, 89, 240, 7, 73, 150, 83, 62, 128, 151, 160, 174, 227, 137, 166, 217, 174, 147, 100, 179, 166, 75, 207, 78, 87, 111, 103, 128, 43, 137, 148, 58, 224, 58, 36, 210, 119, 39, 38, 136, 127, 95, 200, 3, 147, 49, 17, 212, 170, 53, 218, 48, 167, 139, 86, 11, 180, 236, 45, 201, 24, 163, 153, 130, 129, 240, 70, 9, 63, 137, 121, 25, 7, 142, 189, 240, 94, 199, 247, 206, 3, 49, 26, 121, 188, 73, 203, 83, 115, 34, 232, 198, 166, 171, 190, 86, 165, 95, 110, 21, 85, 227, 132, 186, 111, 169, 196, 248, 224, 24, 157, 54, 80, 194, 106, 238, 103, 203, 231, 4, 215, 70, 80, 34, 194, 89, 182, 83, 67, 97, 101, 28, 155, 109, 113, 252, 152, 225, 143, 132, 255, 138, 161, 243, 232, 128, 188, 219, 216, 237, 221, 68, 14, 61, 126, 153, 88, 11, 217, 188, 127, 131, 244, 68, 218, 167, 97, 68, 44, 26, 98, 93, 197, 212, 77, 163, 97, 0, 29, 0, 32, 175, 160, 194, 30, 154, 179, 79, 17, 87, 50, 236, 184, 230, 181, 216, 51, 121, 196, 102, 8, 17, 115, 141, 139, 229, 96, 202, 253, 228, 70, 253, 11, 0, 0, 0, 14, 0, 12, 0, 0, 9, 51, 56, 104, 109, 122, 103, 46, 99, 110, 0, 43, 0, 7, 6, 74, 74, 3, 4, 3, 3, 0, 10, 0, 12, 0, 10, 250, 250, 17, 236, 0, 29, 0, 23, 0, 24, 0, 35, 0, 0, 0, 27, 0, 3, 2, 0, 2, 68, 105, 0, 5, 0, 3, 2, 104, 50, 0, 23, 0, 0, 254, 13, 1, 26, 0, 0, 1, 0, 1, 150, 0, 32, 203, 61, 233, 47, 49, 239, 207, 205, 90, 83, 199, 159, 190, 50, 0, 193, 244, 129, 227, 113, 153, 170, 41, 6, 73, 241, 171, 173, 110, 213, 3, 30, 0, 240, 220, 183, 36, 192, 65, 53, 109, 119, 236, 247, 207, 33, 54, 150, 238, 41, 27, 84, 158, 228, 139, 2, 130, 81, 214, 221, 222, 152, 101, 88, 110, 169, 151, 172, 208, 165, 33, 7, 153, 57, 95, 217, 104, 39, 56, 207, 96, 157, 217, 154, 156, 130, 158, 251, 197, 186, 131, 255, 194, 216, 147, 43, 85, 24, 134, 181, 193, 235, 193, 172, 18, 51, 39, 62, 92, 207, 232, 250, 30, 80, 251, 8, 18, 240, 95, 15, 203, 96, 118, 114, 169, 52, 199, 120, 172, 201, 152, 23, 61, 116, 110, 134, 114, 242, 170, 107, 96, 239, 166, 99, 105, 255, 215, 192, 59, 157, 125, 207, 63, 195, 240, 205, 178, 85, 52, 125, 131, 148, 218, 226, 38, 21, 177, 76, 95, 246, 38, 250, 142, 101, 181, 217, 50, 120, 218, 152, 15, 48, 127, 33, 175, 26, 18, 76, 171, 120, 219, 109, 65, 209, 207, 230, 157, 127, 26, 185, 0, 56, 247, 210, 9, 248, 94, 125, 125, 90, 208, 69, 162, 202, 72, 69, 105, 50, 13, 202, 227, 243, 59, 22, 57, 146, 240, 230, 130, 104, 137, 157, 61, 171, 219, 131, 243, 23, 127, 17, 95, 151, 209, 101, 186, 84, 94, 249, 193, 147, 161, 106, 188, 138, 211, 178, 77, 69, 138, 245, 68, 251, 85, 50, 24, 19, 110, 141, 250, 18, 48, 170, 0, 12, 0, 16, 0, 14, 0, 12, 2, 104, 50, 8, 104, 116, 116, 112, 47, 49, 46, 49, 0, 18, 0, 0, 0, 13, 0, 18, 0, 16, 4, 3, 8, 4, 4, 1, 5, 3, 8, 5, 5, 1, 8, 6, 6, 1, 255, 1, 0, 1, 0, 234, 234, 0, 1, 0];
    pub const DEFAULT: &'static TlsFinger = &TlsFinger::Default;
    pub fn build_client_hello(&self, alpn: &ALPN) -> Result<ClientHello<'_>, RlsError> {
        match self {
            TlsFinger::Default => {
                let mut reader = Reader::from_slice(&Self::DEFAULT_TLS[5..]);
                reader.read_u8()?;
                let mut res = ClientHello::from_bytes(&mut reader)?;
                match alpn {
                    h2 if h2 == ALPN::HTTP20 => res.add_h2_alpn(),
                    _ => res.remove_h2_alpn()
                }
                Ok(res)
            }
            TlsFinger::ClientHello { bytes, .. } => {
                let mut reader = Reader::from_slice(bytes.as_ref());
                reader.read_u8()?;
                ClientHello::from_bytes(&mut reader)
            }
            TlsFinger::Custom { suites, extensions, message_version, .. } => {
                let mut client_hello = ClientHello::default();
                client_hello.set_version(*message_version);
                client_hello.set_cipher_suites(suites.clone());
                client_hello.set_extension(extensions.clone());
                Ok(client_hello)
            }
        }
    }

    pub fn record_version(&self) -> Version {
        match self {
            TlsFinger::Default => Version::TLS_1_0,
            TlsFinger::ClientHello { record_version, .. } => *record_version,
            TlsFinger::Custom { record_version, .. } => *record_version,
        }
    }

    fn random_formats() -> Vec<EcPointFormat> {
        let mut ec_formats: Vec<EcPointFormat> = vec![];
        while ec_formats.len() < 3 {
            let format = EcPointFormat::ALL[rand::random::<usize>() % 3];
            if ec_formats.iter().any(|x| x == &format) { continue; }
            ec_formats.push(format);
        }
        ec_formats
    }

    fn random_algorithms() -> Vec<SignatureAlgorithm> {
        let mut algorithms: Vec<SignatureAlgorithm> = vec![
            SignatureAlgorithm::RSA_PSS_RSAE_SHA256.into(),
            SignatureAlgorithm::ECDSA_SECP256R1_SHA256.into(),
            SignatureAlgorithm::RSA_PKCS1_SHA256.into(),
        ];
        while algorithms.len() < 16 {
            let alg = SignatureAlgorithm::ALL[rand::random::<usize>() % 23];
            if algorithms.iter().any(|x| x == alg) { continue; }
            algorithms.push(alg.into());
        }
        algorithms
    }

    pub fn random() -> TlsFinger {
        let mut suites: Vec<CipherSuite> = vec![
            CipherSuite::TLS_AES_128_GCM_SHA256,
            CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        ];
        while suites.len() < 16 {
            let suite = CipherSuite::ALL[rand::random::<usize>() % 31];
            if suites.contains(&suite) { continue; }
            suites.push(suite);
        }
        let mut groups: Vec<NamedCurve> = vec![NamedCurve::X25519.into(), NamedCurve::SecP256r1.into()];
        while groups.len() < 5 {
            let group = NamedCurve::ALL[rand::random::<usize>() % 11];
            if groups.iter().any(|x| x == group) { continue; }
            groups.push(group.into());
        }
        let mut versions: Vec<Version> = vec![Version::TLS_1_2];
        while versions.len() < 3 {
            let ver = Version::ALL[rand::random::<usize>() % 4];
            if versions.iter().any(|x| x == &ver) { continue; }
            versions.push(ver);
        }

        TlsFinger::Custom {
            record_version: Version::TLS_1_0,
            message_version: Version::TLS_1_2,
            suites,
            extensions: vec![
                Extension::SignatureAlgorithms(SignatureAlgorithms::new(TlsFinger::random_algorithms())),
                Extension::SupportedGroups(SupportedGroups::new(groups.clone())),
                Extension::KeyShare(KeyShare::new(groups)),
                Extension::CompressionCertificate(CompressCertificate::new(vec![CompressionMethod::NULL])),
                Extension::SupportedVersions(SupportVersions::new(versions)),
                Extension::ApplicationLayerProtocolNegotiation(ALPS::new(vec![ALPN::HTTP20, ALPN::HTTP11])),
                Extension::ServerName(vec![ServerName::new_sni("")]),
                Extension::EcPointFormats(EcPointFormats::new(TlsFinger::random_formats())),
                Extension::RenegotiationInfo,
                Extension::ExtendMasterSecret,
                Extension::StatusRequest(StatusRequest::new()),
            ],
        }
    }

    pub fn from_ja3(ja3: impl AsRef<str>) -> RlsResult<TlsFinger> {
        let items = ja3.as_ref().split(",").collect::<Vec<_>>();
        let mut versions = vec![];
        let version = items.first().ok_or("version not found")?.parse::<u16>()?;
        for v in Version::ALL {
            if v < version { continue; }
            versions.insert(0, v);
        }
        let mut suites: Vec<CipherSuite> = vec![];
        for suite in items.get(1).ok_or("suites not found")?.split("-") {
            suites.push(suite.parse::<u16>()?.into());
        }
        let mut groups: Vec<NamedCurve> = vec![];
        for kid in items.get(3).ok_or("groups not found")?.split("-") {
            groups.push(NamedCurve::new(kid.parse()?));
        }
        let mut ec_formats: Vec<EcPointFormat> = vec![];
        for ft in items.get(4).ok_or("fts not found")?.split("-") {
            ec_formats.push(EcPointFormat::new(ft.parse()?));
        }
        let mut extensions = vec![];
        for ext in items.get(2).ok_or("exts not found")?.split("-") {
            let typ = ext.parse::<u16>()?;
            extensions.push(match typ {
                Extension::SUPPORTED_VERSIONS => Extension::SupportedVersions(SupportVersions::new(versions.clone())),
                Extension::SUPPORTED_GROUP => Extension::SupportedGroups(SupportedGroups::new(groups.clone())),
                Extension::KEY_SHARE => Extension::KeyShare(KeyShare::new(groups.clone())),
                Extension::EC_POINT_FORMATS => Extension::EcPointFormats(EcPointFormats::new(ec_formats.clone())),
                Extension::SIGNATURE_ALGORITHMS => Extension::SignatureAlgorithms(SignatureAlgorithms::new(TlsFinger::random_algorithms())),
                Extension::COMPRESSION_CERTIFICATE => Extension::CompressionCertificate(CompressCertificate::new(vec![CompressionMethod::NULL])),
                _ => match Extension::default_value(typ) {
                    None => Extension::Reserved { typ, value: Buf::Ref(&[]) },
                    Some(extend) => extend,
                }
            });
        }
        Ok(TlsFinger::Custom {
            record_version: Version::TLS_1_0,
            message_version: Version::TLS_1_2,
            suites,
            extensions,
        })
    }

    pub fn from_ja4(ja4: impl AsRef<str>) -> RlsResult<TlsFinger> {
        let items = ja4.as_ref().split("_").collect::<Vec<_>>();
        if items.len() != 4 { return Err("ja4 is error".into()); }
        let mut algorithms: Vec<SignatureAlgorithm> = vec![];
        for algo in items[3].split(",") {
            algorithms.push(SignatureAlgorithm::new(u16::from_str_radix(algo, 16)?));
        }

        let mut suites: Vec<CipherSuite> = vec![];
        for suite in items[1].split(",") {
            suites.push(u16::from_str_radix(suite, 16)?.into());
        }

        let versions = match &items[0][1..3] {
            "13" => vec![Version::TLS_1_3, Version::TLS_1_2, Version::TLS_1_1, Version::TLS_1_0],
            "12" => vec![Version::TLS_1_2, Version::TLS_1_1, Version::TLS_1_1],
            "11" => vec![Version::TLS_1_1, Version::TLS_1_0],
            "10" => vec![Version::TLS_1_0],
            _ => return Err("unknown tls version".into()),
        };
        let mut groups: Vec<NamedCurve> = vec![];
        while groups.len() < 5 {
            let group = NamedCurve::ALL[rand::random::<usize>() % 5];
            if groups.iter().any(|x| x == group) { continue; }
            groups.push(group.into());
        }

        let mut extensions = vec![];
        for ext in items.get(2).ok_or("exts not found")?.split(",") {
            let typ = u16::from_str_radix(ext, 16)?;
            extensions.push(match typ {
                Extension::SUPPORTED_VERSIONS => Extension::SupportedVersions(SupportVersions::new(versions.clone())),
                Extension::SUPPORTED_GROUP => Extension::SupportedGroups(SupportedGroups::new(groups.clone())),
                Extension::KEY_SHARE => Extension::KeyShare(KeyShare::new(groups.clone())),
                Extension::SIGNATURE_ALGORITHMS => Extension::SignatureAlgorithms(SignatureAlgorithms::new(algorithms.clone())),
                Extension::COMPRESSION_CERTIFICATE => Extension::CompressionCertificate(CompressCertificate::new(vec![CompressionMethod::BROTLI])),
                Extension::EC_POINT_FORMATS => Extension::EcPointFormats(EcPointFormats::new(TlsFinger::random_formats())),
                _ => match Extension::default_value(typ) {
                    None => Extension::Reserved { typ, value: Buf::Ref(&[]) },
                    Some(extend) => extend,
                }
            });
        }
        extensions.push(Extension::ServerName(vec![ServerName::new_sni("")]));
        extensions.push(Extension::ApplicationLayerProtocolNegotiation(ALPS::new(vec![ALPN::HTTP20, ALPN::HTTP11])));
        Ok(TlsFinger::Custom {
            record_version: Version::TLS_1_0,
            message_version: Version::TLS_1_2,
            suites,
            extensions,
        })
    }

    ///record hex prefix: 220303
    pub fn from_record_hex(record: impl AsRef<str>) -> RlsResult<TlsFinger> {
        let mut client_hello = hex::decode(record.as_ref())?;
        let ver = Version::new(u16::from_be_bytes([client_hello[1], client_hello[2]]));
        let len = u16::from_be_bytes([client_hello[3], client_hello[4]]) as usize + 5;
        let _ = client_hello.split_off(len);
        let client_hello = client_hello.split_off(5);
        Ok(TlsFinger::ClientHello { record_version: ver, bytes: Buf::Vec(client_hello) })
    }

    pub fn add_cipher_suite(&mut self, suite: CipherSuite) {
        if let TlsFinger::Custom { suites, .. } = self {
            suites.push(suite);
        }
    }

    pub fn add_extension(&mut self, value: Extension<'static>) {
        if let TlsFinger::Custom { extensions, .. } = self {
            extensions.push(value)
        }
    }

    pub fn find_mut(&mut self, typ: u16) -> Option<&mut Extension<'static>> {
        match self {
            TlsFinger::Default => None,
            TlsFinger::ClientHello { .. } => None,
            TlsFinger::Custom { extensions, .. } => extensions.iter_mut().find(|x| **x == typ)
        }
    }
}