mod handshake;
#[cfg(feature = "quic")]
mod quic;

use crate::boring::EvpError;
use crate::cipher::CipherError;
use crate::coder::CodingError;
use crate::dns::DNSError;
use crate::hash::HashError;
use crate::url::UrlError;
use crate::{Alert, BufferError, SmError};
pub use handshake::HandShakeError;
use hex::FromHexError;
#[cfg(feature = "quic")]
pub use quic::QUICError;
use std::array::TryFromSliceError;
use std::convert::Infallible;
use std::error::Error;
use std::ffi::NulError;
use std::fmt::{Display, Formatter};
use std::io;
use std::net::AddrParseError;
use std::num::ParseIntError;
use std::str::Utf8Error;
use std::string::FromUtf8Error;
use std::sync::PoisonError;
use std::time::SystemTimeError;

#[derive(Debug)]
pub enum RlsError {
    NullPtr,
    ClientHelloNone,
    EncrypterNone,
    DecrypterNone,
    PayloadNone,
    GenKeyFromAeadNone,
    AeadNone,
    InvalidCipherSuite,
    AeadCryptError,
    AeadEncryptError,
    AeadDecryptError,
    InitEvpCtxError,
    DigestSignError,
    DigestVerifyError,
    RsaNewError,
    BnNewError,
    BnSetWordError,
    RsaGenKeyError,
    PkeyNewError,
    PkeyAssignError,
    BioNewError,
    WritePriKeyError,
    WritePubKeyError,
    RsaSetPaddingError,
    PkeyEncryptError,
    InitEncryptError,
    InitDecryptError,
    PkeyDecryptError,
    OpenX509Error,
    SetRsaMgf1MdError,
    SetRsaPassSaltLenError,
    CertSniInvalid,
    GenEcPubKeyError,
    SkNewError,
    SkPushError,
    X509StoreNewError,
    X509StoreCtxNewError,
    X509StoreCtxInitError,
    X509StoreAddError,
    IssuerUnknown,
    X509NewError,
    X509SetVersionFail,
    NewAsn1IntegerError,
    NewX509NameError,
    X509AddNameError,
    X509SetSubjectError,
    X509SetIssuerError,
    NewX509ExtError,
    X509AddExtFail,
    X509SignError,
    BIOWriteError,
    BIOGetDataError,
    GetAiaFail,
    MissingCertificateChain,
    MissingKeyEntry,
    HandShake(HandShakeError),
    Buffer(BufferError),
    Url(UrlError),
    Currently(String),
    Alert(Alert),
    HasherError(HashError),
    DNSError(DNSError),
    EvpError(EvpError),
    Cipher(CipherError),
    Coding(CodingError),
    Sm(SmError),
}

impl Display for RlsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RlsError::NullPtr => write!(f, "NullPtr"),
            RlsError::ClientHelloNone => f.write_str("Client hello none"),
            RlsError::EncrypterNone => f.write_str("Encrypter none"),
            RlsError::DecrypterNone => f.write_str("Decrypter none"),
            RlsError::PayloadNone => f.write_str("Payload none"),
            RlsError::GenKeyFromAeadNone => f.write_str("get key from aead none"),
            RlsError::AeadNone => f.write_str("Aead none"),
            RlsError::InvalidCipherSuite => f.write_str("Invalid suite suite"),
            RlsError::AeadCryptError => f.write_str("Init aead crypto error"),
            RlsError::AeadEncryptError => f.write_str("Aead encrypt error"),
            RlsError::AeadDecryptError => f.write_str("Aead decrypt error"),
            RlsError::InitEvpCtxError => f.write_str("Init Evp ctx error"),
            RlsError::DigestSignError => f.write_str("Digest sign error"),
            RlsError::DigestVerifyError => f.write_str("Digest verify error"),
            RlsError::RsaNewError => f.write_str("Rsa new error"),
            RlsError::BnNewError => f.write_str("Bn new error"),
            RlsError::BnSetWordError => f.write_str("Bn set word error"),
            RlsError::RsaGenKeyError => f.write_str("Rsa gen key error"),
            RlsError::PkeyNewError => f.write_str("Pkey new error"),
            RlsError::PkeyAssignError => f.write_str("Pkey assign error"),
            RlsError::BioNewError => f.write_str("Bio new error"),
            RlsError::WritePriKeyError => f.write_str("Write private key error"),
            RlsError::WritePubKeyError => f.write_str("Write public key error"),
            RlsError::RsaSetPaddingError => f.write_str("Rsa set padding error"),
            RlsError::PkeyEncryptError => f.write_str("Pkey encrypt error"),
            RlsError::InitDecryptError => f.write_str("Init decrypt error"),
            RlsError::PkeyDecryptError => f.write_str("Pkey decrypt error"),
            RlsError::InitEncryptError => f.write_str("Init encrypt error"),
            RlsError::OpenX509Error => f.write_str("Open X509 error"),
            RlsError::SetRsaMgf1MdError => f.write_str("Set Rsa Mgf1Md error"),
            RlsError::SetRsaPassSaltLenError => f.write_str("Set Rsa Pass Salt Len error"),
            RlsError::CertSniInvalid => f.write_str("cert sni error"),
            RlsError::GenEcPubKeyError => f.write_str("gen ec public key error"),
            RlsError::SkNewError => f.write_str("Sk new error"),
            RlsError::SkPushError => f.write_str("sk push error"),
            RlsError::X509StoreNewError => f.write_str("X509 store new error"),
            RlsError::X509StoreCtxNewError => f.write_str("X509 store ctx new error"),
            RlsError::X509StoreCtxInitError => f.write_str("X509 store ctx init error"),
            RlsError::X509StoreAddError => f.write_str("X509 store add error"),
            RlsError::IssuerUnknown => f.write_str("Issuer unknown"),
            RlsError::X509NewError => f.write_str("X509 new error"),
            RlsError::X509SetVersionFail => f.write_str("X509 set version fail"),
            RlsError::NewAsn1IntegerError => f.write_str("New Asn1 integer error"),
            RlsError::NewX509NameError => f.write_str("New X509 name error"),
            RlsError::X509AddNameError => f.write_str("X509 add name error"),
            RlsError::X509SetSubjectError => f.write_str("X509 set subject error"),
            RlsError::X509SetIssuerError => f.write_str("X509 set issuer error"),
            RlsError::NewX509ExtError => f.write_str("New X509 ext error"),
            RlsError::X509AddExtFail => f.write_str("X509 add ext fail"),
            RlsError::X509SignError => f.write_str("X509 sign error"),
            RlsError::BIOWriteError => f.write_str("BIO write error"),
            RlsError::BIOGetDataError => f.write_str("BIO get data error"),
            RlsError::GetAiaFail => f.write_str("Get authority information access fail"),
            RlsError::MissingCertificateChain => f.write_str("Missing certificate chain"),
            RlsError::MissingKeyEntry => f.write_str("Missing key entry"),
            RlsError::HandShake(v) => write!(f, "HandShake({})", v),
            RlsError::Buffer(e) => write!(f, "Buffer({})", e),
            RlsError::Url(e) => write!(f, "Url({})", e),
            RlsError::Alert(alert) => write!(f, "Alert({})", alert.desc()),
            RlsError::Currently(e) => f.write_str(e),
            RlsError::HasherError(e) => write!(f, "Hasher({})", e),
            RlsError::DNSError(e) => write!(f, "DNSError({:?})", e),
            RlsError::EvpError(e) => write!(f, "EvpError({:?})", e),
            RlsError::Cipher(e) => write!(f, "Cipher({:?})", e),
            RlsError::Coding(e) => write!(f, "Coding({:?})", e),
            RlsError::Sm(sm) => write!(f, "Sm({:?})", sm),
        }
    }
}

impl From<String> for RlsError {
    fn from(e: String) -> Self {
        RlsError::Currently(e)
    }
}

impl From<&str> for RlsError {
    fn from(e: &str) -> Self {
        RlsError::Currently(e.to_string())
    }
}

impl From<Infallible> for RlsError {
    fn from(e: Infallible) -> Self {
        RlsError::Currently(e.to_string())
    }
}

impl From<FromUtf8Error> for RlsError {
    fn from(value: FromUtf8Error) -> Self {
        RlsError::Currently(value.to_string())
    }
}

impl From<TryFromSliceError> for RlsError {
    fn from(value: TryFromSliceError) -> Self {
        RlsError::Currently(value.to_string())
    }
}

impl From<io::Error> for RlsError {
    fn from(value: io::Error) -> Self {
        RlsError::Currently(value.to_string())
    }
}

impl From<FromHexError> for RlsError {
    fn from(value: FromHexError) -> Self {
        RlsError::Currently(value.to_string())
    }
}

impl From<ParseIntError> for RlsError {
    fn from(value: ParseIntError) -> Self {
        RlsError::Currently(value.to_string())
    }
}

impl From<RlsError> for io::Error {
    fn from(error: RlsError) -> Self {
        io::Error::other(error.to_string())
    }
}

impl From<NulError> for RlsError {
    fn from(value: NulError) -> Self {
        RlsError::Currently(value.to_string())
    }
}

impl From<AddrParseError> for RlsError {
    fn from(value: AddrParseError) -> Self {
        RlsError::Currently(value.to_string())
    }
}

impl From<Utf8Error> for RlsError {
    fn from(value: Utf8Error) -> Self {
        RlsError::Currently(value.to_string())
    }
}

impl From<UrlError> for RlsError {
    fn from(value: UrlError) -> Self {
        RlsError::Url(value)
    }
}

impl From<&[u8]> for RlsError {
    fn from(value: &[u8]) -> Self {
        match value {
            b"unable to get local issuer certificate" => RlsError::IssuerUnknown,
            _ => RlsError::Currently(String::from_utf8_lossy(value).to_string()),
        }
    }
}

impl<T: 'static> From<PoisonError<T>> for RlsError {
    fn from(value: PoisonError<T>) -> Self {
        RlsError::Currently(value.to_string())
    }
}

impl From<SystemTimeError> for RlsError {
    fn from(value: SystemTimeError) -> Self {
        RlsError::Currently(value.to_string())
    }
}

impl From<BufferError> for RlsError {
    fn from(value: BufferError) -> Self {
        RlsError::Buffer(value)
    }
}

impl From<HandShakeError> for RlsError {
    fn from(value: HandShakeError) -> Self {
        RlsError::HandShake(value)
    }
}

impl From<HashError> for RlsError {
    fn from(value: HashError) -> Self {
        RlsError::HasherError(value)
    }
}

impl From<DNSError> for RlsError {
    fn from(value: DNSError) -> Self {
        RlsError::DNSError(value)
    }
}

impl From<EvpError> for RlsError {
    fn from(value: EvpError) -> Self {
        RlsError::EvpError(value)
    }
}

impl From<CipherError> for RlsError {
    fn from(value: CipherError) -> Self {
        RlsError::Cipher(value)
    }
}

impl From<CodingError> for RlsError {
    fn from(value: CodingError) -> Self {
        RlsError::Coding(value)
    }
}

impl From<SmError> for RlsError {
    fn from(value: SmError) -> Self {
        RlsError::Sm(value)
    }
}

impl Error for RlsError {}


pub type RlsResult<T> = Result<T, RlsError>;