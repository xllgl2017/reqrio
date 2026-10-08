use crate::json::JsonError;
use crate::pack::PackError;
use reqtls::{hex, Alert, BufferError, RlsError, UrlError, ALPN, HandShakeError};
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
#[cfg(feature = "aync")]
use tokio::time::error::Elapsed;
use reqtls::cipher::CipherError;
use reqtls::coder::CodingError;
#[cfg(feature = "quic")]
use reqtls::quic::QUICError;
use crate::body::FormError;
use crate::H2FrameType;
use crate::packet::HeaderError;
use crate::time::TimeError;

#[derive(Debug)]
pub enum HlsError {
    NullPointer,
    InvalidHeadSize,
    PeerClosedConnection,
    PayloadNone,
    DecrypterNone,
    EncrypterNone,
    WsFrameTypeNone,
    H2(H2FrameType),
    UnsupportedAlpn(ALPN),
    Body(FormError),
    Rls(RlsError),
    HPack(PackError),
    Time(TimeError),
    Header(HeaderError),
    Currently(String),
    #[cfg(feature = "quic")]
    QUIC(QUICError),
}

impl From<&str> for HlsError {
    fn from(s: &str) -> Self {
        HlsError::Currently(s.to_string())
    }
}

impl From<String> for HlsError {
    fn from(s: String) -> Self {
        HlsError::Currently(s)
    }
}

impl From<FromUtf8Error> for HlsError {
    fn from(e: FromUtf8Error) -> Self {
        HlsError::Currently(e.to_string())
    }
}

impl From<ParseIntError> for HlsError {
    fn from(e: ParseIntError) -> Self {
        HlsError::Currently(e.to_string())
    }
}

impl Display for HlsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            HlsError::Currently(e) => f.write_str(e),
            HlsError::InvalidHeadSize => f.write_str("InvalidHeadSize"),
            HlsError::PeerClosedConnection => f.write_str("PeerClosedConnection"),
            HlsError::PayloadNone => f.write_str("PayloadNone"),
            HlsError::DecrypterNone => f.write_str("DecrypterNone"),
            HlsError::NullPointer => f.write_str("NonePointer"),
            HlsError::EncrypterNone => f.write_str("EncrypterNone"),
            HlsError::WsFrameTypeNone => f.write_str("WsFrameTypeNone"),
            HlsError::Rls(e) => write!(f, "RlsError({})", e),
            HlsError::HPack(e) => write!(f, "HPack({})", e),
            HlsError::Body(e) => write!(f, "Body({})", e),
            HlsError::Time(e) => write!(f, "Time({:?})", e),
            HlsError::UnsupportedAlpn(alpn) => write!(f, "UnsupportedAlpn({})", alpn),
            HlsError::H2(typ) => write!(f, "H2({:?})", typ),
            HlsError::Header(e) => write!(f, "Header({:?})", e),
            #[cfg(feature = "quic")]
            HlsError::QUIC(e) => write!(f, "QUIC({:?})", e),
        }
    }
}

impl From<TryFromSliceError> for HlsError {
    fn from(value: TryFromSliceError) -> Self {
        HlsError::Currently(value.to_string())
    }
}

impl From<io::Error> for HlsError {
    fn from(value: io::Error) -> Self {
        HlsError::Currently(value.to_string())
    }
}

impl From<Infallible> for HlsError {
    fn from(value: Infallible) -> Self {
        HlsError::Currently(value.to_string())
    }
}

impl From<PackError> for HlsError {
    fn from(value: PackError) -> Self {
        HlsError::HPack(value)
    }
}

impl From<JsonError> for HlsError {
    fn from(value: JsonError) -> Self {
        HlsError::Currently(value.to_string())
    }
}

impl<T: 'static> From<PoisonError<T>> for HlsError {
    fn from(value: PoisonError<T>) -> Self {
        HlsError::Currently(value.to_string())
    }
}

impl From<Utf8Error> for HlsError {
    fn from(value: Utf8Error) -> Self {
        HlsError::Currently(value.to_string())
    }
}

impl From<RlsError> for HlsError {
    fn from(value: RlsError) -> Self {
        HlsError::Rls(value)
    }
}

#[cfg(feature = "aync")]
impl From<Elapsed> for HlsError {
    fn from(value: Elapsed) -> Self {
        HlsError::Currently(value.to_string())
    }
}

impl From<HlsError> for io::Error {
    fn from(err: HlsError) -> io::Error {
        io::Error::other(err.to_string())
    }
}

impl From<AddrParseError> for HlsError {
    fn from(value: AddrParseError) -> Self {
        HlsError::Currently(value.to_string())
    }
}

impl From<hex::FromHexError> for HlsError {
    fn from(value: hex::FromHexError) -> Self {
        HlsError::Currently(value.to_string())
    }
}

impl From<NulError> for HlsError {
    fn from(value: NulError) -> Self {
        HlsError::Currently(value.to_string())
    }
}

impl From<Alert> for HlsError {
    fn from(value: Alert) -> Self {
        HlsError::Rls(RlsError::Alert(value))
    }
}

impl From<BufferError> for HlsError {
    fn from(value: BufferError) -> Self {
        HlsError::Rls(RlsError::Buffer(value))
    }
}

impl From<FormError> for HlsError {
    fn from(value: FormError) -> Self {
        HlsError::Body(value)
    }
}

impl From<TimeError> for HlsError {
    fn from(value: TimeError) -> Self {
        HlsError::Time(value)
    }
}

impl From<CodingError> for HlsError {
    fn from(value: CodingError) -> Self {
        HlsError::Rls(RlsError::Coding(value))
    }
}

impl From<UrlError> for HlsError {
    fn from(value: UrlError) -> Self {
        HlsError::Rls(RlsError::Url(value))
    }
}

impl From<io::ErrorKind> for HlsError {
    fn from(value: io::ErrorKind) -> Self {
        HlsError::Currently(value.to_string())
    }
}

impl From<CipherError> for HlsError {
    fn from(value: CipherError) -> Self {
        HlsError::Rls(RlsError::Cipher(value))
    }
}

impl From<HeaderError> for HlsError {
    fn from(value: HeaderError) -> Self {
        HlsError::Header(value)
    }
}

#[cfg(feature = "quic")]
impl From<QUICError> for HlsError {
    fn from(value: QUICError) -> Self {
        match value {
            QUICError::Rls(rls) => HlsError::Rls(rls),
            _ => HlsError::QUIC(value),
        }
    }
}

impl From<H2FrameType> for HlsError {
    fn from(value: H2FrameType) -> Self {
        HlsError::H2(value)
    }
}

impl From<HandShakeError> for HlsError {
    fn from(value: HandShakeError) -> Self {
        HlsError::Rls(RlsError::HandShake(value))
    }
}

impl Error for HlsError {}


pub type HlsResult<T> = Result<T, HlsError>;
