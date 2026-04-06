use crate::json::JsonError;
use crate::hpack::HPackError;
use reqtls::{hex, Alert, BufferError, RlsError, UrlError, ALPN};
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
use reqtls::coder::ZSTDError;
use crate::form_data::FormError;
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
    DataTooShort,
    UnsupportedAlpn(ALPN),
    Body(FormError),
    Rls(RlsError),
    HPack(HPackError),
    Time(TimeError),
    Currently(String),
    Zstd(ZSTDError),
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
            HlsError::DataTooShort => f.write_str("DataTooShort"),
            HlsError::Rls(e) => write!(f, "RlsError({})", e),
            HlsError::HPack(e) => write!(f, "HPack({})", e),
            HlsError::Body(e) => write!(f, "Body({})", e),
            HlsError::Time(e) => write!(f, "Time({:?})", e),
            HlsError::UnsupportedAlpn(alpn) => write!(f, "UnsupportedAlpn({})", alpn),
            HlsError::Zstd(e) => write!(f, "Zstd({})", e),
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

impl From<HPackError> for HlsError {
    fn from(value: HPackError) -> Self {
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

impl From<ZSTDError> for HlsError {
    fn from(value: ZSTDError) -> Self {
        HlsError::Zstd(value)
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

impl Error for HlsError {}


pub type HlsResult<T> = Result<T, HlsError>;
