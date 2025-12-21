use std::array::TryFromSliceError;
use std::convert::Infallible;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::io;
use std::num::ParseIntError;
use std::string::FromUtf8Error;
#[cfg(feature = "aws-lc-rs")]
use aws_lc_rs::error::Unspecified;
#[cfg(feature = "hex")]
use hex::FromHexError;
#[cfg(feature = "hmac")]
use hmac::digest::InvalidLength;
use httlib_huffman::EncoderError;
use json::JsonError;
#[cfg(feature = "rustls")]
use rustls::pki_types::InvalidDnsNameError;
#[cfg(feature = "tokio")]
use tokio::time::error::Elapsed;

#[derive(Debug)]
pub enum HlsError {
    NonePointer,
    InvalidHeadSize,
    PeerClosedConnection,
    PayloadNone,
    DecrypterNone,
    EncrypterNone,
    StdErr(Box<dyn Error>),
    Currently(String),
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
        HlsError::StdErr(Box::new(e))
    }
}

impl From<ParseIntError> for HlsError {
    fn from(e: ParseIntError) -> Self {
        HlsError::StdErr(Box::new(e))
    }
}

impl Display for HlsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            HlsError::StdErr(e) => f.write_str(&e.to_string()),
            HlsError::Currently(e) => f.write_str(e),
            HlsError::InvalidHeadSize => f.write_str("InvalidHeadSize"),
            HlsError::PeerClosedConnection => f.write_str("PeerClosedConnection"),
            HlsError::PayloadNone => f.write_str("PayloadNone"),
            HlsError::DecrypterNone => f.write_str("DecrypterNone"),
            HlsError::NonePointer => f.write_str("NonePointer"),
            HlsError::EncrypterNone => f.write_str("EncrypterNone"),
        }
    }
}

impl From<TryFromSliceError> for HlsError {
    fn from(value: TryFromSliceError) -> Self {
        Self::StdErr(Box::new(value))
    }
}

impl From<io::Error> for HlsError {
    fn from(value: io::Error) -> Self {
        HlsError::StdErr(Box::new(value))
    }
}

#[cfg(feature = "tokio")]
impl From<Elapsed> for HlsError {
    fn from(value: Elapsed) -> Self {
        HlsError::Currently(value.to_string())
    }
}

#[cfg(feature = "rustls")]
impl From<InvalidDnsNameError> for HlsError {
    fn from(value: InvalidDnsNameError) -> Self {
        HlsError::StdErr(Box::new(value))
    }
}

#[cfg(feature = "rustls")]
impl From<rustls::Error> for HlsError {
    fn from(value: rustls::Error) -> Self {
        HlsError::Currently(value.to_string())
    }
}

#[cfg(feature = "hex")]
impl From<FromHexError> for HlsError {
    fn from(value: FromHexError) -> Self {
        HlsError::StdErr(Box::new(value))
    }
}

impl From<Infallible> for HlsError {
    fn from(value: Infallible) -> Self {
        HlsError::StdErr(Box::new(value))
    }
}

#[cfg(feature = "hmac")]
impl From<InvalidLength> for HlsError {
    fn from(value: InvalidLength) -> Self {
        HlsError::StdErr(Box::new(value))
    }
}

#[cfg(feature = "aws-lc-rs")]
impl From<Unspecified> for HlsError {
    fn from(value: Unspecified) -> Self {
        HlsError::StdErr(Box::new(value))
    }
}

#[cfg(feature = "p256")]
impl From<p256::elliptic_curve::Error> for HlsError {
    fn from(value: p256::elliptic_curve::Error) -> Self {
        HlsError::StdErr(Box::new(value))
    }
}

impl From<EncoderError> for HlsError {
    fn from(value: EncoderError) -> Self {
        HlsError::StdErr(Box::new(value))
    }
}

impl From<JsonError> for HlsError {
    fn from(value: JsonError) -> Self {
        HlsError::StdErr(Box::new(value))
    }
}

impl Error for HlsError {}

unsafe impl Send for HlsError {}


pub type HlsResult<T> = Result<T, HlsError>;
