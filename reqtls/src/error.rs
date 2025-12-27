use std::array::TryFromSliceError;
use std::convert::Infallible;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::io;
use std::num::ParseIntError;
use std::string::FromUtf8Error;
use aws_lc_rs::error::Unspecified;
use hex::FromHexError;
use hmac::digest::InvalidLength;

#[derive(Debug)]
pub enum RlsError {
    ClientHelloNone,
    EncrypterNone,
    DecrypterNone,
    PayloadNone,
    StdError(Box<dyn Error>),
    Currently(String),
}

impl Display for RlsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RlsError::ClientHelloNone => f.write_str("Client hello none"),
            RlsError::EncrypterNone => f.write_str("Encrypter none"),
            RlsError::DecrypterNone => f.write_str("Decrypter none"),
            RlsError::PayloadNone => f.write_str("Payload none"),
            RlsError::StdError(e) => f.write_fmt(format_args!("{:?}", e)),
            RlsError::Currently(e) => f.write_str(e),
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
        RlsError::StdError(Box::new(e))
    }
}

impl From<FromUtf8Error> for RlsError {
    fn from(value: FromUtf8Error) -> Self {
        RlsError::StdError(Box::new(value))
    }
}

impl From<TryFromSliceError> for RlsError {
    fn from(value: TryFromSliceError) -> Self {
        RlsError::StdError(Box::new(value))
    }
}

impl From<InvalidLength> for RlsError {
    fn from(value: InvalidLength) -> Self {
        RlsError::StdError(Box::new(value))
    }
}

impl From<Unspecified> for RlsError {
    fn from(value: Unspecified) -> Self {
        RlsError::StdError(Box::new(value))
    }
}

impl From<io::Error> for RlsError {
    fn from(value: io::Error) -> Self {
        RlsError::StdError(Box::new(value))
    }
}

impl From<FromHexError> for RlsError {
    fn from(value: FromHexError) -> Self {
        RlsError::StdError(Box::new(value))
    }
}

impl From<ParseIntError> for RlsError {
    fn from(value: ParseIntError) -> Self {
        RlsError::StdError(Box::new(value))
    }
}

impl From<p256::elliptic_curve::Error> for RlsError {
    fn from(value: p256::elliptic_curve::Error) -> Self {
        RlsError::StdError(Box::new(value))
    }
}

impl From<RlsError> for io::Error {
    fn from(error: RlsError) -> Self {
        io::Error::new(io::ErrorKind::Other, error.to_string())
    }
}

impl Error for RlsError {}

pub type RlsResult<T> = Result<T, RlsError>;