use std::error::Error;
use std::fmt::{Display, Formatter};
use std::io;
use std::str::Utf8Error;
use crate::boring::HashError;
use crate::{BufferError, HandShakeError, RlsError};
use crate::message::TrpErrKind;

#[derive(Debug)]
pub enum QUICError {
    InvalidVariant,
    InitialRetry,
    MissingLargestNum,
    IOError(io::Error),
    Rls(RlsError),
    TransportError {
        reason: String,
        err_code: TrpErrKind,
    },
    BufferNotInited,
}

impl Error for QUICError {}

impl Display for QUICError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<BufferError> for QUICError {
    fn from(e: BufferError) -> Self {
        QUICError::Rls(RlsError::Buffer(e))
    }
}

impl From<HashError> for QUICError {
    fn from(e: HashError) -> Self {
        QUICError::Rls(RlsError::HasherError(e))
    }
}

impl From<Utf8Error> for QUICError {
    fn from(e: Utf8Error) -> Self {
        QUICError::Rls(RlsError::Buffer(BufferError::Utf8Error(e)))
    }
}

impl From<RlsError> for QUICError {
    fn from(e: RlsError) -> Self {
        QUICError::Rls(e)
    }
}

impl From<io::Error> for QUICError {
    fn from(value: io::Error) -> Self {
        QUICError::IOError(value)
    }
}

impl From<HandShakeError> for QUICError {
    fn from(value: HandShakeError) -> Self {
        QUICError::Rls(RlsError::HandShake(value))
    }
}

impl From<&str> for QUICError {
    fn from(value: &str) -> Self {
        QUICError::Rls(RlsError::Currently(value.to_string()))
    }
}