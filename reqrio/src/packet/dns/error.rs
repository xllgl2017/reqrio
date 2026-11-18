use std::array::TryFromSliceError;
use std::error::Error;
use std::fmt::Display;
use std::io;
use std::str::Utf8Error;
use crate::BufferError;

#[derive(Debug)]
pub enum DNSError {
    NotFoundNameLen,
    InvalidName(Utf8Error),
    Buffer(BufferError),
    UnknownDNSValue(u16),
    UnknownSvcType(u16),
    SliceError(TryFromSliceError),
    FindDnsAddrFailed,
    BindDnsAddrFailed,
    DnsIoError(io::Error),
    UnknownAead,
    UnknownKDF
}

impl Display for DNSError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<BufferError> for DNSError {
    fn from(e: BufferError) -> Self {
        DNSError::Buffer(e)
    }
}

impl From<Utf8Error> for DNSError {
    fn from(e: Utf8Error) -> Self {
        DNSError::InvalidName(e)
    }
}

impl Error for DNSError {}