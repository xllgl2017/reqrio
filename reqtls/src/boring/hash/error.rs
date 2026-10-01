use std::error::Error;
use std::fmt::Display;

#[derive(Debug)]
pub enum HashError {
    MustInitFirst,
    InitEvpCtxError,
    InitDigestError,
    DigestUpdateError,
    DigestFinalError,
    HmacCtxNull,
    HmacInitError,
    HmacUpdateError,
    HmacFinalizeError,
    HmacHashError,
    HasherNoSecret,
}

impl Display for HashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for HashError {}