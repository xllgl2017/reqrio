use crate::message::HandshakeType;
use crate::Version;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::io;

#[derive(Debug)]
pub enum HandShakeError {
    UnsupportedVersion(Version),
    VerifyFinishedFail,
    UnknownRecord(u8),
    UnknownHandShake(u8),
    UnsupportedMessage(HandshakeType),
    UnknownCipherSuite(u16),
    QUICMissingKeyShare,
    MissingSupportedVersions,
    MissingPubkey,
    DiffieHellmanFailed,
    MissingClientConfig,
    MissingServerConfig,
    InvalidShareSecret,
    SecretPubKeyNull,
    ExtendParseFailed,
}

impl Display for HandShakeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for HandShakeError {}

impl From<HandShakeError> for io::Error {
    fn from(e: HandShakeError) -> Self {
        io::Error::other(e)
    }
}