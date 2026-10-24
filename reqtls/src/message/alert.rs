use crate::error::RlsResult;
use crate::{BufferError, Writer};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::io;

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum AlertLevel {
    Warning = 1,
    Fatal = 2,
}

#[derive(Copy, Clone, Debug)]
pub enum AlertDesc {
    /// Normal closure notification; the session ended normally.
    CloseNotify = 0,
    /// An inappropriate or unexpected message type was received.
    UnexpectedMessage = 10,
    /// The record layer's message authentication code (MAC) check failed.
    BadRecordMac = 20,
    /// An error occurred while decrypting received data.
    DecryptionFailed = 21,
    /// The received record length exceeded the maximum allowed by the protocol and violated the format requirement.
    RecordOverflow = 22,
    /// Decompression failed.
    DecompressionFailure = 30,
    /// A handshake error occurred and the handshake could not complete.
    HandshakeFailure = 40,
    /// No valid certificate was received.
    NoCertificate = 41,
    /// The certificate is invalid or malformed.
    BadCertificate = 42,
    /// The peer-provided certificate is not supported by the local trust store.
    UnsupportedCertificate = 43,
    /// The certificate has been revoked.
    CertificateRevoked = 44,
    /// The certificate has expired.
    CertificateExpired = 45,
    /// The validity of the peer-provided certificate could not be established.
    CertificateUnknown = 46,
    /// An illegal or unsupported parameter was encountered in the handshake message.
    IllegalParameter = 47,
    /// The certificate authority used during validation is unknown.
    UnknownCa = 48,
    /// Access was denied.
    AccessDenied = 49,
    /// An error occurred while decoding the message.
    DecodeError = 50,
    /// An error occurred while decrypting the message.
    DecryptError = 51,
    ExportRestricted = 60,
    /// Unsupported protocol version.
    ProtocolVersion = 70,
    /// The security level is below the minimum requirement.
    InsufficientSecurity = 71,
    /// An internal error occurred.
    InternalError = 80,
    /// The operation was canceled by the user.
    UserCanceled = 90,
    /// This occurs when a client or server rejects a renegotiation request.
    NoRenegotiation = 100,
    /// One side received an SSL/TLS extension that the other side does not support or understand.
    UnsupportedExtension = 110,
    // Unknown `ServerName`.
    UnrecognisedName = 112,
}

impl AlertDesc {
    pub fn from_u8(v: u8) -> Option<AlertDesc> {
        match v {
            0 => Some(AlertDesc::CloseNotify),
            10 => Some(AlertDesc::UnexpectedMessage),
            20 => Some(AlertDesc::BadRecordMac),
            21 => Some(AlertDesc::DecryptionFailed),
            22 => Some(AlertDesc::RecordOverflow),
            30 => Some(AlertDesc::DecompressionFailure),
            40 => Some(AlertDesc::HandshakeFailure),
            41 => Some(AlertDesc::NoCertificate),
            42 => Some(AlertDesc::BadCertificate),
            43 => Some(AlertDesc::UnsupportedCertificate),
            44 => Some(AlertDesc::CertificateRevoked),
            45 => Some(AlertDesc::CertificateExpired),
            46 => Some(AlertDesc::CertificateUnknown),
            47 => Some(AlertDesc::IllegalParameter),
            48 => Some(AlertDesc::UnknownCa),
            49 => Some(AlertDesc::AccessDenied),
            50 => Some(AlertDesc::DecodeError),
            51 => Some(AlertDesc::DecryptError),
            60 => Some(AlertDesc::ExportRestricted),
            70 => Some(AlertDesc::ProtocolVersion),
            71 => Some(AlertDesc::InsufficientSecurity),
            80 => Some(AlertDesc::InternalError),
            90 => Some(AlertDesc::UserCanceled),
            100 => Some(AlertDesc::NoRenegotiation),
            110 => Some(AlertDesc::UnsupportedExtension),
            112 => Some(AlertDesc::UnrecognisedName),
            _ => None,
        }
    }
}

impl Display for AlertDesc {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertDesc::CloseNotify => f.write_str("CloseNotify"),
            AlertDesc::UnexpectedMessage => f.write_str("UnexpectedMessage"),
            AlertDesc::BadRecordMac => f.write_str("BadRecordMac"),
            AlertDesc::DecryptionFailed => f.write_str("DecryptionFailed"),
            AlertDesc::RecordOverflow => f.write_str("RecordOverflow"),
            AlertDesc::DecompressionFailure => f.write_str("DecompressionFailure"),
            AlertDesc::HandshakeFailure => f.write_str("HandshakeFailure"),
            AlertDesc::NoCertificate => f.write_str("NoCertificate"),
            AlertDesc::BadCertificate => f.write_str("BadCertificate"),
            AlertDesc::UnsupportedCertificate => f.write_str("UnsupportedCertificate"),
            AlertDesc::CertificateRevoked => f.write_str("CertificateRevoked"),
            AlertDesc::CertificateExpired => f.write_str("CertificateExpired"),
            AlertDesc::CertificateUnknown => f.write_str("CertificateUnknown"),
            AlertDesc::IllegalParameter => f.write_str("IllegalParameter"),
            AlertDesc::UnknownCa => f.write_str("UnknownCa"),
            AlertDesc::AccessDenied => f.write_str("AccessDenied"),
            AlertDesc::DecodeError => f.write_str("DecodeError"),
            AlertDesc::DecryptError => f.write_str("DecryptError"),
            AlertDesc::ExportRestricted => f.write_str("ExportRestricted"),
            AlertDesc::ProtocolVersion => f.write_str("ProtocolVersion"),
            AlertDesc::InsufficientSecurity => f.write_str("InsufficientSecurity"),
            AlertDesc::InternalError => f.write_str("InternalError"),
            AlertDesc::UserCanceled => f.write_str("UserCanceled"),
            AlertDesc::NoRenegotiation => f.write_str("NoRenegotiation"),
            AlertDesc::UnsupportedExtension => f.write_str("UnsupportedExtension"),
            AlertDesc::UnrecognisedName => f.write_str("UnrecognisedName"),
        }
    }
}

#[derive(Debug)]
pub struct Alert {
    level: AlertLevel,
    desc: AlertDesc,
}


impl Alert {
    pub fn close_notify() -> Alert {
        Alert {
            level: AlertLevel::Warning,
            desc: AlertDesc::CloseNotify,
        }
    }

    pub fn desc(&self) -> &AlertDesc { &self.desc }

    pub fn from_bytes(bytes: &[u8]) -> RlsResult<Alert> {
        Ok(Alert {
            level: if bytes[0] == 1 { AlertLevel::Warning } else { AlertLevel::Fatal },
            desc: AlertDesc::from_u8(bytes[1]).ok_or(format!("unsupported-alert: {}", bytes[1]))?,
        })
    }

    pub fn write_to(self, writer: &mut Writer) -> Result<(), BufferError> {
        writer.write_u8(self.level as u8)?;
        writer.write_u8(self.desc as u8)
    }

    pub fn to_bytes(self) -> [u8; 2] {
        [self.level as u8, self.desc as u8]
    }

    pub fn level(&self) -> AlertLevel { self.level }
}

impl Error for Alert {}

impl Display for Alert {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Alert({})", self.desc)
    }
}

impl From<Alert> for io::Error {
    fn from(value: Alert) -> Self {
        io::Error::other(value.to_string())
    }
}