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
    ///正常关闭通知，表示会话正常结束。
    CloseNotify = 0,
    ///表示收到了不适当或未预期的消息类型
    UnexpectedMessage = 10,
    /// 记录层的消息认证码（MAC）验证失败
    BadRecordMac = 20,
    ///解密接收到的数据时出现了问题
    DecryptionFailed = 21,
    ///接收到的数据记录长度超过了协议所规定的最大长度，违反了协议的格式要求
    RecordOverflow = 22,
    ///解压缩操作失败
    DecompressionFailure = 30,
    /// 握手过程中发生错误，无法完成握手
    HandshakeFailure = 40,
    ///未接收到有效证书
    NoCertificate = 41,
    ///证书无效或格式错误
    BadCertificate = 42,
    ///对端提供的证书不受本地信任存储支持
    UnsupportedCertificate = 43,
    ///证书已被吊销
    CertificateRevoked = 44,
    ///证书已过期
    CertificateExpired = 45,
    ///无法验证对端提供的证书的有效性
    CertificateUnknown = 46,
    ///在握手消息中遇到了非法或不支持的参数
    IllegalParameter = 47,
    ///验证过程中使用的证书颁发机构未知
    UnknownCa = 48,
    ///访问被拒绝
    AccessDenied = 49,
    ///解码消息时出错
    DecodeError = 50,
    ///解密消息时出错
    DecryptError = 51,
    ExportRestricted = 60,
    ///不支持的协议版本
    ProtocolVersion = 70,
    ///安全度低于最低要求
    InsufficientSecurity = 71,
    ///发生了内部错误
    InternalError = 80,
    /// 用户主动取消了相关操作
    UserCanceled = 90,
    ///客户端或服务器拒绝重新协商请求时产生
    NoRenegotiation = 100,
    ///一方接收到的SSL/TLS扩展不被另一方支持或理解
    UnsupportedExtension = 110,
    //未知的ServerName
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