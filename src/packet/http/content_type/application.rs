use std::fmt::{Display, Formatter};
use crate::error::HlsError;

#[derive(Clone)]
pub enum Application {
    Json,
    XWwwFormUrlencoded,
    Xml,
    JavaScript,
    Grpc,
    OctetStream,
    XJavaScript,
    CspReport,
    BondCompactBinary,
    ReportsJson,
    VndAppleMpegUrl,
    XProtobuf,
    Zip,
    FontSFnt,
    Wasm,
    ForceDownload,
    XGzip,
    Jose,
    FontWoff,
    Pdf,
}

impl Display for Application {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Application::Json => f.write_str("application/json"),
            Application::XWwwFormUrlencoded => f.write_str("application/x-www-form-urlencoded"),
            Application::Xml => f.write_str("application/xml"),
            Application::JavaScript => f.write_str("application/javascript"),
            Application::Grpc => f.write_str("application/grpc"),
            Application::OctetStream => f.write_str("application/octet-stream"),
            Application::XJavaScript => f.write_str("application/x-javascript"),
            Application::CspReport => f.write_str("application/csp-report"),
            Application::BondCompactBinary => f.write_str("application/bond-compact-binary"),
            Application::ReportsJson => f.write_str("application/reports+json"),
            Application::VndAppleMpegUrl => f.write_str("application/vnd.apple.mpegurl"),
            Application::XProtobuf => f.write_str("application/x-protobuf"),
            Application::Zip => f.write_str("application/zip"),
            Application::FontSFnt => f.write_str("application/font-sfnt"),
            Application::Wasm => f.write_str("application/wasm"),
            Application::ForceDownload => f.write_str("application/force-download"),
            Application::XGzip => f.write_str("application/x-gzip"),
            Application::Jose => f.write_str("application/jose"),
            Application::FontWoff => f.write_str("application/font-woff"),
            Application::Pdf => f.write_str("application/pdf")
        }
    }
}

impl TryFrom<&str> for Application {
    type Error = HlsError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "json" => Ok(Application::Json),
            "xml" => Ok(Application::Xml),
            "x-www-form-urlencoded" => Ok(Application::XWwwFormUrlencoded),
            "javascript" => Ok(Application::JavaScript),
            "grpc" => Ok(Application::Grpc),
            "octet-stream" => Ok(Application::OctetStream),
            "x-javascript" => Ok(Application::XJavaScript),
            "csp-report" => Ok(Application::CspReport),
            "bond-compact-binary" => Ok(Application::BondCompactBinary),
            "reports+json" => Ok(Application::ReportsJson),
            "vnd.apple.mpegurl" => Ok(Application::VndAppleMpegUrl),
            "x-protobuf" => Ok(Application::XProtobuf),
            "zip" => Ok(Application::Zip),
            "font-sfnt" => Ok(Application::FontSFnt),
            "wasm" => Ok(Application::Wasm),
            "force-download" => Ok(Application::ForceDownload),
            "jose" => Ok(Application::Jose),
            "font-woff" => Ok(Application::FontWoff),
            "pdf" => Ok(Application::Pdf),
            _ => Err(format!("Unknown application-{}", value).into())
        }
    }
}
