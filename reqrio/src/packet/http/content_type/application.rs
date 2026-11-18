use crate::error::HlsError;
use std::fmt::{Display, Formatter};

#[derive(Clone)]
#[cfg_attr(debug_assertions, derive(PartialEq, Debug))]
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
    Proto,
    Custom(String),
}

impl Application {
    pub fn spec(&self) -> &str {
        match self {
            Application::Json => "application/json",
            Application::XWwwFormUrlencoded => "application/x-www-form-urlencoded",
            Application::Xml => "application/xml",
            Application::JavaScript => "application/javascript",
            Application::Grpc => "application/grpc",
            Application::OctetStream => "application/octet-stream",
            Application::XJavaScript => "application/x-javascript",
            Application::CspReport => "application/csp-report",
            Application::BondCompactBinary => "application/bond-compact-binary",
            Application::ReportsJson => "application/reports+json",
            Application::VndAppleMpegUrl => "application/vnd.apple.mpegurl",
            Application::XProtobuf => "application/x-protobuf",
            Application::Zip => "application/zip",
            Application::FontSFnt => "application/font-sfnt",
            Application::Wasm => "application/wasm",
            Application::ForceDownload => "application/force-download",
            Application::XGzip => "application/x-gzip",
            Application::Jose => "application/jose",
            Application::FontWoff => "application/font-woff",
            Application::Pdf => "application/pdf",
            Application::Proto => "application/proto",
            Application::Custom(spec) => spec
        }
    }
}

impl Display for Application {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.spec())
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
            "proto" => Ok(Application::Proto),
            _ => Ok(Application::Custom(value.to_string())),
        }
    }
}
