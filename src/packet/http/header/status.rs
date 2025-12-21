use crate::error::HlsError;
use std::fmt::Display;

#[derive(Clone)]
pub enum HttpStatus {
    None,
    Continue = 100,
    SwitchingProtocols = 101,
    OK = 200,
    Created = 201,
    Accepted = 202,
    NoContent = 204,
    PartialContent = 206,
    Move = 301,
    Found = 302,
    NotModified = 304,
    TemporaryRedirect = 307,
    PermanentRedirect = 308,
    BadRequest = 400,
    Unauthorized = 401,
    Forbidden = 403,
    NotFound = 404,
    ReqTooLarge = 413,
    Teapot = 418,
    TooManyRequests = 429,
    ServerError = 500,
    BadGateway = 502,
    ServiceUnavailable = 503,
    GatewayTimeOut = 504,
    ReceiveTimeOut = 524,
}

impl HttpStatus {
    pub fn status_num(&self) -> i32 {
        self.clone() as i32
    }
}

impl TryFrom<i32> for HttpStatus {
    type Error = HlsError;
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            100 => Ok(HttpStatus::Continue),
            101 => Ok(HttpStatus::SwitchingProtocols),
            200 => Ok(HttpStatus::OK),
            201 => Ok(HttpStatus::Created),
            202 => Ok(HttpStatus::Accepted),
            204 => Ok(HttpStatus::NoContent),
            206 => Ok(HttpStatus::PartialContent),
            301 => Ok(HttpStatus::Move),
            302 => Ok(HttpStatus::Found),
            304 => Ok(HttpStatus::NotModified),
            307 => Ok(HttpStatus::TemporaryRedirect),
            308 => Ok(HttpStatus::PermanentRedirect),
            400 => Ok(HttpStatus::BadRequest),
            401 => Ok(HttpStatus::Unauthorized),
            403 => Ok(HttpStatus::Forbidden),
            404 => Ok(HttpStatus::NotFound),
            413 => Ok(HttpStatus::ReqTooLarge),
            418 => Ok(HttpStatus::Teapot),
            429 => Ok(HttpStatus::TooManyRequests),
            500 => Ok(HttpStatus::ServerError),
            502 => Ok(HttpStatus::BadGateway),
            504 => Ok(HttpStatus::GatewayTimeOut),
            503 => Ok(HttpStatus::ServiceUnavailable),
            524 => Ok(HttpStatus::ReceiveTimeOut),
            _ => Err(format!("Invalid HTTP status: {}", value).into()),
        }
    }
}

impl Display for HttpStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpStatus::None => write!(f, "None"),
            HttpStatus::Continue => f.write_str("Continue"),
            HttpStatus::SwitchingProtocols => f.write_str("Switching Protocols"),
            HttpStatus::OK => f.write_str("Ok"),
            HttpStatus::Created => f.write_str("Created"),
            HttpStatus::Accepted => f.write_str("Accepted"),
            HttpStatus::NoContent => f.write_str("No Content"),
            HttpStatus::PartialContent => write!(f, "Partial Content"),
            HttpStatus::Move => f.write_str("Move"),
            HttpStatus::Found => f.write_str("Found"),
            HttpStatus::NotModified => f.write_str("Not Modified"),
            HttpStatus::TemporaryRedirect => f.write_str("Temporary Redirect"),
            HttpStatus::PermanentRedirect => f.write_str("Permanent Redirect"),
            HttpStatus::BadRequest => f.write_str("Bad Request"),
            HttpStatus::Unauthorized => f.write_str("Unauthorized"),
            HttpStatus::Forbidden => f.write_str("Forbidden"),
            HttpStatus::NotFound => f.write_str("Not Found"),
            HttpStatus::ReqTooLarge => f.write_str("Request Too Large"),
            HttpStatus::Teapot => f.write_str("Teapot"),
            HttpStatus::TooManyRequests => f.write_str("Too Many Requests"),
            HttpStatus::ServerError => f.write_str("Server Error"),
            HttpStatus::BadGateway => f.write_str("Bad Gateway"),
            HttpStatus::ServiceUnavailable => f.write_str("Service Unavailable"),
            HttpStatus::GatewayTimeOut => f.write_str("Gateway Time Out"),
            HttpStatus::ReceiveTimeOut => f.write_str("Receive Time Out"),
        }
    }
}