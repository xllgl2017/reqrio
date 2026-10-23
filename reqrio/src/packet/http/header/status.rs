use std::fmt::{Debug, Display};

#[repr(C)]
#[derive(Copy, Clone, PartialEq)]
pub struct HttpStatus(u16);


#[allow(non_upper_case_globals)]
impl HttpStatus {
    pub const None: HttpStatus = HttpStatus(0);
    pub const Continue: HttpStatus = HttpStatus(100);
    pub const SwitchingProtocols: HttpStatus = HttpStatus(101);
    pub const OK: HttpStatus = HttpStatus(200);
    pub const Created: HttpStatus = HttpStatus(201);
    pub const Accepted: HttpStatus = HttpStatus(202);
    pub const NoContent: HttpStatus = HttpStatus(204);
    pub const PartialContent: HttpStatus = HttpStatus(206);
    pub const Move: HttpStatus = HttpStatus(301);
    pub const Found: HttpStatus = HttpStatus(302);
    pub const SeeOther: HttpStatus = HttpStatus(303);
    pub const NotModified: HttpStatus = HttpStatus(304);
    pub const TemporaryRedirect: HttpStatus = HttpStatus(307);
    pub const PermanentRedirect: HttpStatus = HttpStatus(308);
    pub const BadRequest: HttpStatus = HttpStatus(400);
    pub const Unauthorized: HttpStatus = HttpStatus(401);
    pub const Forbidden: HttpStatus = HttpStatus(403);
    pub const NotFound: HttpStatus = HttpStatus(404);
    pub const LengthRequired: HttpStatus = HttpStatus(411);
    pub const PreconditionFailed: HttpStatus = HttpStatus(412);
    pub const ReqTooLarge: HttpStatus = HttpStatus(413);
    pub const Teapot: HttpStatus = HttpStatus(418);
    pub const TooManyRequests: HttpStatus = HttpStatus(429);
    pub const ServerError: HttpStatus = HttpStatus(500);
    pub const BadGateway: HttpStatus = HttpStatus(502);
    pub const ServiceUnavailable: HttpStatus = HttpStatus(503);
    pub const GatewayTimeOut: HttpStatus = HttpStatus(504);
    pub const ReceiveTimeOut: HttpStatus = HttpStatus(524);
}

impl HttpStatus {
    pub const fn new(code: u16) -> HttpStatus { HttpStatus(code) }

    pub const fn code(&self) -> u16 { self.0 }

    pub const fn spec(&self) -> &'static str {
        match self.0 {
            0 => "None",
            100 => "Continue",
            101 => "Switching Protocols",
            200 => "Ok",
            201 => "Created",
            202 => "Accepted",
            204 => "No Content",
            206 => "Partial Content",
            301 => "Move",
            302 => "Found",
            304 => "Not Modified",
            307 => "Temporary Redirect",
            308 => "Permanent Redirect",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            411 => "Length Required",
            412 => "Precondition Failed",
            413 => "Req Too Large",
            418 => "Teapot",
            429 => "Too Many Requests",
            500 => "Server Error",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            504 => "Gateway Time Out",
            524 => "Receive Time Out",
            _ => "Unknown"
        }
    }
}

impl PartialEq<HttpStatus> for &HttpStatus {
    fn eq(&self, other: &HttpStatus) -> bool {
        self.0 == other.0
    }
}

impl PartialEq<u16> for HttpStatus {
    fn eq(&self, other: &u16) -> bool {
        self.0 == *other
    }
}

impl Display for HttpStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}({})", self.spec(), self.code())
    }
}

impl Debug for HttpStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}({})", self.spec(), self.code())
    }
}