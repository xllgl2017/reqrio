#[derive(PartialEq)]
pub enum ALPN {
    Http10,
    Http11,
    Http20,
    Unknown,
}

impl ALPN {
    pub fn value(&self) -> Vec<u8> {
        match self {
            ALPN::Http10 => b"http/1.0".to_vec(),
            ALPN::Http11 => b"http/1.1".to_vec(),
            ALPN::Http20 => b"h2".to_vec(),
            ALPN::Unknown => vec![]
        }
    }

    pub fn alpn_str(&self) -> &'static str {
        match self {
            ALPN::Http10 => "http/1.0",
            ALPN::Http11 => "http/1.1",
            ALPN::Http20 => "h2",
            ALPN::Unknown => ""
        }
    }

    pub fn from_tls(opt: Option<Vec<u8>>) -> ALPN {
        match opt {
            None => ALPN::Unknown,
            Some(alpn) => Self::from_slice(alpn.as_slice())
        }
    }

    pub fn from_slice(opt: &[u8]) -> ALPN {
        match opt {
            b"http/1.0" => ALPN::Http10,
            b"http/1.1" => ALPN::Http11,
            b"h2" => ALPN::Http20,
            &_ => ALPN::Unknown
        }
    }
}