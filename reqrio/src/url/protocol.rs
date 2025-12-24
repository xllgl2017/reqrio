use std::fmt::Display;
use crate::error::HlsError;

#[derive(Eq, PartialEq, Debug, Clone)]
pub enum Protocol {
    Http,
    Https,
    Ws,
    Wss,
    Socks5,
    Trojan,
}

impl Protocol {
    pub fn default_port(&self) -> u16 {
        match self {
            Protocol::Http => 80,
            Protocol::Https => 443,
            Protocol::Ws => 80,
            Protocol::Wss => 443,
            Protocol::Socks5 => 8888,
            Protocol::Trojan => 8888
        }
    }
}


impl Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Http => f.write_str("http"),
            Protocol::Https => f.write_str("https"),
            Protocol::Ws => f.write_str("ws"),
            Protocol::Wss => f.write_str("wss"),
            Protocol::Socks5 => f.write_str("socks5"),
            Protocol::Trojan => f.write_str("trojan")
        }
    }
}

impl TryFrom<&str> for Protocol {
    type Error = HlsError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "http" => Ok(Protocol::Http),
            "https" => Ok(Protocol::Https),
            "ws" => Ok(Protocol::Ws),
            "wss" => Ok(Protocol::Wss),
            "socks5" => Ok(Protocol::Socks5),
            "trojan" => Ok(Protocol::Trojan),
            _ => Err("unknown protocol".into()),
        }
    }
}