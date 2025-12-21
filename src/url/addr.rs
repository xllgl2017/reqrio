use std::fmt::Display;
use crate::error::{HlsError, HlsResult};

#[derive(Debug)]
pub struct Addr {
    host: String,
    port: u16,
}

impl Addr {
    pub fn new() -> Addr {
        Addr {
            host: "".to_string(),
            port: 0,
        }
    }

    pub fn new_addr(host: impl ToString, port: u16) -> Addr {
        let mut res = Addr::new();
        res.host = host.to_string();
        res.port = port;
        res
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn set_port(&mut self, port: u16) {
        self.port = port;
    }
}

impl Display for Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}:{}", self.host, self.port))
    }
}

impl TryFrom<&str> for Addr {
    type Error = HlsError;
    fn try_from(value: &str) -> HlsResult<Addr> {
        let mut i = value.split(':');
        let mut res = Addr::new();
        res.host = i.next().ok_or("addr error")?.to_string();
        if let Some(port) = i.next() {
            res.port = port.parse()?;
        }
        Ok(res)
    }
}

impl TryFrom<String> for Addr {
    type Error = HlsError;
    fn try_from(value: String) -> HlsResult<Addr> {
        Addr::try_from(value.as_str())
    }
}
