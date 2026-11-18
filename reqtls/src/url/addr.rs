use crate::error::RlsResult;
use crate::url::UrlError;
use std::fmt::Display;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;


#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Addr {
    host: String,
    port: u16,
}

impl Default for Addr {
    fn default() -> Self {
        Addr {
            host: "".to_string(),
            port: 0,
        }
    }
}

impl Addr {
    pub fn new_addr(host: impl ToString, port: u16) -> Addr {
        Addr {
            host: host.to_string(),
            port,
        }
    }

    pub fn new_bits(host: u32, port: u16) -> Addr {
        let mut res = Addr::default();
        let ip = Ipv4Addr::from_bits(host);
        res.host = ip.to_string();
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

    pub fn set_host(&mut self, host: impl ToString) {
        self.host = host.to_string();
    }


    // fn get_dns(&self, ech: bool) -> RlsResult<Arc<DNSCache>> {
    //     let mut cache = match IpAddr::from_str(&self.host) {
    //         Ok(addr) => DNSCache::new_addrs(vec![addr]),
    //         Err(_) => {
    //             let mut cache = if ech {
    //                 let mut stream = DNSStream::new()?;
    //                 stream.get_dns_https(&self.host)?
    //             } else { DNSCache::new_addrs(vec![]) };
    //             if cache.addrs().is_empty() {
    //                 let addrs = format!("{}:{}", self.host, self.port).to_socket_addrs()?.map(|x| x.ip()).collect();
    //                 cache.set_addrs(addrs);
    //             }
    //             cache
    //         }
    //     };
    // 
    //     let t = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs();
    //     cache.set_time(t);
    //     let cache = Arc::new(cache);
    //     let mut dns_write = DNS.write()?;
    //     dns_write.insert(self.host.clone(), cache.clone());
    //     Ok(cache)
    // }
    // pub fn get_dns_cache(&self, ech: bool) -> RlsResult<Arc<DNSCache>> {
    //     let dns_read = DNS.read()?;
    //     match dns_read.get(&self.host) {
    //         None => {
    //             drop(dns_read);
    //             self.get_dns(ech)
    //         }
    //         Some(dns) => {
    //             let t = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs();
    //             if t - dns.time() > 30 * 60 {
    //                 drop(dns_read);
    //                 self.get_dns(ech)
    //             } else {
    //                 Ok(dns.clone())
    //             }
    //         }
    //     }
    // }

    #[deprecated]
    pub fn socket_addr(&self, _ech: bool) -> RlsResult<SocketAddr> {
        Ok(format!("{}:{}", self.host, self.port)
            .to_socket_addrs()?
            .next()
            .ok_or("dns none")?)
    }

    pub fn to_bits(&self) -> RlsResult<u32> {
        Ok(Ipv4Addr::from_str(self.host())?.to_bits())
    }
}

impl Display for Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}:{}", self.host, self.port))
    }
}

impl TryFrom<&str> for Addr {
    type Error = UrlError;
    fn try_from(value: &str) -> Result<Addr, Self::Error> {
        let host_pos = value.find(':');
        match host_pos {
            None => {
                Ok(Addr {
                    host: value.to_string(),
                    port: 0,
                })
            }
            Some(host_pos) => {
                Ok(Addr {
                    host: value[..host_pos].to_string(),
                    port: value[host_pos + 1..].parse().or(Err(UrlError::InvalidPort(value[host_pos + 1..].to_string())))?,
                })
            }
        }
    }
}

impl TryFrom<String> for Addr {
    type Error = UrlError;
    fn try_from(value: String) -> Result<Addr, UrlError> {
        Addr::try_from(value.as_str())
    }
}


impl From<SocketAddr> for Addr {
    fn from(value: SocketAddr) -> Self {
        Addr {
            host: value.ip().to_string(),
            port: value.port(),
        }
    }
}


#[cfg(test)]
mod tests {
    use crate::Addr;

    #[test]
    fn test_addr() {
        let addr = Addr::new_addr("127.0.0.1", 1234);
        assert_eq!(addr.to_string(), "127.0.0.1:1234");
    }
}