use super::{DNSError, SvcParamValue, SvcType, DNS};
use crate::dns::add::Additional;
use crate::dns::value::{DNSValue, DnsType};
use crate::extend::EchConfig;
use crate::{rand, Writer, ALPN};
use std::io;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr, UdpSocket};
#[cfg(target_os = "windows")]
use std::ptr::null_mut;
use std::str::FromStr;
use std::time::Duration;


#[derive(Debug)]
pub struct DNSCache {
    addrs: Vec<IpAddr>,
    alpn: Vec<ALPN>,
    echo: EchConfig,
    time: u64,
}

impl DNSCache {
    pub fn new_addrs(addrs: Vec<IpAddr>) -> Self {
        DNSCache {
            addrs,
            alpn: vec![],
            echo: EchConfig::new(),
            time: 0,
        }
    }
    pub fn addrs(&self) -> &Vec<IpAddr> {
        &self.addrs
    }

    pub fn set_addrs(&mut self, addrs: Vec<IpAddr>) {
        self.addrs = addrs;
    }

    pub fn into_addrs(self) -> Vec<IpAddr> { self.addrs }

    pub fn alpn(&self) -> &Vec<ALPN> {
        &self.alpn
    }

    pub fn echo(&self) -> &EchConfig {
        &self.echo
    }

    pub fn time(&self) -> u64 { self.time }

    pub fn set_time(&mut self, time: u64) {
        self.time = time;
    }
}

pub struct DNSStream {
    dns_addr: SocketAddr,
    conn: UdpSocket,
    write_buf: Writer,
    read_buf: Vec<u8>,

}

#[cfg(target_os = "windows")]
#[repr(C)]
struct IpAddrString {
    next: *mut IpAddrString,
    ip_address: [u8; 16],
    ip_mask: [u8; 16],
    context: u32,
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct FixedInfo {
    host_name: [u8; 128 + 4],
    domain_name: [u8; 128 + 4],
    current_dns_server: *mut IpAddrString,
    dns_server_list: IpAddrString,
}

#[cfg(target_os = "windows")]
#[link(name = "iphlpapi")]
unsafe extern "system" {
    fn GetNetworkParams(p_fixed_info: *mut u8, p_out_buf_len: *mut u32) -> u32;
}

impl DNSStream {
    pub fn new() -> Result<DNSStream, DNSError> {
        let dns_addr = Self::get_dns_addr()?.into_iter().next().ok_or(DNSError::FindDnsAddrFailed)?;
        let conn = UdpSocket::bind("0.0.0.0:0").map_err(|_| DNSError::BindDnsAddrFailed)?;
        // conn.set_read_timeout(Some(Duration::from_millis(100))).map_err(DNSError::DnsIoError)?;
        Ok(DNSStream {
            dns_addr,
            conn,
            write_buf: Writer::with_capacity(256),
            read_buf: vec![0; 2048],
        })
    }

    fn get_dns_addr() -> Result<Vec<SocketAddr>, DNSError> {
        #[cfg(target_os = "linux")]
        return Self::get_dns_linux();
        #[cfg(target_os = "windows")]
        return Self::get_dns_win();
        #[cfg(all(not(target_os = "linux"), not(target_os = "windows")))]
        return Ok(vec![SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)), 8080)]);
    }

    #[cfg(target_os = "linux")]
    fn get_dns_linux() -> Result<Vec<SocketAddr>, DNSError> {
        let resolv = std::fs::read_to_string("/etc/resolv.conf").map_err(|_| DNSError::FindDnsAddrFailed)?.replace("\r\n", "\n");
        let mut res = vec![];
        for line in resolv.split("\n") {
            if !line.starts_with("nameserver") { continue; }
            let mut ip = line.split(" ");
            let _ = ip.next();
            let addr = IpAddr::from_str(ip.next().ok_or(DNSError::FindDnsAddrFailed)?).map_err(|_| DNSError::FindDnsAddrFailed)?;
            res.push(SocketAddr::new(addr, 53))
        }
        Ok(res)
    }

    #[cfg(target_os = "windows")]
    fn get_dns_win() -> Result<Vec<SocketAddr>, DNSError> {
        let mut len = 0;
        unsafe { GetNetworkParams(null_mut(), &mut len); }
        let mut buffer = vec![0; len as usize];
        unsafe { GetNetworkParams(buffer.as_mut_ptr(), &mut len) };
        let info = unsafe { (buffer.as_ptr() as *const FixedInfo).as_ref() }.ok_or(DNSError::FindDnsAddrFailed)?;
        let mut curr = &info.dns_server_list as *const IpAddrString;
        let mut addrs = vec![];
        while !curr.is_null() {
            if let Some(ptr) = unsafe { curr.as_ref() } && let Some(addr) = ptr.ip_address.split(|x| x == &0).next() && !addr.is_empty() {
                let addr = std::str::from_utf8(addr)?;
                let addr = IpAddr::from_str(addr).map_err(|_| DNSError::FindDnsAddrFailed)?;
                addrs.push(SocketAddr::new(addr, 53));
            }
            unsafe { curr = (*curr).next; }
        }
        Ok(addrs)
    }

    fn read(&mut self) -> Result<usize, DNSError> {
        for _ in 0..3 {
            match self.conn.recv(&mut self.read_buf) {
                Ok(len) => return Ok(len),
                Err(e) => if e.kind() == ErrorKind::WouldBlock {
                    self.conn.send_to(self.write_buf.filled(), self.dns_addr).map_err(DNSError::DnsIoError)?;
                    continue;
                } else { return Err(DNSError::DnsIoError(e)) }
            }
        }
        Err(DNSError::DnsIoError(io::Error::new(ErrorKind::TimedOut, "read timeout")))
    }

    pub fn get_dns_https(&mut self, domain: &str) -> Result<DNSCache, DNSError> {
        self.write_buf.reset();
        let cookie = rand::random::<[u8; 8]>();
        let add = Additional::new_opt(&cookie);
        let mut dns = DNS::new_query_https(domain);
        dns.add_additional(add);
        dns.write_to(&mut self.write_buf)?;
        self.conn.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
        self.conn.send_to(self.write_buf.filled(), self.dns_addr).map_err(DNSError::DnsIoError)?;
        let len = if let Ok(len) = self.read() {
            len
        }else { return Ok(DNSCache::new_addrs(vec![])) };
        let dns = DNS::from_bytes(&self.read_buf[..len])?;
        let answer = dns.answers().iter().find(|x| x.type_() == DnsType::HTTPS);
        let (alpn, addrs, echo) = if let Some(answer) = answer && let DNSValue::Https { params, .. } = answer.data() {
            let alpn = params.iter().find(|x| x.key == SvcType::ALPN).map(|x| {
                x.values.iter().filter_map(|x| if let SvcParamValue::ALPN(alpn) = x {
                    Some(ALPN::from_slice(alpn.as_bytes()))
                } else { None }).collect::<Vec<ALPN>>()
            }).unwrap_or(vec![]);
            let mut addrs = params.iter().find(|x| x.key == SvcType::IPV4).map(|x| {
                x.values.iter().filter_map(|x| if let SvcParamValue::IPV4(addr) = x {
                    Some(IpAddr::V4(*addr))
                } else { None }).collect::<Vec<IpAddr>>()
            }).unwrap_or(vec![]);
            if let Some(x) = params.iter().find(|x| x.key == SvcType::IPV6) {
                x.values.iter().for_each(|x| if let SvcParamValue::IPV6(addr) = x {
                    addrs.push(IpAddr::V6(*addr))
                })
            }
            let echo = params.iter().find(|x| x.key == SvcType::ECHO);
            let echo = if let Some(echo) = echo && let Some(value) = echo.values.first() && let SvcParamValue::ECHO(x) = value {
                EchConfig::from_bytes(&x[2..])?
            } else { EchConfig::new() };
            (alpn, addrs, echo)
        } else { (vec![], vec![], EchConfig::new()) };
        Ok(DNSCache {
            alpn,
            addrs,
            echo,
            time: 0,
        })
    }
}


#[cfg(test)]
mod test {
    use crate::dns::stream::DNSStream;

    #[test]
    fn test_https_dns() {
        let mut stream = DNSStream::new().unwrap();
        // let dns = stream.get_dns_https("crypto.cloudflare.com").unwrap();
        // println!("{:#?}", dns);
        // let dns = stream.get_dns_a("m.so.com").unwrap();
        // println!("{:#?}", dns);
        let dns = stream.get_dns_https("cn.bing.com").unwrap();
        println!("{:#?}", dns);
        // let dns = stream.get_dns_a("www.baidu.com").unwrap();
        // println!("{:#?}", dns);
        // let dns = stream.get_dns_aaaa("www.baidu.com").unwrap();
        // println!("{:#?}", dns);
    }
}