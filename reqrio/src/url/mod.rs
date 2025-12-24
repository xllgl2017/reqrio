use crate::error::{HlsError, HlsResult};
pub use addr::Addr;
pub use protocol::Protocol;
use std::fmt::Display;
pub use uri::Uri;

mod addr;
mod param;
mod protocol;
mod uri;

#[derive(Debug, Clone)]
pub struct Url {
    protocol: Protocol,
    addr: Addr,
    uri: Uri,
}

impl Url {
    pub fn new() -> Url {
        Url {
            protocol: Protocol::Http,
            addr: Addr::new(),
            uri: Uri::new(),
        }
    }

    pub fn uri(&self) -> &Uri {
        &self.uri
    }

    pub fn uri_mut(&mut self) -> &mut Uri {
        &mut self.uri
    }

    pub fn set_uri(&mut self, uri: String) -> HlsResult<()> {
        let mut i = uri.split("?");
        self.uri.set_uri(i.next().ok_or("Invalid uri")?);
        self.uri.parse_param(i.next().unwrap_or(""))
    }

    pub fn addr(&self) -> &Addr {
        &self.addr
    }

    pub fn protocol(&self) -> &Protocol {
        &self.protocol
    }
}

impl Display for Url {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let addr = self.addr.to_string().replace(":443", "").replace(":80", "");
        let mut res = format!("{}://{}{}", self.protocol, addr, self.uri());
        if res.ends_with("?") {
            res = res[..res.len() - 1].to_string();
        }
        f.write_str(&res)
    }
}

impl TryFrom<String> for Url {
    type Error = HlsError;
    fn try_from(t: String) -> Result<Self, Self::Error> {
        Url::try_from(t.as_ref())
    }
}

impl TryFrom<&str> for Url {
    type Error = HlsError;
    fn try_from(t: &str) -> Result<Self, Self::Error> {
        let mut res = Url::new();
        let mut t = t.split("?");
        let base = t.next().ok_or("not found url base")?;
        let mut i = base.split("://");
        let protocol = i.next().ok_or("not found protocol")?;
        res.protocol = Protocol::try_from(protocol)?;
        let addr = i.next().ok_or("not found addr")?;
        let pos = addr.find("/");
        res.addr = match pos {
            None => {
                res.uri.set_uri("/");
                Addr::try_from(addr)?
            }
            Some(pos) => {
                res.uri.set_uri(addr[pos..].to_string());
                Addr::try_from(&addr[..pos])?
            }
        };
        if res.addr.port() == 0 {
            res.addr.set_port(res.protocol.default_port())
        }
        if let Some(param) = t.next() {
            res.uri.parse_param(param)?;
        }
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use crate::url::Url;

    #[test]
    fn test_url() {
        let url1 = "https://docs.rs/urlencoding/2.1.3/urlencoding/";
        let url = Url::try_from(url1).unwrap();
        println!("{:#?} {}", url, url.to_string() == url1);
        let url2 = "http://www.lxspider.com/?p=956";
        let url = Url::try_from(url2).unwrap();
        println!("{:#?} {}", url, url.to_string() == url2);
        let url3 = "https://fxg.jinritemai.com/ffa/morder/order/list?btm_ppre=a2427.b76571.c902327.d871297&btm_pre=a2427.b76571.c902327.d871297&btm_show_id=1bf5f779-f687-47db-8637-4941db8e409f";
        let url = Url::try_from(url3).unwrap();
        println!("{:#?} {}", url, url.to_string() == url3);
        let url4 = "https://cn.bing.com/search?q=abogus%E8%A1%A5%E7%8E%AF%E5%A2%83&qs=UT&pq=abogus&sk=OS1LT1&sc=5-6&cvid=50BFA522127149719EEDBC510E8F26D2&sp=3&ghc=1&lq=0&ajf=60&mkt=zh-CN&FPIG=078354D7800D43BBA67D7529C688C765&first=10&FORM=PORE1&ajf=70&dayref=1&ajf=10";
        let url = Url::try_from(url4).unwrap();
        println!("{:#?} {}", url, url.to_string() == url4);
        let url5 = "https://www.baidu.com";
        let url = Url::try_from(url5).unwrap();
        println!("{:#?} {}", url, url.to_string() == url5);
        let url6 = "socks5://127.0.0.1:1023";
        let url = Url::try_from(url6).unwrap();
        println!("{:#?} {}", url, url6.to_string() == url6);
        let url7 = "http://127.0.0.1:8080";
        let url = Url::try_from(url7).unwrap();
        println!("{:#?} {}", url, url.to_string() == url7);
        let url8 = "https://www.so.com/link?m=uJUHfEbfz+ZVSx90v4iLs4mlJ1cSfmojdrI1pYls/wftn5aL/ll53A6XAa1BSX2UtYWvcHBuUKSEURqhhVHtJNCWxeXYrgMOwkXoRLHGJ4yHLzOB1C61LDwQTgDd5OjTmAFlu3YJVdfU=";
        let url = Url::try_from(url8).unwrap();
        println!("{:#?} {}", url, url.to_string() == url8);
    }
}
