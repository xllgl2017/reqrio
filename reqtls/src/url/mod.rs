use crate::coder::url_decode;
use crate::error::RlsResult;
pub use addr::Addr;
pub use error::UrlError;
pub use param::Param;
pub use scheme::Scheme;
use std::fmt::Display;
pub use uri::Uri;
use std::borrow::Cow;

mod addr;
mod param;
mod scheme;
mod uri;
mod error;

#[derive(Debug, Clone)]
pub struct Url {
    scheme: Scheme,
    addr: Addr,
    uri: Uri,
    username: String,
    password: String,
    domain: Option<String>,
}

impl Default for Url {
    fn default() -> Self {
        Url {
            scheme: Scheme::Http,
            addr: Addr::default(),
            uri: Uri::default(),
            username: "".to_string(),
            password: "".to_string(),
            domain: None,
        }
    }
}

impl Url {
    pub fn uri(&self) -> &Uri {
        &self.uri
    }

    pub fn uri_mut(&mut self) -> &mut Uri {
        &mut self.uri
    }

    pub fn with_uri(mut self, uri: impl AsRef<str>) -> RlsResult<Self> {
        self.set_uri(uri)?;
        Ok(self)
    }

    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }

    pub fn set_domain(&mut self, domain: impl Into<String>) {
        self.domain = Some(domain.into());
    }

    pub fn sni(&self) -> &str {
        self.domain.as_deref().unwrap_or(self.addr.host())
    }

    pub fn into_uri(self) -> Uri { self.uri }

    pub fn set_uri(&mut self, uri: impl AsRef<str>) -> RlsResult<()> {
        self.uri = Uri::try_from(uri.as_ref())?;
        Ok(())
    }

    pub fn addr(&self) -> &Addr {
        &self.addr
    }

    pub fn set_addr(&mut self, addr: Addr) {
        self.addr = addr;
    }

    pub fn scheme(&self) -> &Scheme {
        &self.scheme
    }
    pub fn set_scheme(&mut self, proto: Scheme) {
        self.scheme = proto;
    }

    pub fn protocol(&self) -> &Scheme {
        &self.scheme
    }

    pub fn into_inner(self) -> (Scheme, Addr, Uri) {
        (self.scheme, self.addr, self.uri)
    }

    pub fn from_inner(scheme: Scheme, addr: Addr, uri: Uri) -> Url {
        Url {
            scheme,
            addr,
            uri,
            ..Default::default()
        }
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn password(&self) -> &str {
        &self.password
    }

    pub fn set_username(&mut self, username: String) {
        self.username = username;
    }

    pub fn set_password(&mut self, password: String) {
        self.password = password;
    }

    pub fn insert_param<'a>(&mut self, name: impl ToString, value: impl Into<Cow<'a, str>>) {
        self.uri.insert_param(name, value);
    }

    pub fn join(&mut self, path: impl AsRef<str>) {
        self.uri.join(path)
    }
}

impl Display for Url {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}://", self.scheme.spec())?;
        write!(f, "{}", self.username)?;
        if !self.password.is_empty() {
            write!(f, "{}{}@", if self.username.is_empty() { "" } else { ":" }, self.password)?;
        }
        write!(f, "{}", self.addr.host())?;
        if self.addr.port() != 443 && self.addr.port() != 80 {
            write!(f, ":{}", self.addr.port())?;
        }
        write!(f, "{}", self.uri)
    }
}

impl TryFrom<String> for Url {
    type Error = UrlError;
    fn try_from(t: String) -> Result<Self, Self::Error> {
        Url::try_from(t.as_str())
    }
}

impl TryFrom<&str> for Url {
    type Error = UrlError;

    fn try_from(mut url: &str) -> Result<Self, Self::Error> {
        let scheme_pos = url.find("://").ok_or(UrlError::MissingScheme)?;
        let scheme = Scheme::from(&url[..scheme_pos]);
        url = &url[scheme_pos + 3..];
        let mut addr_pos = url.find("/").unwrap_or(url.len());
        let addr = &url[..addr_pos];
        let mut username = "".to_string();
        let mut password = "".to_string();
        let mut addr = if addr.contains('@') {
            let auth_pos = addr.find('@').ok_or(UrlError::AuthInfoError)?;
            let auth = &addr[..auth_pos];
            let username_pos = auth.find(':').ok_or(UrlError::MissingUsername)?;
            username = url_decode(&auth[..username_pos])?.into_owned();
            password = url_decode(&auth[username_pos + 1..])?.into_owned();
            Addr::try_from(&addr[auth_pos + 1..])?
        } else { Addr::try_from(addr)? };
        if addr.port() == 0 {
            addr.set_port(scheme.default_port());
        }
        let uri = if addr_pos != url.len() {
            // If `://` appears in the URI, it is likely a proxied URL (for example, `wss://`), so the leading `/` should be removed here.
            if url.split("?").next().map(|x| x.contains("://")).unwrap_or(false) { addr_pos += 1; }
            Uri::try_from(&url[addr_pos..])?
        } else { Uri::default() };
        Ok(Url {
            scheme,
            addr,
            username,
            password,
            uri,
            domain: None,
        })
    }
}

impl TryFrom<&String> for Url {
    type Error = UrlError;
    fn try_from(t: &String) -> Result<Self, Self::Error> {
        Url::try_from(t.as_str())
    }
}

impl TryFrom<&&mut String> for Url {
    type Error = UrlError;
    fn try_from(t: &&mut String) -> Result<Self, Self::Error> {
        Url::try_from(t.as_str())
    }
}

impl TryFrom<Result<Url, UrlError>> for Url {
    type Error = UrlError;
    fn try_from(result: Result<Url, UrlError>) -> Result<Self, Self::Error> {
        result
    }
}


#[cfg(test)]
mod tests {
    use crate::url::Url;

    #[test]
    fn test_url() {
        let url1 = "https://docs.rs/urlencoding/2.1.3/urlencoding/";
        let url = Url::try_from(url1).unwrap();
        assert_eq!(url.to_string(), url1);
        let url2 = "http://www.lxspider.com/?p=956";
        let url = Url::try_from(url2).unwrap();
        assert_eq!(url.to_string(), url2);
        let url3 = "https://fxg.jinritemai.com/ffa/morder/order/list?btm_ppre=a2427.b76571.c902327.d871297&btm_pre=a2427.b76571.c902327.d871297&btm_show_id=1bf5f779-f687-47db-8637-4941db8e409f";
        let url = Url::try_from(url3).unwrap();
        assert_eq!(url.to_string(), url3);
        let url4 = "https://cn.bing.com/search?q=abogus%E8%A1%A5%E7%8E%AF%E5%A2%83&qs=UT&pq=abogus&sk=OS1LT1&sc=5-6&cvid=50BFA522127149719EEDBC510E8F26D2&sp=3&ghc=1&lq=0&ajf=60&mkt=zh-CN&FPIG=078354D7800D43BBA67D7529C688C765&first=10&FORM=PORE1&ajf=70&dayref=1&ajf=10";
        let url = Url::try_from(url4).unwrap();
        assert_eq!(url.to_string(), url4);
        let url5 = "https://www.baidu.com/";
        let url = Url::try_from(url5).unwrap();
        assert_eq!(url.to_string(), url5);
        let url6 = "socks5://127.0.0.1:1023";
        let url = Url::try_from(url6).unwrap();
        assert_eq!(url.to_string(), url6);
        let url7 = "http://127.0.0.1:8080";
        let url = Url::try_from(url7).unwrap();
        assert_eq!(url.to_string(), url7);
        let url8 = "https://www.so.com/link?m=uJUHfEbfz+ZVSx90v4iLs4mlJ1cSfmojdrI1pYls/wftn5aL/ll53A6XAa1BSX2UtYWvcHBuUKSEURqhhVHtJNCWxeXYrgMOwkXoRLHGJ4yHLzOB1C61LDwQTgDd5OjTmAFlu3YJVdfU=";
        let url = Url::try_from(url8).unwrap();
        assert_eq!(url.to_string(), url8);
        let url9 = "wss://poe.game.qq.com/";
        let mut uri = Url::try_from(url9).unwrap();
        uri.set_uri("wss://poe.game.qq.com/api/trade2/live/poe2/%E7%93%A6%E5%B0%94%E7%9A%84%E5%AE%BF%E5%91%BD/32Y6Wjkc5").unwrap();
        let url10 = "wss://poe.game.qq.com/wss://poe.game.qq.com/api/trade2/live/poe2/%E7%93%A6%E5%B0%94%E7%9A%84%E5%AE%BF%E5%91%BD/32Y6Wjkc5";
        assert_eq!(uri.to_string(), url10);
        let url = Url::try_from(url10).unwrap();
        assert_eq!(url.to_string(), url10);
        let url6 = "socks5://username:passwrod@127.0.0.1:1023/";
        let url = Url::try_from(url6).unwrap();
        assert_eq!(url.to_string(), url6);
        let url11 = "https://login.gjzwfw.gov.cn/tacs-uc/sso/loginTrust?backUrl=https://oauth.hubei.gov.cn:8443/uias/mainChain.do?appCode=hbzwfw&checkUser=1";
        let url = Url::try_from(url11).unwrap();
        assert_eq!(url.to_string(), url11);
        let url12 = "https://life5-normal-m-zjg.amemv.com/aweme/v2/poi_shelf_api/second_page_shelf?poi_id=6601125223309772808&item_id&poi_enter_id=371ffca81e3ed1abda840f56f9b47955&location_permission=1&extra_params=%7B%22sale_channel%22%3A%22city_groupon.channel_page.default%22%2C%22poi_bottom_bar%22%3A%22mv_full_list%22%2C%22detail_enter_method%22%3A%22mv_full_list%22%7D&shelf_trim_v3=1&request_tag_from=h5&life_client_extra=%7B%22local_life_bcm_chain%22%3A%22%5B%7B%5C%22btm%5C%22%3A%5C%22a2552.b8562.c0.d0%5C%22%7D%2C%7B%5C%22btm%5C%22%3A%5C%22a2552.b14588.c760679.d63687%5C%22%2C%5C%22unit%5C%22%3A%7B%5C%22life_poi_id%5C%22%3A%5C%226601125223309772808%5C%22%2C%5C%22life_req_id%5C%22%3A%5C%221781188427708_2931724304786500_2109299690083371_196245%5C%22%2C%5C%22life_room_id%5C%22%3A%5C%227649937566917331738%5C%22%7D%7D%2C%7B%5C%22btm%5C%22%3A%5C%22a2552.b735718.c705138.d118440%5C%22%7D%2C%7B%5C%22btm%5C%22%3A%5C%22a1128.b0438.c0.d0%5C%22%7D%5D%22%7D&klink_egdi=AAKPDwSc4A2u67dEKdjLcj7La28C_5Id001etpNCiWL9hQKEUeYi7CZv&iid=4263230270877751&device_id=2109299690083371&ac=wifi&channel=huawei_1128_64&aid=1128&app_name=aweme&version_code=380000&version_name=38.0.0&device_platform=android&os=android&ssmix=a&device_type=2312DRAABC&device_brand=Redmi&language=zh&os_api=33&os_version=13&manifest_version_code=380001&resolution=1080*2262&dpi=440&update_version_code=38009900&_rticket=1781188437951&package=com.ss.android.ugc.aweme&first_launch_timestamp=1781161579&last_deeplink_update_version_code=0&cpu_support64=true&host_abi=arm64-v8a&is_guest_mode=0&app_type=normal&minor_status=0&appTheme=light&is_preinstall=0&need_personal_recommend=1&is_android_pad=0&is_android_fold=0&ts=1781188437&cdid=3db2741c-7990-4e09-b9b9-2acfbd0b42bb";
        let url = Url::try_from(url12).unwrap();
        assert_eq!(url.to_string(), url12);
    }
}
