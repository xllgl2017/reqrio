#[cfg(feature = "export")]
use crate::json;
#[cfg(feature = "export")]
use json::JsonValue;


#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Cookie {
    name: String,
    value: String,
    age: i32,
    domain: String,
    path: String,
    http_only: bool,
    secure: bool,
    expires: String,
    same_site: String,
    icpsp: bool,
    equal_sign: bool,
}

impl Default for Cookie {
    fn default() -> Self {
        Cookie {
            name: "".to_string(),
            value: "".to_string(),
            age: -1,
            domain: "".to_string(),
            path: "".to_string(),
            http_only: false,
            secure: false,
            expires: "".to_string(),
            same_site: "".to_string(),
            icpsp: false,
            equal_sign: true,
        }
    }
}

impl Cookie {
    pub fn new_cookie(name: impl ToString, value: impl ToString) -> Cookie {
        Cookie {
            name: name.to_string(),
            value: value.to_string(),
            ..Default::default()
        }
    }

    pub fn equal_sign(&self) -> bool {
        self.equal_sign
    }

    pub fn with_equal_sign(mut self, value: bool) -> Self {
        self.equal_sign = value;
        self
    }

    pub fn insert(&mut self, k: &str, v: String) {
        match k.to_lowercase().as_str() {
            "httponly" => self.http_only = true,
            "secure" => self.secure = true,
            "path" => self.path = v,
            "max-age" => self.age = v.parse().unwrap_or(-1),
            "domain" => self.domain = v,
            "expires" => self.expires = v,
            "samesite" => self.same_site = v,
            "icpsp" => self.icpsp = true,
            _ => {
                self.name = k.to_string();
                self.value = v;
            }
        }
    }

    pub fn from_req(ck: impl AsRef<str>) -> Vec<Cookie> {
        let ck = ck.as_ref().trim();
        if ck.is_empty() { return vec![]; }
        let items = ck.split(";");
        let mut res = Vec::with_capacity(size_of::<Cookie>() * items.clone().count());
        for item in items {
            let cookie = item.trim();
            let (index, equal_sign) = match cookie.find('=') {
                None => (cookie.len(), false),
                Some(index) => (index, true)
            };
            let name: &str = cookie[..index].trim();
            let value: &str = if equal_sign { cookie[index + 1..].trim() } else { "" };
            res.push(Cookie {
                name: name.to_string(),
                value: value.to_string(),
                equal_sign,
                ..Default::default()
            });
        }
        res
    }
    pub fn from_res(ck: impl AsRef<str>) ->Cookie {
        let ck = ck.as_ref().trim();
        let mut cookie = Cookie::default();
        for item in ck.split(";") {
            let item = item.trim();
            if item.is_empty() { continue; }
            let index = item.find('=').unwrap_or(item.len());
            let name = item[..index].trim();
            let value = if index == item.len() { "" } else { item[index + 1..].trim() };
            cookie.insert(name, value.to_string());
        }
        cookie
    }
    pub fn as_res(&self) -> String {
        let mut res = vec![format!("{}={}", self.name, self.value)];
        if !self.expires.is_empty() { res.push(format!("expires={}", self.expires)); }
        if self.age != -1 { res.push(format!("Max-Age={}", self.age)); }
        if !self.path.is_empty() { res.push(format!("path={}", self.path)); }
        if !self.same_site.is_empty() { res.push(format!("samesite={}", self.same_site)); }
        if !self.domain.is_empty() { res.push(format!("domain={}", self.domain)); }
        if self.secure { res.push("secure".to_string()); }
        if self.http_only { res.push("httponly".to_string()); }
        if self.icpsp { res.push("icpsp".to_string()); }
        res.join("; ")
    }
    pub fn as_req(&self) -> String {
        format!("{}{}{}", self.name, if self.equal_sign { "=" } else { "" }, self.value)
    }
    pub fn set_name(&mut self, name: String) {
        self.name = name;
    }
    pub fn set_value(&mut self, value: String) {
        self.value = value;
    }
    pub fn set_age(&mut self, age: i32) {
        self.age = age;
    }
    pub fn set_domain(&mut self, domain: String) {
        self.domain = domain;
    }
    pub fn with_domain(mut self, domain: impl ToString) -> Self {
        self.set_domain(domain.to_string());
        self
    }
    pub fn with_expires(mut self, expires: impl ToString) -> Self {
        self.set_expires(expires.to_string());
        self
    }
    pub fn set_path(&mut self, path: String) {
        self.path = path;
    }
    pub fn with_path(mut self, path: impl ToString) -> Self {
        self.set_path(path.to_string());
        self
    }
    pub fn set_http_only(&mut self, http_only: bool) {
        self.http_only = http_only;
    }
    pub fn with_http_only(mut self, http_only: bool) -> Cookie {
        self.set_http_only(http_only);
        self
    }
    pub fn set_expires(&mut self, expires: String) {
        self.expires = expires;
    }
    pub fn value(&self) -> &str {
        &self.value
    }
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn path(&self) -> &str {
        &self.path
    }
}

#[cfg(feature = "export")]
impl From<&Cookie> for JsonValue {
    fn from(cookie: &Cookie) -> Self {
        json::object! {
            "name": cookie.name.clone(),
            "value": cookie.value.clone(),
            "age": cookie.age,
            "domain": cookie.domain.clone(),
            "path": cookie.path.clone(),
            "http_only": cookie.http_only,
            "secure": cookie.secure,
            "expires": cookie.expires.clone(),
            "same_site": cookie.same_site.clone(),
            "icpsp": cookie.icpsp,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::packet::http::cookie::Cookie;

    #[test]
    fn test_cookie() {
        let cookie1 = "_EDGE_V=1; MUIDB=184C10AD397866DF1A1607B038566708; MUID=184C10AD397866DF1A1607B038566708; _UR=QS=0&TQS=0&Pn=0; BFBUSR=BFBHP=0; MUIDB=184C10AD397866DF1A1607B038566708; SRCHD=AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF&AF=NOFORM; SRCHUID=V=2&GUID=EB7B9E5DE58F4D5690F6904732C24C7B&dmnchg=1; USRLOC=HS&ELOC=LAT=23.384721755981445|LON=113.44195556640625|N=%E7%99%BD%E4%BA%91%E5%8C%BA%EF%BC%8C%E5%B9%BF%E4%B8%9C%E7%9C%81|ELT=4|&HS=1; _RwBf=r&r&r&r&r=0&ilt=10&ihpd=5&ispd=3&rc=12&rb=0&rg=200&pc=12&mtu=0&rbb=0&clo=0&v=8&l=2026-03-15T07:00:00.0000000Z&lft=0001-01-01T00:00:00.0000000&aof=0&ard=0001-01-01T00:00:00.0000000&rwdbt=0&rwflt=0&rwaul2=0&g=&o=2&p=&c=&t=0&s=0001-01-01T00:00:00.0000000+00:00&ts=2026-03-15T14:03:35.7211444+00:00&rwred=0&wls=&wlb=&wle=&ccp=&cpt=&lka=0&lkt=0&aad=0&TH=&cid=0&gb=; SRCHUSR=DOB&DS&DS&DS&DS&DS=1&DOB=20260315; _EDGE_S=SID=357AA105805E678827ACB618817066E6; _SS=SID=357AA105805E678827ACB618817066E6; _HPVN=CS=eyJQbiI6eyJDbiI6MSwiU3QiOjAsIlFzIjowLCJQcm9kIjoiUCJ9LCJTYyI6eyJDbiI6MSwiU3QiOjAsIlFzIjowLCJQcm9kIjoiSCJ9LCJReiI6eyJDbiI6MSwiU3QiOjAsIlFzIjowLCJQcm9kIjoiVCJ9LCJBcCI6dHJ1ZSwiTXV0ZSI6dHJ1ZSwiTGFkIjoiMjAyNi0wMy0xNVQwMDowMDowMFoiLCJJb3RkIjowLCJHd2IiOjAsIlRucyI6MCwiRGZ0IjpudWxsLCJNdnMiOjAsIkZsdCI6MCwiSW1wIjozMCwiVG9ibiI6MH0=; SRCHHPGUSR=SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&V&SRCHLANG&SRCHLANG&SRCHLANG&V&SRCHLANG&SRCHLANG=zh-Hans&PREFCOL=0&BRW=NOTP&BRH=M&CW=150&CH=769&SCW=150&SCH=769&DPR=1.0&UTC=480&HV=1773588648&HVE=CfDJ8HAK7eZCYw5BifHFeUHnkJGC6_lT8f9GeruXx8zjPXuk-5GHkofYMoFErMkT8CTKKKsSt5O2HyGmjLyCEXbEREUmwCd8ZBlYMLSDZu1wZ-EI1LDuyIiI1tkP6Usyicm601qX3aJVYqVWUBn-t6h0ZWLiftm4aS627xFj1fE5PD-85i7BWTkhqG0uvaYzuSgB2A&BZA=0&PRVCW=150&PRVCH=769&B=0&EXLTT=7&V=CfDJ8HAK7eZCYw5BifHFeUHnkJGijeRjCoaCMaAnmznMvdEg2GXY8647Wb-7wnHNpePKXRO6KRQ_0cQc-onivd35uV-p-4g0MB0V_Z1ZpW-QSJe9zbPUG-Ks-kQMjzEl6GlLo6N0ciP51vkQdR-P-lCUH58&PR=1";
        let cookie = Cookie::from_req(cookie1);
        assert_eq!(cookie.len(), 15);
        let cookie2 = "GC=Q4sdCza0cnj5G7P5IvdIbE5FSUS6b4z5A0SujitITnpD8uTkDt_q4kntWQnMCm-fXZCaGxTessBv0CNz94OaTA; expires=Fri, 19 Dec 2025 03:53:27 GMT; domain=.bing.com; path=/; secure; samesite=none";
        let cookie = Cookie::from_res(cookie2);
        assert_eq!(cookie.name(), "GC");
        assert_eq!(cookie.age, -1);
        assert_eq!(cookie.domain, ".bing.com");
        assert_eq!(cookie.path, "/");
        assert!(!cookie.http_only);
        assert!(cookie.secure);
        assert_eq!(cookie.expires, "Fri, 19 Dec 2025 03:53:27 GMT")
    }
}