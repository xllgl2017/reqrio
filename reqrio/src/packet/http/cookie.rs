#[cfg(feature = "export")]
use json::JsonValue;
use crate::error::HlsResult;

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug)]
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
}

impl Cookie {
    pub fn new() -> Self {
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
        }
    }

    pub fn new_cookie(name: impl ToString, value: impl ToString) -> Cookie {
        let mut res = Cookie::new();
        res.name = name.to_string();
        res.value = value.to_string();
        res
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

    pub fn from_req(ck: impl AsRef<str>) -> HlsResult<Vec<Cookie>> {
        let mut res = vec![];
        let ck = ck.as_ref().replace("; ", ";");
        for cookie in ck.split(";") {
            let mut items = cookie.split("=");
            let mut cookie = Cookie::new();
            cookie.name = items.next().ok_or("cooke name not found")?.to_string();
            cookie.value = items.next().unwrap_or("").to_string();
            res.push(cookie);
        }
        Ok(res)
    }
    pub fn from_res(ck: impl AsRef<str>) -> HlsResult<Cookie> {
        let mut cookie = Cookie::new();
        let ck = ck.as_ref().replace("; ", ";");
        for item in ck.split(";").filter(|x| x != &"") {
            let mut items = item.split("=");
            let name = items.next().ok_or("cooke name not found")?;
            let value = items.next().unwrap_or("");
            cookie.insert(name, value.to_string());
        }
        Ok(cookie)
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
    pub fn as_req(&self) -> String { format!("{}={}", self.name, self.value) }
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
    pub fn set_path(&mut self, path: String) {
        self.path = path;
    }
    pub fn set_http_only(&mut self, http_only: bool) {
        self.http_only = http_only;
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
}

#[cfg(feature = "export")]
impl From<Cookie> for JsonValue {
    fn from(cookie: Cookie) -> Self {
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
        let cookie1 = "_EDGE_V=1; SRCHD=AF=NOFORM; SRCHUID=V=2&GUID=3AEBA45E639947BDB25C0B932701D4FB&dmnchg=1; MUIDB=2CB54C94A5B8630A3E345A24A496621E; SRCHUSR=DOB=20251126&DS=1&POEX=W; ANON=A=810A3248E83EF5C0C3F9C182FFFFFFFF; MUID=2EF86634B64061E808597099B7056038; MUIDB=2EF86634B64061E808597099B7056038; _U=1Gx8KzU1TOugm0M7vVh_b0PT8Rh1TSf22nOQoV_9B84NdgzPrSbC_0foiRrmaYLQsWEmxg6ubf64H8Oaf74qhVg8Ht1HZQiSLD3mjQ8UrfNGgpspo2W7JMvmfy8mZb3k9R5Lyyk4PMdFwZJ5L9T-4-fYxPTpXN0j6ObRllzJmhbx8V2HYAJyLw7PDcrRDK5IhP89G1_uRGLBfRboJvmECMQ; WLS=C=6571e3de6f8c1a9d&N=; _Rwho=u=d&ts=2025-12-15; _EDGE_S=SID=03A86FECEEF9656D08D5792FEF2B6499&mkt=zh-CN; USRLOC=HS=1&ELOC=LAT=23.389690399169922|LON=113.39459991455078|N=%E7%99%BD%E4%BA%91%E5%8C%BA%EF%BC%8C%E5%B9%BF%E4%B8%9C%E7%9C%81|ELT=5|&BID=MjUxMjE3MTkwOTI3X2IzNjFlMTRmMGM1ZmYwOTU4NTUwNGU4NmFjZDgwYTIxOTIxYzI4OWNhZWUyOGI2NjNmOTdhYzYyYWJiYjI1NDg=; BFPRResults=FirstPageUrls=D3841A9E4352BC9929AA00C7AB197AB9%2C9F8C0251FEB417C75B307BFA151A22D3%2C4CB951108993A5D0705CACA6FD1CC741%2C19D86A6CE228D5CA1DBBE50162254A6D%2C18A8FB111EB188733A31B73DEE641855%2CB17FD84727986CFC7DAA8D66AAD00918%2CE693A143DECA103B88765E7F99EC6700%2CAD92553AA082228ABF7D7C6635224381%2CF1E01DEDCE56853ED4432825780E6ED8%2CAEF5FFD33DA57A9E7EF5F95BF9ECE442&FPIG=078354D7800D43BBA67D7529C688C765; SNRHOP=I=&TS=; _RwBf=r=0&ilt=2&ihpd=0&ispd=5&rc=504&rb=504&rg=0&pc=504&mtu=0&rbb=0.0&clo=0&v=5&l=2025-12-16T08:00:00.0000000Z&lft=0001-01-01T00:00:00.0000000&aof=0&ard=0001-01-01T00:00:00.0000000&rwdbt=-62135539200&rwflt=1760343522&rwaul2=0&g=&o=0&p=MSAAUTOENROLL&c=MR000T&t=2279&s=2024-11-13T12:49:09.1007032+00:00&ts=2025-12-16T09:40:33.7317655+00:00&rwred=0&wls=2&wlb=0&wle=0&ccp=2&cpt=0&lka=0&lkt=0&aad=0&TH=&cid=0&gb=2025w18_u&mta=0&e=-dJPgHz14kC5WWWPJpzI_IJ6chA8pRbiiESmxP2BvfssVZ-yFUfaVwsHUIWGekBw22Fj4NurVQEpZol5STgDUw&A=; _SS=PC=ACTS&SID=03A86FECEEF9656D08D5792FEF2B6499&R=504&RB=504&GB=0&RG=0&RP=504; dsc=order=BingPages; SRCHHPGUSR=SRCHLANG=zh-Hans&PV=19.0.0&BZA=0&PREFCOL=0&BRW=XW&BRH=M&CW=1537&CH=953&SCW=1522&SCH=2083&DPR=1.0&UTC=480&B=0&EXLTT=6&AV=14&ADV=14&RB=0&MB=0&HV=1765878035&HVE=CfDJ8BJecyNyfxpMtsfDoM3OqQsVcYF0utrFhtCQkc9XinWXXiZrSBKVtuXT2StW6tNvoXlOnFUrqeCmSnlcLO5NyZTr_1ZxdyAKUsrYlkpZXsdX9EotsiD1s--SxmX5S4vJAcvGCzMigKNCJm0AN1pATRzancBb-aC77EmApzLk0tIiGQJrYnEHpp_OGzeXFdFQYw&PRVCW=1545&PRVCH=957; _C_ETH=1; GC=Q4sdCza0cnj5G7P5IvdIbE5FSUS6b4z5A0SujitITnpD8uTkDt_q4kntWQnMCm-fXZCaGxTessBv0CNz94OaTA";
        let cookie = Cookie::from_req(cookie1).unwrap();
        println!("{:#?}", cookie);
        let cookie2 = "GC=Q4sdCza0cnj5G7P5IvdIbE5FSUS6b4z5A0SujitITnpD8uTkDt_q4kntWQnMCm-fXZCaGxTessBv0CNz94OaTA; expires=Fri, 19 Dec 2025 03:53:27 GMT; domain=.bing.com; path=/; secure; samesite=none";
        let cookie = Cookie::from_res(cookie2).unwrap();
        println!("{:#?}", cookie);
    }
}