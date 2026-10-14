use std::fmt::Display;
use crate::Cookie;

#[derive(Clone)]
pub struct CookieManager(Vec<Cookie>);

impl CookieManager {
    pub fn new(inner: Vec<Cookie>) -> Self {
        CookieManager(inner)
    }

    pub fn push(&mut self, cookie: Cookie) {
        let exits = self.0.iter_mut().find(|x| x.name() == cookie.name());
        match exits {
            None => self.0.push(cookie),
            Some(exits) => *exits = cookie,
        }
    }

    pub fn inner(&self) -> &Vec<Cookie> { &self.0 }
    
    pub fn inner_mut(&mut self) -> &mut Vec<Cookie> { &mut self.0 }

    pub fn into_inner(self) -> Vec<Cookie> { self.0 }

    pub fn is_empty(&self) -> bool { self.0.is_empty() }

    pub fn get(&self, name: &str) -> Option<&Cookie> {
        self.0.iter().find(|c| c.name() == name)
    }

    pub fn remove(&mut self, name: &str) -> Option<Cookie> {
        let pos = self.0.iter().position(|c| c.name() == name);
        pos.map(|i| self.0.remove(i))
    }

    fn filter(&self, cookie: &&Cookie, host: &str, uri: &str) -> bool {
        host.contains(cookie.domain()) && uri.contains(cookie.path())
    }

    pub fn as_req(&self, host: &str, uri: &str) -> Vec<&Cookie> {
        self.0.iter().filter(|c| self.filter(c, host, uri)).collect()
    }
}

impl Display for CookieManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cookie = self.0.iter().map(|x| x.as_req()).collect::<Vec<_>>();
        write!(f, "{}", cookie.join("; "))
    }
}


#[cfg(test)]
mod tests {
    use crate::Cookie;
    use crate::cookie::CookieManager;

    #[test]
    fn test_cookie_manager() {
        let cookie = "GC=Q4sdCza0cnj5G7P5IvdIbE5FSUS6b4z5A0SujitITnpD8uTkDt_q4kntWQnMCm-fXZCaGxTessBv0CNz94OaTA; expires=Fri, 19 Dec 2025 03:53:27 GMT; domain=.bing.com; path=/; secure; samesite=none";
        let cookie = Cookie::from_res(cookie);
        let manager = CookieManager(vec![cookie]);
        let res = manager.as_req("cn.bing.com", "/api/get");
        assert_eq!(res.len(), 1)
    }
}