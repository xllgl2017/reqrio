use std::fmt::{Debug, Display, Formatter};
use std::ops::Index;

#[derive(Clone)]
pub struct HPack(String, String);


impl Display for HPack {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(format!("HPack(\"{}\",\"{}\")", self.0, self.1).as_str())
    }
}

impl Debug for HPack {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.to_string().as_str())
    }
}

impl HPack {
    pub fn new(name: impl ToString, value: impl ToString) -> HPack {
        HPack(name.to_string(), value.to_string())
    }
    pub fn name_value(&self) -> String {
        format!("{}: {}", self.0, self.1)
    }
    pub fn with_value(mut self, value: impl ToString) -> HPack {
        self.1 = value.to_string();
        self
    }
    pub fn set_name(&mut self, name: impl ToString) {
        self.0 = name.to_string();
    }
    pub fn set_value(&mut self, value: impl ToString) {
        self.1 = value.to_string();
    }
    pub fn to_h1_bytes(self) -> Vec<u8> { format!("{}: {}\r\n", self.0, self.1).into_bytes() }
    pub fn name(&self) -> &str { &self.0 }
    pub fn value(&self) -> &str { &self.1 }
    pub fn static_table() -> Vec<HPack> {
        vec![
            HPack::new(":authority", ""),
            HPack::new(":method", "GET"),
            HPack::new(":method", "POST"),
            HPack::new(":path", "/"),
            HPack::new(":path", "/index.html"),
            HPack::new(":scheme", "http"),
            HPack::new(":scheme", "https"),
            HPack::new(":status", "200"),
            HPack::new(":status", "204"),
            HPack::new(":status", "206"),
            HPack::new(":status", "304"),
            HPack::new(":status", "400"),
            HPack::new(":status", "404"),
            HPack::new(":status", "500"),
            HPack::new("accept-charset", ""),
            HPack::new("accept-encoding", ""),
            HPack::new("accept-language", ""),
            HPack::new("accept-ranges", ""),
            HPack::new("accept", ""),
            HPack::new("access-control-allow-origin", ""),
            HPack::new("age", ""),
            HPack::new("allow", ""),
            HPack::new("authorization", ""),
            HPack::new("cache-control", ""),
            HPack::new("content-disposition", ""),
            HPack::new("content-encoding", ""),
            HPack::new("content-language", ""),
            HPack::new("content-length", ""),
            HPack::new("content-location", ""),
            HPack::new("content-range", ""),
            HPack::new("content-type", ""),
            HPack::new("cookie", ""),
            HPack::new("date", ""),
            HPack::new("etag", ""),
            HPack::new("expect", ""),
            HPack::new("expires", ""),
            HPack::new("from", ""),
            HPack::new("host", ""),
            HPack::new("if-match", ""),
            HPack::new("if-modified-since", ""),
            HPack::new("if-none-match", ""),
            HPack::new("if-range", ""),
            HPack::new("if-unmodified-since", ""),
            HPack::new("last-modified", ""),
            HPack::new("link", ""),
            HPack::new("location", ""),
            HPack::new("max-forwards", ""),
            HPack::new("proxy-authenticate", ""),
            HPack::new("proxy-authorization", ""),
            HPack::new("range", ""),
            HPack::new("referer", ""),
            HPack::new("refresh", ""),
            HPack::new("retry-after", ""),
            HPack::new("server", ""),
            HPack::new("set-cookie", ""),
            HPack::new("strict-transport-security", ""),
            HPack::new("transfer-encoding", ""),
            HPack::new("user-agent", ""),
            HPack::new("vary", ""),
            HPack::new("via", ""),
            HPack::new("www-authenticate", ""),
        ]
    }
}

#[derive(Clone)]
pub struct HPackTable {
    tables: Vec<HPack>,
}

impl HPackTable {
    pub fn new() -> Self { HPackTable { tables: HPack::static_table() } }
    pub fn len(&self) -> usize { self.tables.len() }
    pub fn get(&self, index: usize) -> Option<&HPack> { self.tables.get(index) }
    pub fn insert(&mut self, index: usize, value: HPack) { self.tables.insert(index, value); }
    pub fn remove(&mut self, index: usize) -> HPack { self.tables.remove(index) }

    pub fn filter_by_name(&self, name: &str) -> Vec<&HPack> {
        self.tables.iter().filter_map(|t| if t.name() == name {
            Some(t)
        } else { None }).collect()
    }

    pub fn position(&self, pack: &HPack) -> Option<usize> {
        for (index, table) in self.tables.iter().enumerate() {
            if table.0 == pack.0 && table.1 == pack.1 { return Some(index); }
        }
        None
    }
}

impl Index<usize> for HPackTable {
    type Output = HPack;

    fn index(&self, index: usize) -> &Self::Output {
        &self.tables[index]
    }
}