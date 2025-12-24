use crate::error::RlsResult;

#[derive(Debug, Clone)]
pub struct ALPN {
    len: usize,
    value: String,
}

impl ALPN {
    pub fn new() -> ALPN {
        ALPN {
            len: 0,
            value: "".to_string(),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> RlsResult<Vec<ALPN>> {
        let mut res = vec![];
        let mut index = 0;
        while index < bytes.len() {
            let mut alpn = ALPN::new();
            alpn.len = bytes[index] as usize;
            alpn.value = String::from_utf8(bytes[index + 1..alpn.len + index + 1].to_vec())?;
            index = index + 1 + alpn.len;
            res.push(alpn);
        }
        Ok(res)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = vec![self.value.len() as u8];
        res.extend(self.value.as_bytes());
        res
    }

    pub fn value(&self) -> &str {
        &self.value
    }
}

#[derive(Debug)]
pub struct ALPS {
    len: u16,
    values: Vec<ALPN>,
}

impl ALPS {
    pub fn new() -> ALPS {
        ALPS {
            len: 0,
            values: vec![],
        }
    }
    pub fn from_bytes(bytes: &[u8]) -> RlsResult<ALPS> {
        let mut res = ALPS::new();
        res.len = u16::from_be_bytes([bytes[0], bytes[1]]);
        res.values = ALPN::from_bytes(&bytes[2..res.len as usize + 2])?;
        Ok(res)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = vec![0, 0];
        for value in &self.values {
            res.extend(value.as_bytes());
        }
        let len = (res.len() - 2) as u16;
        res[0..2].clone_from_slice(len.to_be_bytes().as_slice());
        res
    }

    pub fn remove_h2_alpn(&mut self) {
        if self.values.len() == 1 {
            self.values = vec![ALPN {
                len: 8,
                value: "http/1.1".to_string(),
            }]
        } else {
            self.values = self.values.clone().into_iter().filter_map(|x| {
                if x.value != "h2" { Some(x) } else { None }
            }).collect();
        }
    }

    pub fn add_h2_alpn(&mut self) {
        self.values.clear();
        self.values = vec![
            ALPN {
                len: 2,
                value: "h2".to_string(),
            },
            ALPN {
                len: 8,
                value: "http/1.1".to_string(),
            },
            ALPN {
                len: 8,
                value: "http/1.0".to_string(),
            }
        ]
    }

    pub fn values(&self) -> &Vec<ALPN> {
        &self.values
    }
}