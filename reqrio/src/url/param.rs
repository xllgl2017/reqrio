use std::fmt::{Display, Formatter};
use crate::coder;
use crate::error::HlsError;

#[derive(Debug, Clone)]
pub struct Param {
    name: String,
    value: String,
}

impl Param {
    pub fn new() -> Param {
        Param {
            name: "".to_string(),
            value: "".to_string(),
        }
    }

    pub fn new_param(name: impl ToString, value: impl ToString) -> Param {
        let mut res = Param::new();
        res.name = name.to_string();
        res.value = value.to_string();
        res
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    pub fn take_value(self) -> String {
        self.value
    }

    pub fn set_value(&mut self, value: impl ToString) {
        self.value = value.to_string();
    }
}

impl Display for Param {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let res = format!("{}={}", self.name, coder::url_encode(&self.value));
        f.write_str(&res)
    }
}

impl TryFrom<&str> for Param {
    type Error = HlsError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut items = value.split("=");
        let mut res = Param::new();
        res.name = items.next().ok_or("name not found")?.to_string();
        let value = items.collect::<Vec<_>>().join("=");
        res.value = coder::url_decode(value)?.to_string();
        Ok(res)
    }
}