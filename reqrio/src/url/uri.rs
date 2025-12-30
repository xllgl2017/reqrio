use std::fmt::{Display, Formatter};
use crate::error::HlsResult;
use crate::HlsError;
use super::param::Param;

#[derive(Debug, Clone)]
pub struct Uri {
    uri: String,
    params: Vec<Param>,
}

impl Uri {
    pub fn new() -> Uri {
        Uri {
            uri: "".to_string(),
            params: vec![],
        }
    }

    pub(crate) fn set_uri(&mut self, uri: impl ToString) {
        self.uri = uri.to_string();
    }

    pub(crate) fn parse_param(&mut self, item: &str) -> HlsResult<()> {
        for kv in item.split("&") {
            self.params.push(Param::try_from(kv)?);
        }
        Ok(())
    }

    pub fn insert_param(&mut self, name: impl ToString, value: impl ToString) {
        let name = name.to_string();
        let param = self.params.iter_mut().find(|x| x.name() == &name);
        match param {
            None => self.params.push(Param::new_param(name, value)),
            Some(param) => param.set_value(value),
        }
    }

    pub fn params(&self) -> &Vec<Param> { &self.params }

    pub fn clear_params(&mut self) {
        self.params.clear();
    }
}

impl Display for Uri {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let param = self.params.iter().map(|p| p.to_string()).collect::<Vec<_>>().join("&");
        if param.is_empty() {
            f.write_str(&self.uri)
        } else {
            f.write_str(&format!("{}?{}", self.uri, param))
        }
    }
}

impl TryFrom<&str> for Uri {
    type Error = HlsError;
    fn try_from(value: &str) -> HlsResult<Uri> {
        let mut items = value.split("?");
        let mut res = Uri::new();
        res.uri = items.next().unwrap_or("").to_string();
        res.parse_param(items.next().unwrap_or(""))?;
        Ok(res)
    }
}