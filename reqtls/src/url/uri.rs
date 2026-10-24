use super::param::Param;
use crate::UrlError;
use std::borrow::Cow;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone)]
pub struct Uri {
    path: String,
    params: Vec<Param>,
}

impl Default for Uri {
    fn default() -> Self {
        Uri {
            path: String::with_capacity(1),
            params: vec![],
        }
    }
}

impl Uri {
    pub fn path(&self) -> &str { &self.path }

    pub fn new_path(path: impl ToString) -> Uri {
        let path = path.to_string();
        Uri {
            path: path.to_string(),
            params: vec![],
        }
    }

    pub fn set_path(&mut self, path: impl ToString) {
        self.path = path.to_string();
    }

    /// `value` should be unencoded.
    pub fn insert_param<'a>(&mut self, name: impl ToString, value: impl Into<Cow<'a, str>>) {
        if self.path.is_empty() { self.path += "/"; }
        let name = name.to_string();
        let param = self.params.iter_mut().find(|x| x.name() == name);
        match param {
            None => self.params.push(Param::new_param(name, value)),
            Some(param) => param.set_value(value)
        }
    }

    pub fn remove_param(&mut self, name: impl ToString) -> Option<String> {
        let name = name.to_string();
        let pos = self.params.iter().position(|x| x.name() == name)?;
        self.params.remove(pos).into_value().ok()
    }

    pub fn params(&self) -> &Vec<Param> { &self.params }

    pub fn params_mut(&mut self) -> &mut Vec<Param> { &mut self.params }

    pub fn is_empty(&self) -> bool { self.path.is_empty() && self.params.is_empty() }

    pub fn len(&self) -> usize {
        self.path.len() + 1 + self.params.iter().map(|x| x.len()).sum::<usize>()
    }

    pub fn clear_params(&mut self) {
        self.params.clear();
    }

    pub fn join(&mut self, path: impl AsRef<str>) {
        if !self.path.ends_with("/") { self.path += "/"; }
        self.path += path.as_ref();
    }
}

impl Display for Uri {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.path.contains("://") {
            write!(f, "/{}", self.path)?
        } else {
            write!(f, "{}", self.path)?
        }
        if !self.params.is_empty() { write!(f, "?")?; }
        for (i, param) in self.params.iter().enumerate() {
            write!(f, "{}", param)?;
            if i != self.params.len() - 1 { write!(f, "&")?; }
        }
        Ok(())
    }
}

impl TryFrom<&str> for Uri {
    type Error = UrlError;
    fn try_from(uri: &str) -> Result<Uri, UrlError> {
        if uri.is_empty() { return Ok(Uri::new_path("/")); }
        let path_pos = uri.find('?').unwrap_or(uri.len());
        let path = uri[..path_pos].to_string();
        let mut params = vec![];
        if path_pos != uri.len() {
            let param = &uri[path_pos + 1..];
            for item in param.split("&") {
                params.push(Param::try_from(item)?);
            }
        }
        Ok(Uri {
            path,
            params,
        })
    }
}

impl TryFrom<String> for Uri {
    type Error = UrlError;
    fn try_from(value: String) -> Result<Uri, UrlError> {
        Uri::try_from(value.as_str())
    }
}