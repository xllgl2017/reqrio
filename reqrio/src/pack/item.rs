use std::borrow::Cow;
use std::fmt::{Debug, Display, Formatter};


#[derive(Clone)]
pub struct PackItem {
    pub(crate) name: Cow<'static, str>,
    pub(crate) value: Cow<'static, str>,
}


impl Display for PackItem {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(format!("HPack(\"{}\",\"{}\")", self.name, self.value).as_str())
    }
}

impl Debug for PackItem {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.to_string().as_str())
    }
}

impl PackItem {
    pub fn new(name: impl Into<Cow<'static, str>>, value: impl Into<Cow<'static, str>>) -> PackItem {
        PackItem {
            name: name.into(),
            value: value.into(),
        }
    }

    pub fn new_table_size(size: usize) -> PackItem {
        PackItem {
            name: Cow::Borrowed("update-table-size"),
            value: Cow::Owned(size.to_string()),
        }
    }

    pub fn name_value(&self) -> String {
        format!("{}: {}", self.name, self.value)
    }
    pub fn with_value(mut self, value: impl Into<Cow<'static, str>>) -> PackItem {
        self.value = value.into();
        self
    }
    pub fn set_name(&mut self, name: impl Into<Cow<'static, str>>) {
        self.name = name.into();
    }
    pub fn set_value(&mut self, value: impl Into<Cow<'static, str>>) {
        self.value = value.into();
    }
    pub fn name(&self) -> &str { &self.name }
    pub fn value(&self) -> &str { &self.value }

    /// Entry size = len(name) + len(value) + 32
    ///
    /// Reference: RFC 7541-4.1
    pub fn item_size(&self) -> usize {
        self.name.len() + self.value.len() + 32
    }
}


macro_rules! pack_item {
    ($name:expr, $value:expr) => {
        super::PackItem {
            name: std::borrow::Cow::Borrowed($name),
            value: std::borrow::Cow::Borrowed($value),
        }
    };
}

pub(crate) use pack_item;