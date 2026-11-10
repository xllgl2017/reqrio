use std::fmt::{Display, Formatter};
use crate::error::HlsError;

#[derive(Clone)]
#[cfg_attr(debug_assertions, derive(PartialEq, Debug))]
pub enum Font {
    Woff2,
    Woff,
    Otf,
    Ttf,
    Custom(String),
}

impl Font {
    pub fn spec(&self) -> &str {
        match self {
            Font::Woff2 => "font/woff2",
            Font::Woff => "font/woff",
            Font::Otf => "font/otf",
            Font::Ttf => "font/ttf",
            Font::Custom(spec) => spec,
        }
    }
}

impl Display for Font {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.spec())
    }
}

impl TryFrom<&str> for Font {
    type Error = HlsError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "woff2" => Ok(Font::Woff2),
            "woff" => Ok(Font::Woff),
            "otf" => Ok(Font::Otf),
            "ttf" => Ok(Font::Ttf),
            _ => Ok(Font::Custom(value.to_string())),
        }
    }
}