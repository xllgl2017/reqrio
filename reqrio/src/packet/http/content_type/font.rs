use std::fmt::{Display, Formatter};
use crate::error::HlsError;

#[derive(Clone)]
pub enum Font {
    Woff2,
    Woff,
    Otf,
    Ttf,
}

impl Display for Font {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Font::Woff2 => f.write_str("font/woff2"),
            Font::Woff => f.write_str("font/woff"),
            Font::Otf => f.write_str("font/otf"),
            Font::Ttf => f.write_str("font/ttf")
        }
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
            _ => Err(format!("invalid font type {} ", value).into()),
        }
    }
}