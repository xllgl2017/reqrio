use crate::error::HlsError;
use std::fmt::{Display, Formatter};

#[derive(Clone)]
#[cfg_attr(debug_assertions, derive(PartialEq, Debug))]
pub enum Video {
    Mp4,
    MP2T,
    Custom(String),
}

impl Video {
    pub fn spec(&self) -> &str {
        match self {
            Video::Mp4 => "video/mp4",
            Video::MP2T => "video/mp2t",
            Video::Custom(spec) => spec,
        }
    }
}

impl Display for Video {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.spec())
    }
}

impl TryFrom<&str> for Video {
    type Error = HlsError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "mp4" => Ok(Video::Mp4),
            "mp2t" => Ok(Video::MP2T),
            _ => Ok(Video::Custom(value.to_string())),
        }
    }
}