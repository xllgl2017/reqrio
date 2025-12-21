use std::fmt::{Display, Formatter};
use crate::error::HlsError;

#[derive(Clone)]
pub enum Video {
    Mp4,
    MP2T,
}

impl Display for Video {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Video::Mp4 => f.write_str("video/mp4"),
            Video::MP2T => f.write_str("video/mp2t")
        }
    }
}

impl TryFrom<&str> for Video {
    type Error = HlsError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "mp4" => Ok(Video::Mp4),
            "mp2t" => Ok(Video::MP2T),
            _ => Err(format!("invalid video type: {}", value).into())
        }
    }
}