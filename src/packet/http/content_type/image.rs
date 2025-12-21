use std::fmt::{Display, Formatter};
use crate::error::HlsError;

#[derive(Clone)]
pub enum ImageType {
    AVif,
    Webp,
    Apng,
    Png,
    Gif,
    Jpeg,
    SvgXml,
    XIcon,
    WxPic,
}

impl Display for ImageType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ImageType::AVif => f.write_str("image/avif"),
            ImageType::Webp => f.write_str("image/webp"),
            ImageType::Apng => f.write_str("image/apng"),
            ImageType::Png => f.write_str("image/png"),
            ImageType::Gif => f.write_str("image/gif"),
            ImageType::Jpeg => f.write_str("image/jpeg"),
            ImageType::SvgXml => f.write_str("image/svg+xml"),
            ImageType::XIcon => f.write_str("image/x-icon"),
            ImageType::WxPic => f.write_str("image/wxpic")
        }
    }
}

impl TryFrom<&str> for ImageType {
    type Error = HlsError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "gif" => Ok(ImageType::Gif),
            "jpeg" => Ok(ImageType::Jpeg),
            "png" => Ok(ImageType::Png),
            "svg+xml" => Ok(ImageType::SvgXml),
            "webp" => Ok(ImageType::Webp),
            "apng" => Ok(ImageType::Apng),
            "avif" => Ok(ImageType::AVif),
            "x-icon" => Ok(ImageType::XIcon),
            _ => Err(format!("invalid image type {}", value).into()),
        }
    }
}