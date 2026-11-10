use std::fmt::{Display, Formatter};
use crate::error::HlsError;

#[derive(Clone)]
#[cfg_attr(debug_assertions, derive(PartialEq, Debug))]
pub enum ImageType {
    AVif,
    Webp,
    Apng,
    Png,
    Gif,
    Jpg,
    Jpeg,
    SvgXml,
    XIcon,
    WxPic,
    Custom(String),
}

impl ImageType {
    pub fn spec(&self) -> &str {
        match self {
            ImageType::AVif => "image/avif",
            ImageType::Webp => "image/webp",
            ImageType::Apng => "image/apng",
            ImageType::Png => "image/png",
            ImageType::Gif => "image/gif",
            ImageType::Jpg => "image/jpg",
            ImageType::Jpeg => "image/jpeg",
            ImageType::SvgXml => "image/svg+xml",
            ImageType::XIcon => "image/x-icon",
            ImageType::WxPic => "image/wxpic",
            ImageType::Custom(value) => value,
        }
    }
}

impl Display for ImageType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.spec())
    }
}

impl TryFrom<&str> for ImageType {
    type Error = HlsError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "gif" => Ok(ImageType::Gif),
            "jpg" => Ok(ImageType::Jpg),
            "jpeg" => Ok(ImageType::Jpeg),
            "png" => Ok(ImageType::Png),
            "svg+xml" => Ok(ImageType::SvgXml),
            "webp" => Ok(ImageType::Webp),
            "apng" => Ok(ImageType::Apng),
            "avif" => Ok(ImageType::AVif),
            "x-icon" => Ok(ImageType::XIcon),
            _ => Ok(ImageType::Custom(value.to_string())),
        }
    }
}