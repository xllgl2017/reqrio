use std::fmt::{Display, Formatter};
pub use application::Application;
pub use image::ImageType;
pub use text::Text;
pub use font::Font;
pub use video::Video;
use crate::error::HlsError;

mod application;
mod image;
mod text;
mod font;
mod video;

#[derive(Clone)]
pub enum ContentType {
    Application(Application),
    Image(ImageType),
    Text(Text),
    File(String),
    Multipart,
    Font(Font),
    Video(Video),
    Upgrade,
}

impl Display for ContentType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ContentType::Application(v) => f.write_str(&v.to_string()),
            ContentType::Image(v) => f.write_str(&v.to_string()),
            ContentType::Text(v) => f.write_str(&v.to_string()),
            ContentType::File(uuid) => f.write_str(&format!("multipart/form-data; boundary={}", uuid)),
            ContentType::Multipart => f.write_str("multipart/form-data"),
            ContentType::Font(v) => f.write_str(&v.to_string()),
            ContentType::Video(v) => f.write_str(&v.to_string()),
            ContentType::Upgrade => f.write_str("Upgrade")
        }
    }
}

impl TryFrom<&str> for ContentType {
    type Error = HlsError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut t = value.split("/");
        let tf = t.next().ok_or("invalid content-type")?;
        let ts = t.next().unwrap_or(tf).split(";").next().ok_or("invalid content-type")?;
        let ts = ts.split(" ").next().ok_or("invalid content-type")?;
        match tf {
            "application" => Ok(ContentType::Application(Application::try_from(ts)?)),
            "image" => Ok(ContentType::Image(ImageType::try_from(ts)?)),
            "text" => Ok(ContentType::Text(Text::try_from(ts)?)),
            "multipart/form-data" => Ok(ContentType::Multipart),
            "font" => Ok(ContentType::Font(Font::try_from(ts)?)),
            "video" => Ok(ContentType::Video(Video::try_from(ts)?)),
            "jpeg" => Ok(ContentType::Image(ImageType::Jpeg)),
            "upgrade" => Ok(ContentType::Upgrade),
            _ => Err(format!("invalid content type: {}", value).into()),
        }
    }
}

impl TryFrom<&String> for ContentType {
    type Error = HlsError;
    fn try_from(value: &String) -> Result<Self, Self::Error> {
        ContentType::try_from(value.as_str())
    }
}

impl TryFrom<String> for ContentType {
    type Error = HlsError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        ContentType::try_from(value.as_str())
    }
}