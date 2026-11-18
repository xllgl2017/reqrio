use crate::error::HlsError;
pub use application::Application;
pub use font::Font;
pub use image::ImageType;
use std::borrow::Cow;
use std::fmt::{Display, Formatter};
use std::sync::Arc;
pub use text::Text;
pub use video::Video;

mod application;
mod image;
mod text;
mod font;
mod video;

#[derive(Clone)]
#[cfg_attr(debug_assertions, derive(PartialEq, Debug))]
pub enum ContentType {
    Application(Application),
    Image(ImageType),
    Text(Text),
    File(Arc<String>),
    Multipart,
    Font(Font),
    Video(Video),
    Binary(BinaryType),
    Upgrade,
    Custom(String),
    Null,
}

impl ContentType {
    pub const fn form() -> ContentType {
        ContentType::Application(Application::XWwwFormUrlencoded)
    }
    pub const fn json() -> ContentType {
        ContentType::Application(Application::Json)
    }

    pub const fn text() -> ContentType {
        ContentType::Text(Text::Plain)
    }

    pub fn spec(&self) -> Cow<'_, str> {
        match self {
            ContentType::Application(v) => Cow::Borrowed(v.spec()),
            ContentType::Image(v) => Cow::Borrowed(v.spec()),
            ContentType::Text(v) => Cow::Borrowed(v.spec()),
            ContentType::File(v) => Cow::Owned(format!("multipart/form-data; boundary={}", v)),
            ContentType::Multipart => Cow::Borrowed("multipart/form-data"),
            ContentType::Font(v) => Cow::Borrowed(v.spec()),
            ContentType::Video(v) => Cow::Borrowed(v.spec()),
            ContentType::Binary(_) => Cow::Borrowed("binary/octet-stream"),
            ContentType::Upgrade => Cow::Borrowed("Upgrade"),
            ContentType::Custom(v) => Cow::Borrowed(v),
            ContentType::Null => Cow::Borrowed(""),
        }
    }
}

impl Display for ContentType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.spec())
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
            "multipart" => Ok(ContentType::Multipart),
            "font" => Ok(ContentType::Font(Font::try_from(ts)?)),
            "video" => Ok(ContentType::Video(Video::try_from(ts)?)),
            "jpeg" => Ok(ContentType::Image(ImageType::Jpeg)),
            "upgrade" => Ok(ContentType::Upgrade),
            "binary" => Ok(ContentType::Binary(BinaryType::OctetStream)),
            _ => Ok(ContentType::Custom(value.to_string())),
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

impl From<Application> for ContentType {
    fn from(value: Application) -> Self {
        ContentType::Application(value)
    }
}

impl From<ImageType> for ContentType {
    fn from(value: ImageType) -> Self {
        ContentType::Image(value)
    }
}

impl From<Text> for ContentType {
    fn from(value: Text) -> Self {
        ContentType::Text(value)
    }
}

impl From<Font> for ContentType {
    fn from(value: Font) -> Self {
        ContentType::Font(value)
    }
}

#[derive(Clone)]
#[cfg_attr(debug_assertions, derive(PartialEq, Debug))]
pub enum BinaryType {
    OctetStream
}