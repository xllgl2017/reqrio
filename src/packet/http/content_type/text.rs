use std::fmt::{Display, Formatter};
use crate::error::HlsError;

#[derive(Clone)]
pub enum Text {
    Css,
    Html,
    Plain,
    JavaScript,
    EventStream,
    Xml,
    XComponent,
    Json,
}

impl Display for Text {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Text::Css => f.write_str("text/css"),
            Text::Html => f.write_str("text/html"),
            Text::Plain => f.write_str("text/plain"),
            Text::JavaScript => f.write_str("text/javascript"),
            Text::EventStream => f.write_str("text/event-stream"),
            Text::Xml => f.write_str("text/xml"),
            Text::XComponent => f.write_str("text/x-component"),
            Text::Json => f.write_str("text/json")
        }
    }
}

impl TryFrom<&str> for Text {
    type Error = HlsError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "plain" => Ok(Text::Plain),
            "html" => Ok(Text::Html),
            "css" => Ok(Text::Css),
            "javascript" => Ok(Text::JavaScript),
            "event-stream" => Ok(Text::EventStream),
            "xml" => Ok(Text::Xml),
            "x-component" => Ok(Text::XComponent),
            _ => Err(format!("invalid text type {} ", value).into()),
        }
    }
}