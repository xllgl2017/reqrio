use json::JsonValue;
use crate::file::HttpFile;

pub enum BodyType {
    Text(String),
    Bytes(Vec<u8>),
    Files((JsonValue, Vec<HttpFile>)),
    WwwForm(JsonValue),
    Json(JsonValue),
}

impl Drop for BodyType {
    fn drop(&mut self) {
        match self {
            BodyType::Text(v) => {
                v.clear();
                v.shrink_to_fit();
            }
            BodyType::Bytes(v) => {
                v.clear();
                v.shrink_to_fit();
            }
            BodyType::Files((v,fs)) => {
                v.clear();
                fs.clear();
                fs.shrink_to_fit();
            }
            BodyType::WwwForm(v) => v.clear(),
            BodyType::Json(v) => v.clear(),
        }
    }
}