mod ext;
mod reader;
mod multi_form;

use crate::error::HlsResult;
use crate::reader::{HCow, ReadExt, RefReader, StrCow};
use crate::*;
use crate::{Application, ContentType, Text};
pub use ext::{BodyData, BodyExt};
pub use multi_form::{FileForm, FormError, HttpFile};
use reader::RawBodyReader;
pub use reader::H2BodyReader;
#[cfg(feature = "quic")]
pub use reader::H3BodyReader;
use reqrio_json::JsonValue;
use reqtls::{hash, rand};
#[cfg(feature = "serde")]
use serde::Serialize;
use std::borrow::Cow;
use std::sync::Arc;

pub enum BodyKind<'a> {
    Data(HCow<'a, JsonValue>),
    Bytes(Cow<'a, [u8]>),
    Files(HCow<'a, HttpFile>),
}

impl<'a, 'b: 'a> From<&'b BodyKind<'a>> for BodyKind<'a> {
    fn from(value: &'b BodyKind) -> Self {
        match value {
            BodyKind::Data(data) => BodyKind::Data(HCow::Borrowed(data.as_ref())),
            BodyKind::Bytes(bytes) => BodyKind::Bytes(Cow::Borrowed(bytes.as_ref())),
            BodyKind::Files(file) => BodyKind::Files(HCow::Borrowed(file.as_ref())),
        }
    }
}

pub struct Body<'a> {
    kind: BodyKind<'a>,
    ct: ContentType,
}

impl<'a, 'b: 'a> From<&'b Body<'a>> for Body<'a> {
    fn from(value: &'b Body<'a>) -> Self {
        Body {
            kind: BodyKind::from(&value.kind),
            ct: value.ct.clone(),
        }
    }
}

impl<'a> From<&'a JsonValue> for Body<'a> {
    fn from(json: &'a JsonValue) -> Body<'a> {
        Body {
            kind: BodyKind::Data(HCow::Borrowed(json)),
            ct: ContentType::json(),
        }
    }
}

impl<'a> From<JsonValue> for Body<'a> {
    fn from(json: JsonValue) -> Body<'a> {
        Body {
            kind: BodyKind::Data(HCow::Owned(json)),
            ct: ContentType::json(),
        }
    }
}

impl<'a> From<&'a [u8]> for Body<'a> {
    fn from(bytes: &'a [u8]) -> Body<'a> {
        Body {
            kind: BodyKind::Bytes(Cow::Borrowed(bytes)),
            ct: ContentType::Application(Application::OctetStream),
        }
    }
}

impl<'a> From<&'a Vec<u8>> for Body<'a> {
    fn from(bytes: &'a Vec<u8>) -> Body<'a> {
        Body {
            kind: BodyKind::Bytes(Cow::Borrowed(bytes)),
            ct: ContentType::Application(Application::OctetStream),
        }
    }
}

impl<'a> From<Vec<u8>> for Body<'a> {
    fn from(bytes: Vec<u8>) -> Body<'a> {
        Body {
            kind: BodyKind::Bytes(Cow::Owned(bytes)),
            ct: ContentType::Application(Application::OctetStream),
        }
    }
}

impl<'a, const N: usize> From<&'a [u8; N]> for Body<'a> {
    fn from(bytes: &'a [u8; N]) -> Body<'a> {
        Body {
            kind: BodyKind::Bytes(Cow::Borrowed(bytes)),
            ct: ContentType::Application(Application::OctetStream),
        }
    }
}

impl<'a> From<&'a str> for Body<'a> {
    fn from(text: &'a str) -> Body<'a> {
        Body {
            kind: BodyKind::Bytes(Cow::Borrowed(text.as_bytes())),
            ct: ContentType::Text(Text::Plain),
        }
    }
}

impl<'a> From<String> for Body<'a> {
    fn from(text: String) -> Body<'a> {
        Body {
            kind: BodyKind::Bytes(Cow::Owned(text.into_bytes())),
            ct: ContentType::Text(Text::Plain),
        }
    }
}

impl<'a> From<HttpFile> for Body<'a> {
    fn from(file: HttpFile) -> Body<'a> {
        let r = rand::random::<[u8; 16]>();
        let md5 = hash::md5_hex(r).unwrap_or_else(|_| hex::encode(r));
        let boundary = Arc::new(format!("----WebKitFormBoundary{}", &md5[..16]));
        Body {
            ct: ContentType::File(boundary.clone()),
            kind: BodyKind::Files(HCow::Owned(file.with_boundary(boundary))),

        }
    }
}

impl<'a> From<Option<()>> for Body<'a> {
    fn from(_: Option<()>) -> Self {
        Body::none()
    }
}


impl<'a> Body<'a> {
    pub fn new(body: BodyKind<'a>, ty: ContentType) -> Body<'a> {
        Body {
            kind: body,
            ct: ty,
        }
    }
    pub(crate) fn none() -> Body<'a> {
        Body {
            kind: BodyKind::Bytes(Cow::Borrowed(&[])),
            ct: ContentType::Null,
        }
    }

    #[cfg(feature = "serde")]
    pub fn json<T: Serialize>(value: &T) -> HlsResult<Body<'a>> {
        let bytes = json::to_string(value).map_err(|e| format!("struct to json error, {}", e))?;
        Ok(Body {
            kind: BodyKind::Bytes(Cow::Owned(bytes.into_bytes())),
            ct: ContentType::json(),
        })
    }

    #[cfg(feature = "serde")]
    pub fn form<T: Serialize>(value: &T) -> HlsResult<Body<'a>> {
        let form = json::from_struct(value).map_err(|e| format!("struct to json error, {}", e))?;
        Ok(Body {
            kind: BodyKind::Data(HCow::Owned(form)),
            ct: ContentType::form(),
        })
    }

    pub(crate) fn as_reader(&'a self) -> HlsResult<RawBodyReader<'a>> {
        match &self.kind {
            BodyKind::Data(data) => {
                if let ContentType::Application(Application::Json) = self.ct {
                    Ok(RawBodyReader::Data(RefReader::new_buf(StrCow::Owned(data.dump()))))
                } else {
                    let mut readers: RefReader<StrCow> = RefReader::default();
                    for (i, (k, v)) in data.entries().enumerate() {
                        readers.add_str(k);
                        readers.add_str("=");
                        match v.as_str() {
                            Ok(v) => {
                                match coder::url_encode(v) {
                                    Cow::Borrowed(_) => readers.add_str(v),
                                    Cow::Owned(o) => readers.add_string(o)
                                }
                            }
                            Err(_) => readers.add_string(coder::url_encode(v.dump()).into_owned())
                        }
                        if i != data.entries().count() - 1 { readers.add_str("&") }
                    }
                    Ok(RawBodyReader::Data(readers))
                }
            }
            BodyKind::Bytes(bytes) => Ok(RawBodyReader::Bytes(RefReader::new_buf(bytes.as_ref()))),
            BodyKind::Files(file) => Ok(RawBodyReader::File(file.as_reader()?)),
        }
    }

    pub fn to_vec(&self) -> HlsResult<Vec<u8>> {
        let mut body = self.as_reader()?;
        let mut res = vec![0; body.len()];
        let mut reader = Writer::from_ptr(res.as_mut());
        let len = body.read(&mut reader)?;
        assert_eq!(len, res.len());
        Ok(res)
    }

    pub fn to_string(&self) -> HlsResult<String> {
        let res = self.to_vec()?;
        Ok(String::from_utf8(res)?)
    }

    pub fn context_type(&self) -> &ContentType { &self.ct }
}

pub(crate) enum BodyReader<'a> {
    HTTP1(RawBodyReader<'a>),
    HTTP2(H2BodyReader<'a>),
    #[cfg(feature = "quic")]
    HTTP3(H3BodyReader<'a>),
}

impl<'a> ReadExt for BodyReader<'a> {
    fn wrote(&self) -> bool {
        match self {
            BodyReader::HTTP1(h1) => h1.wrote(),
            BodyReader::HTTP2(h2) => h2.wrote(),
            #[cfg(feature = "quic")]
            BodyReader::HTTP3(h3) => h3.wrote(),
        }
    }

    fn len(&self) -> usize {
        match self {
            BodyReader::HTTP1(h1) => h1.len(),
            BodyReader::HTTP2(h2) => h2.len(),
            #[cfg(feature = "quic")]
            BodyReader::HTTP3(h3) => h3.len(),
        }
    }

    fn read(&mut self, buf: &mut Writer) -> HlsResult<usize> {
        match self {
            BodyReader::HTTP1(h1) => h1.read(buf),
            BodyReader::HTTP2(h2) => h2.read(buf),
            #[cfg(feature = "quic")]
            BodyReader::HTTP3(h3) => h3.read(buf),
        }
    }
}