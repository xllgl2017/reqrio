mod error;
mod field;
mod reader;
mod file_form;

use crate::error::HlsResult;
use crate::body::multi_form::field::FormField;
use crate::reader::RefReader;
pub use error::FormError;
pub use reader::HttpFileReader;
use reqrio_json::JsonValue;
use std::path::Path;
use std::sync::Arc;
pub use file_form::FileForm;

/// * File upload example
/// ```no_run
/// use reqrio::*;
/// let data=json::object!{"key":"value"};
/// let mut file=HttpFile::new_path_data(data,"path/to/file1").unwrap();
/// file.add_form(FileForm::new_path("path/to/file2").unwrap());
/// let mut req=ScReq::new();
/// req.post("https://url/api",file).unwrap();
/// ```
pub struct HttpFile {
    data: Vec<FormField>,
    forms: Vec<FileForm>,
    boundary: Arc<String>,
}

impl Default for HttpFile {
    fn default() -> Self {
        HttpFile {
            data: vec![],
            forms: vec![],
            boundary: Arc::new(String::new()),
        }
    }
}

impl HttpFile {
    #[inline]
    pub fn new_bytes(bytes: impl Into<Vec<u8>>) -> HttpFile {
        HttpFile::new_bytes_data(JsonValue::Null, bytes)
    }

    pub fn new_bytes_data(data: JsonValue, bytes: impl Into<Vec<u8>>) -> HttpFile {
        HttpFile {
            data: data.into_entries().map(|(k, v)| FormField::new(k, v.dump())).collect(),
            forms: vec![FileForm::new_bytes(bytes)],
            boundary: Arc::new("".to_string()),
        }
    }

    #[inline]
    pub fn new_path(path: impl AsRef<Path>) -> HlsResult<HttpFile> {
        HttpFile::new_path_data(JsonValue::Null, path)
    }

    pub fn new_path_data(data: JsonValue, path: impl AsRef<Path>) -> HlsResult<HttpFile> {
        Ok(HttpFile {
            data: data.into_entries().map(|(k, v)| FormField::new(k, v.dump())).collect(),
            forms: vec![FileForm::new_path(path)?],
            boundary: Arc::new("".to_string()),
        })
    }

    #[inline]
    pub fn new_form(form: FileForm) -> HttpFile {
        HttpFile::new_form_data(JsonValue::Null, form)
    }

    pub fn new_form_data(data: JsonValue, form: FileForm) -> HttpFile {
        HttpFile {
            data: data.into_entries().map(|(k, v)| FormField::new(k, v.dump())).collect(),
            forms: vec![form],
            boundary: Arc::new("".to_string()),
        }
    }

    pub fn set_data(&mut self, data: JsonValue) {
        self.data = data.into_entries().map(|(k, v)| FormField::new(k, v.dump())).collect();
    }

    #[inline]
    pub fn with_boundary(mut self, boundary: Arc<String>) -> HttpFile {
        self.set_boundary(boundary);
        self
    }

    #[inline]
    pub fn set_boundary(&mut self, boundary: Arc<String>) {
        self.boundary = boundary;
    }

    #[inline]
    pub fn add_form(&mut self, form: FileForm) {
        self.forms.push(form);
    }

    #[inline]
    pub fn remove_form(&mut self, index: usize) -> FileForm {
        self.forms.remove(index)
    }

    #[inline]
    pub fn forms(&self) -> &[FileForm] {
        &self.forms
    }

    pub(crate) fn as_reader(&self) -> HlsResult<HttpFileReader<'_>> {
        let mut suffix_reader: RefReader<&[u8]> = RefReader::default();
        suffix_reader.add_buf(b"--");
        suffix_reader.add_buf(self.boundary.as_bytes());
        // TODO: placeholder for the pending implementation
        suffix_reader.add_buf(b"--");
        let mut files = vec![];
        for form in &self.forms {
            files.push(form.as_form_render(&self.boundary)?);
        }
        Ok(HttpFileReader {
            data_readers: self.data.iter().map(|x| x.as_render(&self.boundary)).collect(),
            files,
            suffix_reader,
            row: 0,
            pos: 0,
            wrote: false,
        })
    }
}

