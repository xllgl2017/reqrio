use std::path::Path;
use crate::error::HlsResult;

pub struct HttpFile {
    filename: String,
    bytes: Vec<u8>,
    filed_name: String,
    file_type: String,
}

impl HttpFile {
    pub fn new(bytes: Vec<u8>) -> HttpFile {
        HttpFile {
            bytes,
            filename: format!("{}.png", "abbac323abe"),
            filed_name: "file".to_string(),
            file_type: "".to_string(),
        }
    }
    pub fn new_with_fp(fp: impl AsRef<Path>) -> HlsResult<HttpFile> {
        let fp = fp.as_ref();
        let filename = fp.file_name().ok_or("path error")?.display().to_string();
        let mut res = HttpFile::new(std::fs::read(fp)?);
        res.set_filename(filename);
        Ok(res)
    }

    pub fn set_filename(&mut self, filename: String) {
        self.filename = filename;
    }

    pub fn set_filed_name(&mut self, filed_name: String) {
        self.filed_name = filed_name;
    }

    pub fn filesize(&self) -> usize { self.bytes.len() }

    pub fn raw_bytes(&self) -> &[u8] { self.bytes.as_slice() }

    pub fn set_file_type(&mut self, file_type: String) {
        self.file_type = file_type;
    }

    pub fn file_type(&self) -> &str { &self.file_type }

    pub fn filed_name(&self) -> &str { &self.filed_name }

    pub fn filename(&self) -> &str { &self.filename }

}