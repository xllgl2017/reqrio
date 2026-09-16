use crate::error::HlsResult;
use crate::reader::{ReadExt, RefReader};
use reqtls::Writer;
use std::fs::File;
use std::io::{Cursor, Read};

pub struct HttpFileReader<'a> {
    pub(crate) data_readers: Vec<RefReader<&'a [u8]>>,
    pub(crate) files: Vec<FileFormReader<'a>>,
    pub(crate) suffix_reader: RefReader<&'a [u8]>,
    pub(crate) row: usize,
    pub(crate) pos: usize,
    pub(crate) wrote: bool,
}


impl<'a> ReadExt for HttpFileReader<'a> {
    fn wrote(&self) -> bool {
        self.wrote
    }

    fn len(&self) -> usize {
        let data_len: usize = self.data_readers.iter().map(|x| x.len()).sum();
        let file_len: usize = self.files.iter().map(|x| x.len()).sum();
        let suffix_len: usize = self.suffix_reader.len();
        data_len + file_len + suffix_len
    }

    fn read(&mut self, buf: &mut Writer) -> HlsResult<usize> {
        let start = buf.offset().end;
        if self.row == 0 {
            for (index, data_reader) in self.data_readers.iter_mut().enumerate() {
                if index < self.pos { continue; }
                data_reader.read(buf)?;
                match data_reader.wrote() {
                    true => self.pos += 1,
                    false => return Ok(buf.offset().end - start)
                }
            }
            self.row += 1;
            self.pos = 0;
        }
        if self.row == 1 {
            for (i, form) in self.files.iter_mut().enumerate() {
                if i < self.pos { continue; }
                form.read(buf)?;
                match form.wrote() {
                    true => self.pos += 1,
                    false => return Ok(buf.offset().end - start)
                }
            }
            self.row += 1;
        }
        if self.row == 2 {
            self.suffix_reader.read(buf)?;
            match self.suffix_reader.wrote() {
                true => self.pos += 1,
                false => return Ok(buf.offset().end - start)
            }
        }
        self.wrote = true;
        Ok(buf.offset().end - start)
    }
}

pub enum FileDataRender<'a> {
    File((usize, usize, File)),
    Bytes(Cursor<&'a [u8]>),
}

impl<'a> ReadExt for FileDataRender<'a> {
    fn wrote(&self) -> bool {
        match self {
            FileDataRender::File((wrote, size, _)) => wrote == size,
            FileDataRender::Bytes(bytes) => bytes.position() as usize == bytes.get_ref().len(),
        }
    }

    fn len(&self) -> usize {
        match self {
            FileDataRender::File((_, size, _)) => *size,
            FileDataRender::Bytes(bs) => bs.get_ref().len()
        }
    }

    fn read(&mut self, buf: &mut Writer) -> HlsResult<usize> {
        match self {
            FileDataRender::File((wrote, _, f)) => {
                let len = f.read(buf.unfilled())?;
                buf.add_len(len);
                *wrote += len;
                Ok(len)
            }
            FileDataRender::Bytes(bs) => {
                let len = bs.read(buf.unfilled())?;
                buf.add_len(len);
                Ok(len)
            }
        }
    }
}

pub(crate) struct FileFormReader<'a> {
    pub(crate) prefix_reader: RefReader<&'a [u8]>,
    pub(crate) file_reader: FileDataRender<'a>,
    pub(crate) suffix_reader: RefReader<&'a [u8]>,
    pub(crate) pos: usize,
}

impl<'a> ReadExt for FileFormReader<'a> {
    fn wrote(&self) -> bool {
        self.pos > 2
    }

    fn len(&self) -> usize {
        self.prefix_reader.len() + self.file_reader.len() + self.suffix_reader.len()
    }

    fn read(&mut self, buf: &mut Writer) -> HlsResult<usize> {
        let start = buf.offset().end;
        if self.pos == 0 {
            self.prefix_reader.read(buf)?;
            match self.prefix_reader.wrote() {
                true => self.pos += 1,
                false => return Ok(buf.offset().end - start),
            }
        }
        if self.pos == 1 {
            self.file_reader.read(buf)?;
            match self.file_reader.wrote() {
                true => self.pos += 1,
                false => return Ok(buf.offset().end - start),
            }
        }
        if self.pos == 2 {
            self.suffix_reader.read(buf)?;
            match self.suffix_reader.wrote() {
                true => self.pos += 1,
                false => return Ok(buf.offset().end - start)
            }
        }
        Ok(buf.offset().end - start)
    }
}

#[cfg(test)]
mod tests {
    use crate::reader::ReadExt;
    use crate::{json, HttpFile};
    use reqtls::Writer;
    use std::sync::Arc;

    #[test]
    fn test_files_reader() {
        let file = HttpFile::new_bytes_data(json::object! {"test filed":"value"}, b"test file data")
            .with_boundary(Arc::new("----WebKitFormBoundary1234567812345678".to_string()));
        let mut reader = file.as_reader().unwrap();
        let mut res = [0; 1024];
        let mut writer = Writer::from_ptr(res.as_mut());
        let len = reader.read(&mut writer).unwrap();
        let raw = vec![
            "------WebKitFormBoundary1234567812345678",
            "Content-Disposition: form-data; name=\"test filed\"",
            "",
            "value",
            "------WebKitFormBoundary1234567812345678",
            "Content-Disposition: form-data; name=\"file\"; filename=\"1223.txt\"",
            "",
            "test file data",
            "------WebKitFormBoundary1234567812345678--"
        ];
        assert_eq!(&res[..len], raw.join("\r\n").as_bytes());
    }
}