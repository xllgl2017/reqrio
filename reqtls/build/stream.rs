use crate::frame::Frame;
use crate::Reader;
use std::cmp::min;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::ops::Range;
use std::path::Path;
use std::process::Command;

struct FileHash {
    target: &'static str,
    dy_bcz: &'static str,
    bcz: &'static str,
}

const FILE_HASHES: [FileHash; 4] = [
    FileHash {
        target: "x86_64-windows-msvc",
        bcz: "8089ea0f5097338d13337bec68b0e53113fbc8fca8a2e6d8f3be590d64e763b2",
        dy_bcz: "ac7e33a0b29d110930a42ae06a740d751bbd08ad4e8836be60fab862d6e09a7b",
    },
    FileHash {
        target: "x86_64-windows-gnu",
        bcz: "f9539fce44e93181fdd32afa8668c92b085623a60e101241c14e3044598bbf7a",
        dy_bcz: "9cf395794f26d89d5a0473e23288c00c99eb30af6187196a2734b309a8bf4d0b",
    },
    FileHash {
        target: "x86_64-linux-gnu",
        bcz: "226542db9364fed0dcb05b54369665405f4a2f7e2d8fea3c2408873cf617bd10",
        dy_bcz: "3fe2ad7dd36743c24527e64a6f4beb36f05d3eedae70d641a1a787f60214bb63",
    },
    FileHash {
        target: "aarch64-macos-",
        bcz: "dc933e64d4fb5ba037c446acdf7aad87dbbb4e30c165952e6155ff14c47067ed",
        dy_bcz: "270598732be493dca6f008ccbc1da584d72af66b5123c11d664061c2ba94025e",
    }
];

pub struct TkStream {
    stream: TcpStream,
    buffer: [u8; 4096],
    offset: Range<usize>,
}


impl TkStream {
    pub(crate) fn new(stream: TcpStream) -> TkStream {
        TkStream {
            stream,
            buffer: [0; 4096],
            offset: 0..0,
        }
    }

    fn read_size(&mut self, want: usize) -> Result<(), Box<dyn Error>> {
        let unfilled_size = self.buffer.len() - self.offset.end;
        if unfilled_size < want && self.offset.start != 0 {
            let filled = self.buffer[self.offset.clone()].to_vec();
            self.buffer[0..self.offset.len()].copy_from_slice(filled.as_slice());
            self.offset = 0..self.offset.len();
        }
        while self.offset.len() < want {
            let unfilled = &mut self.buffer[self.offset.end..];
            let len = self.stream.read(unfilled)?;
            if len == 0 && !unfilled.is_empty() { return Err("peer close".into()); }
            self.offset.end += len;
        }
        Ok(())
    }

    fn read_stream(&mut self) -> Result<usize, Box<dyn Error>> {
        if self.offset.len() < 4 { self.read_size(4)?; }
        let filled = &self.buffer[self.offset.clone()];
        let len = u32::from_be_bytes(filled[0..4].try_into()?) as usize + 4;
        self.read_size(len)?;
        Ok(len)
    }


    fn handle_stream(&mut self, tdr: &Path, target: &str) -> Result<(), Box<dyn Error>> {
        let len = self.read_stream()?;
        let off = self.offset.start..self.offset.start + len;
        let mut reader = Reader::from_slice(&self.buffer[off]);
        let frame_len = reader.read_u32()? as usize;
        let frame = Frame::from_reader(reader.read_reader(frame_len)?)?;
        match frame {
            Frame::Error { code, message } => return Err(format!("error: code={}; msg={}", code, message).into()),
            Frame::FileStream { filename, filesize } => {
                self.offset.start += reader.pos;
                let filesize = filesize as usize;
                let path = tdr.join("reqrio").join(filename);
                let dep_path = tdr.join("deps").join(filename);
                let exa_path = tdr.join("examples").join(target);
                let t_path = tdr.join(filename);
                let filename = filename.to_string();
                let mut f = File::create(&path)?;
                let mut read_size = 0;
                if !self.offset.is_empty() {
                    let len = min(filesize, self.offset.len());
                    let off = self.offset.start..self.offset.start + len;
                    let filled = &self.buffer[off];
                    f.write_all(filled)?;
                    read_size += filled.len();
                    self.offset.start += filled.len();
                }
                loop {
                    if read_size >= filesize { break; }
                    let chunk_size = min(filesize - read_size, 4096);
                    let len = self.stream.read(&mut self.buffer[..chunk_size])?;
                    if len == 0 { return Err("invalid eof".into()); }
                    let filled = &self.buffer[..len];
                    f.write_all(filled)?;
                    read_size += filled.len();
                }
                f.flush()?;
                drop(f);
                if !self.file_cmp(path.as_path(), target, &filename)? { return Err("File Hash not correct".into()); }
                if !cfg!(feature = "static_link") {
                    fs::copy(&path, dep_path)?;
                    fs::copy(&path, t_path)?;
                    fs::copy(&path, exa_path)?;
                }
            }
            _ => unreachable!()
        };
        // self.offset.start += len;
        Ok(())
    }

    fn file_cmp(&self, path: &Path, target: &str, filename: &str) -> Result<bool, Box<dyn Error>> {
        let hash = FILE_HASHES.iter().find(|x| x.target == target);
        let Some(hash) = hash else { return Ok(false) };
        let dylib = !cfg!(feature = "static_link");
        if dylib && (filename == "bcz.lib") { return Ok(true); }
        let file_hash = if cfg!(target_os = "windows") {
            let res = Command::new("powershell").args(["-NoProfile", "-Command"])
                .arg(format!("certutil -hashfile {} SHA256 | Select-Object -Index 1", path.display()))
                .output()?;
            if !res.stderr.is_empty() {
                panic!("{}", String::from_utf8_lossy(&res.stderr));
            }
            String::from_utf8(res.stdout)?
        } else if cfg!(target_os = "linux") {
            let res = Command::new("sha256sum").arg(path.display().to_string()).output()?;
            println!("{}", String::from_utf8_lossy(&res.stdout));
            println!("{}", String::from_utf8_lossy(&res.stderr));
            String::from_utf8(res.stdout)?.split(" ").next().unwrap_or("").to_string()
        } else {
            let res = Command::new("shasum").args(["-a", "256"])
                .arg(path.display().to_string()).output()?;
            println!("{}", String::from_utf8_lossy(&res.stdout));
            println!("{}", String::from_utf8_lossy(&res.stderr));
            String::from_utf8(res.stdout)?.split(" ").next().unwrap_or("").to_string()
        };
        println!("{:?} {:?} {:?}", hash.dy_bcz, hash.bcz, file_hash);
        match filename.split('.').next().unwrap_or("") {
            "bcz" | "libbcz" => Ok(if dylib { hash.dy_bcz } else { hash.bcz } == file_hash.trim()),
            _ => Ok(false)
        }
    }

    pub fn fetch_lib(&mut self, frame: Frame, tdr: &Path, target: String) -> Result<(), Box<dyn Error>> {
        let mut buf = Vec::with_capacity(frame.len());
        frame.encode(&mut buf);
        self.stream.write_all(&buf)?;
        loop {
            if let Err(e) = self.handle_stream(tdr, &target) {
                if e.to_string().contains("peer close") { break; }
                return Err(e);
            }
        }
        Ok(())
    }
}