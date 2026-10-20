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
        bcz: "8dc7b2a81e1a81144f740ae08c9b1153c97699057c721f3f7b8e3982c5404fff",
        dy_bcz: "303fe7e118951043ce01aa8410b399bd2a59368b7973030340565ac6a047c694",
    },
    FileHash {
        target: "x86_64-windows-gnu",
        bcz: "9026c9beb73c0eccfe455fc727d7a9a6cae0a2c7f4262b48a1d00811b2400cfe",
        dy_bcz: "9f02398f52207485209a4687d952fa6773a7624f0ec5f1e6c8f4743f6c34bb32",
    },
    FileHash {
        target: "x86_64-linux-gnu",
        bcz: "78cb5d925c7e73e58bf8edb7363ed14496a716171ca3a5ffcb4b8dbf17b43302",
        dy_bcz: "94a5da7457af05b472a5a1ba750b4b645bd43bb0811919eec074f5d0c723c49f",
    },
    FileHash {
        target: "aarch64-macos-",
        bcz: "ac57496acdfbf9af0f927ea6a5538f5c1f1a220ab07d6f374974ae65a223bb6e",
        dy_bcz: "3d77a67344239bd0cdb72b6cb039805ff02f625afe970b999fa7ad172c75fe20",
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