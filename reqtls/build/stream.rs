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
        bcz: "2ff0b517446dd9898bbcf9f939896b0da35dc6ccad18fcb68c284174fb6e608e",
        dy_bcz: "c2e3abae15925dcc85cd4f5653e57b69c2350f5ecf5ac6fadc01af332224d33b",
    },
    FileHash {
        target: "x86_64-windows-gnu",
        bcz: "c8ca6649f296fb628050a650b7e75409b598f63ee3b6a38788abfb5ed5c1cb0d",
        dy_bcz: "401481ee9fd4db0771b8c5274a0381409baf99a65ff3f311b64adf8478fe65ac",
    },
    FileHash {
        target: "x86_64-linux-gnu",
        bcz: "5fc715e406044b936b295fa374a9e3068f9d0906e68659a1cc8707e9c401a325",
        dy_bcz: "74b78830f343bad303dbf656eddd29dec4470f429225ffb7b926e48654675512",
    },
    FileHash {
        target: "aarch64-macos-",
        bcz: "707b0fb0233eeba5e3ec105d9ce797fba9d4ffe0f50af4d823b1738f1622b778",
        dy_bcz: "9dd4146de7380d96aa75506cbf3db79386ec5c6813738635b3c7d73cc4b492a1",
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


    fn handle_stream(&mut self, tdr: &Path, target: &str, ver: i32) -> Result<(), Box<dyn Error>> {
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
                println!("{}", tdr.display());
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
                if !self.file_cmp(path.as_path(), target, &filename).unwrap() { return Err("File Hash not correct".into()); }
                if !cfg!(feature = "static_link") {
                    if ver < 100 { fs::copy(&path, dep_path).unwrap(); }
                    fs::copy(&path, t_path).unwrap();
                    fs::copy(&path, exa_path).unwrap();
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

    pub fn fetch_lib(&mut self, frame: Frame, tdr: &Path, target: String, ver: i32) -> Result<(), Box<dyn Error>> {
        let mut buf = Vec::with_capacity(frame.len());
        frame.encode(&mut buf);
        self.stream.write_all(&buf)?;
        loop {
            if let Err(e) = self.handle_stream(tdr, &target, ver) {
                if e.to_string().contains("peer close") { break; }
                println!("{}", e);
                return Err(e);
            }
        }
        Ok(())
    }
}