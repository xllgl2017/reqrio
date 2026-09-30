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
    dy_bcrypto: &'static str,
    dy_zap: &'static str,
    bcrypto: &'static str,
    zap: &'static str,
}

const FILE_HASHES: [FileHash; 4] = [
    FileHash {
        target: "x86_64-windows-msvc",
        dy_bcrypto: "9aa0940e8c5e72ea900e217bfff25806f33b741ab234b7739c0c1d411d2b1dc3",
        dy_zap: "c74dc8e695d760d48b122fbd5fccaac3e6ef89aef09988f74ae57d2761f02c00",
        bcrypto: "5deaf5e2cbe068de75a3c36da36530a299aa67af12aa39719dc7f3da8d3477ac",
        zap: "103a0632ba85850655071e761ef109b2294c958b1237b03d91112b9fcba4db93",
    },
    // FileHash {
    //     target: "windows-msvc-i686",
    //     bcrypto: "E82C70804F2989574BAD7E451BC622D1BFF9F16985F09FF86EECB48B7608D2A7",
    //     zap: "E82C70804F2989574BAD7E451BC622D1BFF9F16985F09FF86EECB48B7608D2A7",
    // },
    FileHash {
        target: "x86_64-windows-gnu",
        dy_bcrypto: "0f85a17dd07b2fceb9eb61df24777eacfefa51546155168f687b19a47c4f844e",
        dy_zap: "dcf84ccbde20ee33f0152838b1252c1576876986821c5df20673485def791dbe",
        bcrypto: "0f85a17dd07b2fceb9eb61df24777eacfefa51546155168f687b19a47c4f844e",
        zap: "bd5642fbac1f1594b07b6e55f87999ee3e580891339222e9d30192411b083f39",
    },
    FileHash {
        target: "x86_64-linux-gnu",
        dy_bcrypto: "155b693eadcbd228a0bb198e64966d3a76c3b9e48b583d171fe582764bb462de",
        dy_zap: "2307308ebef386c9fbf1751d16856d089768224c86a8904b77746b44f21811dc",
        bcrypto: "366f551c3c0b64256b1b99d58c162da7400cc61736c5e8852d83397f5df62d2c",
        zap: "3f333918a4eed17454b78192f182968e2ac30b8720b90878242865ddfa451e72",
    },
    // FileHash {
    //     target: "macos-x86_64",
    //     bcrypto: "E82C70804F2989574BAD7E451BC622D1BFF9F16985F09FF86EECB48B7608D2A7",
    //     zap: "E82C70804F2989574BAD7E451BC622D1BFF9F16985F09FF86EECB48B7608D2A7",
    // },
    FileHash {
        target: "aarch64-macos-",
        dy_bcrypto: "170e7aa5db34325efb69ba96f2e56497d137090958d83d3b02e120f392ae74fe",
        dy_zap: "b56abde2717a43b4958c16bb588d3ff4e4d6827b8c161fdbcb35f691d365a8bd",
        bcrypto: "041ac6b3b6809db2f8d73f7bda3540030a760f397d3eb7ff429effe4e056b4d5",
        zap: "7f314d6ed706d432d872b50389eb126276c387e547a5937a31927470176b998a",
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
                fs::copy(&path, dep_path)?;
                fs::copy(&path, t_path)?;
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
        if dylib && (filename == "bcrypto.lib" || filename == "zap.lib") { return Ok(true); }
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
        println!("{:?} {:?} {:?}", hash.dy_bcrypto, hash.bcrypto, file_hash);
        match filename.split('.').next().unwrap_or("") {
            "bcrypto"|"libbcrypto" => Ok(if dylib { hash.dy_bcrypto } else { hash.bcrypto } == file_hash.trim()),
            "zap"|"libzap" => Ok(if dylib { hash.dy_zap } else { hash.zap } == file_hash.trim()),
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