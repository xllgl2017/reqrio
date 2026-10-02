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
        dy_bcrypto: "1a34cf4c051e9a556fbcbf68e5bc5cac8c804434cd030541045b3946eae69710",
        dy_zap: "c74dc8e695d760d48b122fbd5fccaac3e6ef89aef09988f74ae57d2761f02c00",
        bcrypto: "63ee9d7a634c1dbff9a0046bf580858c86207e2d81a6dc533a9ff24c00cdcbfa",
        zap: "103a0632ba85850655071e761ef109b2294c958b1237b03d91112b9fcba4db93",
    },
    // FileHash {
    //     target: "windows-msvc-i686",
    //     bcrypto: "E82C70804F2989574BAD7E451BC622D1BFF9F16985F09FF86EECB48B7608D2A7",
    //     zap: "E82C70804F2989574BAD7E451BC622D1BFF9F16985F09FF86EECB48B7608D2A7",
    // },
    FileHash {
        target: "x86_64-windows-gnu",
        dy_bcrypto: "b1f08b484659cba590583ec827b5e652409cbde115ebb46916d78f5b7144ef70",
        dy_zap: "dcf84ccbde20ee33f0152838b1252c1576876986821c5df20673485def791dbe",
        bcrypto: "0bf6edaa0654999d6c0ee28afe495363d766839c2d252090deecfd191979fb39",
        zap: "bd5642fbac1f1594b07b6e55f87999ee3e580891339222e9d30192411b083f39",
    },
    FileHash {
        target: "x86_64-linux-gnu",
        dy_bcrypto: "a8cd851efb3db70230999dd090150a8def68164f047cd462091cd3962408ec64",
        dy_zap: "2307308ebef386c9fbf1751d16856d089768224c86a8904b77746b44f21811dc",
        bcrypto: "af5b0a8fb52b9b29cfad4eb9cf7110ff89bcad645bd5d43a0ef0ec4487db07b1",
        zap: "3f333918a4eed17454b78192f182968e2ac30b8720b90878242865ddfa451e72",
    },
    // FileHash {
    //     target: "macos-x86_64",
    //     bcrypto: "E82C70804F2989574BAD7E451BC622D1BFF9F16985F09FF86EECB48B7608D2A7",
    //     zap: "E82C70804F2989574BAD7E451BC622D1BFF9F16985F09FF86EECB48B7608D2A7",
    // },
    FileHash {
        target: "aarch64-macos-",
        dy_bcrypto: "b0fc28b96ea6861e366d432b24bc8e0ff4f967cb32195a646e68202eaaf6493b",
        dy_zap: "b56abde2717a43b4958c16bb588d3ff4e4d6827b8c161fdbcb35f691d365a8bd",
        bcrypto: "7fdaa7dfc987fa94a72005817e48933264bb4b7f069a5b684d00e39216e57d3f",
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
            "bcrypto" | "libbcrypto" => Ok(if dylib { hash.dy_bcrypto } else { hash.bcrypto } == file_hash.trim()),
            "zap" | "libzap" => Ok(if dylib { hash.dy_zap } else { hash.zap } == file_hash.trim()),
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