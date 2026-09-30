mod frame;
mod stream;

use std::path::{Path, PathBuf};
use std::{env, fs};
use std::error::Error;
use std::net::TcpStream;
use crate::frame::{Frame, LibType};
use crate::stream::TkStream;

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn from_slice(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn check(&self, size: usize) -> Result<(), Box<dyn Error>> {
        if self.pos + size > self.buf.len() { return Err("index out of bounds".into()); }
        Ok(())
    }

    pub fn read_u8(&mut self) -> Result<u8, Box<dyn Error>> {
        self.check(1)?;
        let res = self.buf[self.pos];
        self.pos += 1;
        Ok(res)
    }

    pub fn read_u16(&mut self) -> Result<u16, Box<dyn Error>> {
        self.check(2)?;
        let res = u16::from_be_bytes(self.buf[self.pos..self.pos + 2].try_into()?);
        self.pos += 2;
        Ok(res)
    }

    pub fn read_u32(&mut self) -> Result<u32, Box<dyn Error>> {
        self.check(4)?;
        let res = u32::from_be_bytes(self.buf[self.pos..self.pos + 4].try_into()?);
        self.pos += 4;
        Ok(res)
    }

    pub fn read_slice(&mut self, len: usize) -> Result<&'a [u8], Box<dyn Error>> {
        self.check(len)?;
        let slice = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }

    pub fn read_str(&mut self, len: usize) -> Result<&'a str, Box<dyn Error>> {
        let slice = self.read_slice(len)?;
        let res = str::from_utf8(slice)?;
        Ok(res)
    }

    pub fn read_reader(&mut self, len: usize) -> Result<Reader<'a>, Box<dyn Error>> {
        self.check(len)?;
        let slice = self.read_slice(len)?;
        Ok(Reader::from_slice(slice))
    }
}

fn fetch_lib(frame: Frame, tdr: &Path, target: String) -> Result<(), Box<dyn Error>> {
    let stream = TcpStream::connect("ms.xllgl.top:8080")?;
    let mut stream = TkStream::new(stream);
    stream.fetch_lib(frame, tdr, target)
}


fn check_lib(tdr: &Path, typ: &LibType, ver: &str) -> Result<bool, Box<dyn Error>> {
    let checksum = tdr.join("reqrio").join("checksum");
    let checksum = fs::read_to_string(checksum).unwrap_or("".to_string());
    if checksum != format!("{:?} {}", typ, ver) { return Ok(false); };
    let mut has_crypto = false;
    let mut has_zap = false;
    for dir in fs::read_dir(tdr.join("reqrio"))? {
        let path = dir?.path();
        let filename = path.file_name().map(|x| x.display().to_string()).unwrap_or("".to_string());
        if filename.ends_with("bcrypto.dll") || filename.ends_with("bcrypto.so") ||
            filename.ends_with("bcrypto.dylib") ||
            filename.ends_with("bcrypto.lib") || filename.ends_with("bcrypto.a") {
            has_crypto = true;
            let dep = tdr.join("deps").join(&filename);
            if !dep.exists() { fs::copy(&path, &dep)?; }
            println!("cargo:rerun-if-changed={}", dep.display());
            let td = tdr.join(&filename);
            if !td.exists() { fs::copy(&path, &td)?; }
            println!("cargo:rerun-if-changed={}", td.display());
        }
        if filename.ends_with("zap.dll") || filename.ends_with("zap.so") ||
            filename.ends_with("zap.dylib") ||
            filename.ends_with("zap.lib") || filename.ends_with("zap.a") {
            has_zap = true;
            let dep = tdr.join("deps").join(&filename);
            if !dep.exists() { fs::copy(&path, &dep)?; }
            println!("cargo:rerun-if-changed={}", dep.display());
            let td = tdr.join(&filename);
            if !td.exists() { fs::copy(&path, &td)?; }
            println!("cargo:rerun-if-changed={}", td.display());
        }
    }
    Ok(has_crypto && has_zap)
}


fn main() {
    if env::var("DOCS_RS").is_ok() { return; }
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let env = env::var("CARGO_CFG_TARGET_ENV").unwrap();
    let version = env::var("CARGO_PKG_VERSION").unwrap();
    let token = env::var("REQRIO_TOKEN").unwrap_or("".to_string());
    let typ = if cfg!(feature = "static_link") { LibType::Static } else { LibType::Dynamic };
    let target_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let target_dir = target_dir.ancestors().nth(3).unwrap();
    println!("cargo:rerun-if-changed={}", target_dir.join("reqrio").display());
    println!("cargo:rustc-link-search={}", target_dir.join("reqrio").display());
    println!("cargo:rustc-link-lib={}=bcrypto", typ.link());
    println!("cargo:rustc-link-lib={}=zap", typ.link());
    if env == "gnu" {
        println!("cargo:rustc-link-lib=dylib=stdc++");
    }
    if env.is_empty() {
        println!("cargo:rustc-link-lib=c++");
    }
    if check_lib(target_dir, &typ, &version).unwrap_or(false) {
        return;
    }
    fs::create_dir_all(target_dir.join("reqrio")).unwrap();
    fetch_lib(Frame::GetLib {
        typ,
        os: &os,
        env: &env,
        arch: &arch,
        version: &version,
        token: &token,
    }, target_dir, format!("{}-{}-{}", arch, os, env)).unwrap();
    let checksum = format!("{:?} {}", typ, version);
    fs::write(target_dir.join("reqrio").join("checksum"), checksum).unwrap();
}
