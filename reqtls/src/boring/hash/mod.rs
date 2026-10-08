pub mod hmac;
mod hasher;
mod error;

use crate::boring::bindings::*;
use crate::error::RlsResult;
pub use error::HashError;
pub use hasher::Hasher;
pub use hmac::Hmac;
use std::ptr::null_mut;

#[repr(C)]
#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(debug_assertions, derive(Debug))]
pub enum HashType {
    MD5 = 0,
    Sha1 = 1,
    Sha224 = 2,
    Sha256 = 3,
    Sha384 = 4,
    Sha512 = 5,
    Sm3 = 6,
}

impl HashType {
    const SHA256_SECRET: [u8; 32] = [227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174, 65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85];
    const SHA384_SECRET: [u8; 48] = [56, 176, 96, 167, 81, 172, 150, 56, 76, 217, 50, 126, 177, 177, 227, 106, 33, 253, 183, 17, 20, 190, 7, 67, 76, 12, 199, 191, 99, 246, 225, 218, 39, 78, 222, 191, 231, 111, 101, 251, 213, 26, 210, 241, 72, 152, 185, 91];
    pub(crate) fn evp_md(&self) -> *const EVP_MD {
        match self {
            HashType::MD5 => unsafe { EVP_md5() },
            HashType::Sha224 => unsafe { EVP_sha224() }
            HashType::Sha1 => unsafe { EVP_sha1() },
            HashType::Sha256 => unsafe { EVP_sha256() },
            HashType::Sha384 => unsafe { EVP_sha384() },
            HashType::Sha512 => unsafe { EVP_sha512() },
            HashType::Sm3 => unsafe { EVP_sm3() }
        }
    }

    pub(crate) const fn hash_size(&self) -> usize {
        match self {
            HashType::MD5 => 16,
            HashType::Sha1 => 20,
            HashType::Sha224 => 28,
            HashType::Sha256 => 32,
            HashType::Sha384 => 48,
            HashType::Sha512 => 64,
            HashType::Sm3 => 32
        }
    }

    pub(crate) const fn tls13_secret(&self) -> Result<&[u8], HashError> {
        match self {
            HashType::Sha256 => Ok(&HashType::SHA256_SECRET),
            HashType::Sha384 => Ok(&HashType::SHA384_SECRET),
            _ => Err(HashError::HasherNoSecret)
        }
    }
}

fn digest(data: &[u8], out: *mut u8, sha: HashType) -> Result<usize, HashError> {
    let mut len = 0;
    let ret = unsafe {
        EVP_Digest(
            data.as_ptr() as *const _,
            data.len(),
            out as *mut _,
            &mut len,
            sha.evp_md(),
            null_mut(),
        )
    };
    if ret != 1 { return Err(HashError::DigestUpdateError); }
    Ok(len as usize)
}

pub fn md5(context: impl AsRef<[u8]>) -> RlsResult<[u8; 16]> {
    let mut out = [0u8; 16];
    digest(context.as_ref(), out.as_mut_ptr(), HashType::MD5)?;
    Ok(out)
}

pub fn md5_hex(context: impl AsRef<[u8]>) -> RlsResult<String> {
    Ok(hex::encode(md5(context)?))
}

pub fn sha1(context: impl AsRef<[u8]>) -> RlsResult<[u8; 20]> {
    let mut out = [0u8; 20];
    digest(context.as_ref(), out.as_mut_ptr(), HashType::Sha1)?;
    Ok(out)
}

pub fn sha1_hex(context: impl AsRef<[u8]>) -> RlsResult<String> {
    Ok(hex::encode(sha1(context)?))
}

pub fn sha224(context: impl AsRef<[u8]>) -> RlsResult<[u8; 28]> {
    let mut out = [0u8; 28];
    digest(context.as_ref(), out.as_mut_ptr(), HashType::Sha224)?;
    Ok(out)
}

pub fn sha224_hex(context: impl AsRef<[u8]>) -> RlsResult<String> {
    Ok(hex::encode(sha224(context)?))
}

pub fn sha256(context: impl AsRef<[u8]>) -> RlsResult<[u8; 32]> {
    let mut out = [0u8; 32];
    digest(context.as_ref(), out.as_mut_ptr(), HashType::Sha256)?;
    Ok(out)
}

pub fn sha256_hex(context: impl AsRef<[u8]>) -> RlsResult<String> {
    Ok(hex::encode(sha256(context)?))
}

pub fn sha384(context: impl AsRef<[u8]>) -> RlsResult<[u8; 48]> {
    let mut out = [0u8; 48];
    digest(context.as_ref(), out.as_mut_ptr(), HashType::Sha384)?;
    Ok(out)
}

pub fn sha384_hex(context: impl AsRef<[u8]>) -> RlsResult<String> {
    Ok(hex::encode(sha384(context)?))
}

pub fn sha512(context: impl AsRef<[u8]>) -> RlsResult<[u8; 64]> {
    let mut out = [0u8; 64];
    digest(context.as_ref(), out.as_mut_ptr(), HashType::Sha512)?;
    Ok(out)
}

pub fn sha512_hex(context: impl AsRef<[u8]>) -> RlsResult<String> {
    Ok(hex::encode(sha512(context)?))
}


pub fn sm3(context: impl AsRef<[u8]>) -> RlsResult<[u8; 32]> {
    let mut out = [0u8; 32];
    digest(context.as_ref(), out.as_mut_ptr(), HashType::Sm3)?;
    Ok(out)
}

pub fn sm3_hex(context: impl AsRef<[u8]>) -> RlsResult<String> {
    Ok(hex::encode(sm3(context)?))
}


#[cfg(test)]
mod hash_tests {
    use crate::{HashType, Hasher};

    #[test]
    fn hasher_test() {
        let sm3 = [98, 38, 193, 189, 121, 90, 222, 162, 61, 189, 218, 164, 65, 12, 83, 86, 123, 93, 171, 159, 114, 237, 116, 186, 164, 239, 210, 172, 218, 122, 42, 183];
        let mut hasher = Hasher::new(HashType::Sm3).unwrap();
        hasher.update("4546").unwrap();
        hasher.update("12345").unwrap();
        assert_eq!(hasher.finalize().unwrap(), sm3);
        assert_eq!(super::sm3("454612345").unwrap(), sm3);
    }
}