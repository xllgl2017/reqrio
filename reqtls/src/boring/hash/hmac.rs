use super::super::bindings::*;
use super::HashType;
use crate::boring::{BoringResExt, HashError};
use crate::error::RlsResult;
use crate::ffi::CPointer;
use std::ffi::CString;
use std::ptr::null_mut;


pub struct Hmac {
    ctx: CPointer<HMAC_CTX>,
}

impl Hmac {
    pub fn new(key: impl AsRef<[u8]>, sha: HashType) -> Result<Hmac, HashError> {
        let ctx = CPointer::new_checked(unsafe { HMAC_CTX_new() }, HashError::HmacCtxNull)?;
        unsafe {
            HMAC_Init_ex(
                ctx.as_mut_ptr(),
                key.as_ref().as_ptr() as *const _,
                key.as_ref().len(),
                sha.evp_md(),
                null_mut(),
            )
        }.ok(HashError::HmacInitError)?;
        Ok(Hmac {
            ctx,
        })
    }

    pub fn update(&mut self, data: impl AsRef<[u8]>) -> Result<(), HashError> {
        unsafe { HMAC_Update(self.ctx.as_mut_ptr(), data.as_ref().as_ptr(), data.as_ref().len()) }.ok(HashError::HmacUpdateError)?;
        Ok(())
    }

    pub fn finalize(self) -> Result<Vec<u8>, HashError> {
        let mut res = vec![0; 64];
        let mut len = 0;
        unsafe { HMAC_Final(self.ctx.as_mut_ptr(), res.as_mut_ptr(), &mut len) }.ok(HashError::HmacFinalizeError)?;
        res.truncate(len as usize);
        Ok(res)
    }

    pub fn finalize_extract(&mut self, out: &mut [u8]) -> Result<(), HashError> {
        let mut len = out.len() as u32;
        unsafe { HMAC_Final(self.ctx.as_mut_ptr(), out.as_mut_ptr(), &mut len) }.ok(HashError::HmacFinalizeError)?;
        assert_eq!(len, out.len() as u32);
        Ok(())
    }
}

fn hmac(key: &[u8], data: &[u8], out: &mut [u8], sha: HashType) -> Result<usize, HashError> {
    let mut len = 0;
    let ret = unsafe {
        HMAC(
            sha.evp_md(),
            key.as_ptr() as *const _,
            key.len(),
            data.as_ptr() as *const _,
            data.len(),
            out.as_mut_ptr(),
            &mut len,
        )
    };
    if ret.is_null() { return Err(HashError::HmacHashError); }
    Ok(len as usize)
}

pub fn hmac_sha1(key: impl AsRef<[u8]>, data: impl AsRef<[u8]>) -> Result<[u8; 20], HashError> {
    let mut out = [0; 20];
    hmac(key.as_ref(), data.as_ref(), &mut out[..], HashType::Sha1)?;
    Ok(out)
}

pub fn hmac_sha256(key: impl AsRef<[u8]>, data: impl AsRef<[u8]>) -> Result<[u8; 32], HashError> {
    let mut out = [0; 32];
    hmac(key.as_ref(), data.as_ref(), &mut out[..], HashType::Sha1)?;
    Ok(out)
}

pub fn hmac_sha384(key: impl AsRef<[u8]>, data: impl AsRef<[u8]>) -> Result<[u8; 48], HashError> {
    let mut out = [0; 48];
    hmac(key.as_ref(), data.as_ref(), &mut out[..], HashType::Sha1)?;
    Ok(out)
}

pub fn hmac_sha512(key: impl AsRef<[u8]>, data: impl AsRef<[u8]>) -> Result<[u8; 64], HashError> {
    let mut out = [0; 64];
    hmac(key.as_ref(), data.as_ref(), &mut out[..], HashType::Sha1)?;
    Ok(out)
}

pub fn pkcs5_pbkdf_hmac(psd: impl AsRef<str>, salt: impl AsRef<[u8]>, rounds: u32, hash: HashType) -> RlsResult<Vec<u8>> {
    let c_psd = CString::new(psd.as_ref())?;
    let mut out = vec![0u8; hash.hash_size()];
    unsafe {
        PKCS5_PBKDF2_HMAC(
            c_psd.as_ptr(),
            psd.as_ref().len(),
            salt.as_ref().as_ptr(),
            salt.as_ref().len(),
            rounds,
            hash.evp_md(),
            hash.hash_size(),
            out.as_mut_ptr(),
        )
    }.ok(HashError::HmacFinalizeError)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use crate::boring::hash::{HashType, Hmac};

    #[test]
    fn test_hmac() {
        let mut hmac = Hmac::new("test", HashType::Sha256).unwrap();
        hmac.update("sdf").unwrap();
        assert_eq!(hmac.finalize().unwrap(), [46, 10, 163, 88, 247, 49, 205, 241, 36, 183, 31, 251, 41, 30, 250, 112, 102, 212, 10, 5, 160, 216, 253, 169, 25, 107, 69, 152, 44, 211, 155, 23]);


        let mut hmac = Hmac::new("1233", HashType::Sm3).unwrap();
        hmac.update("123").unwrap();
        hmac.update("43545").unwrap();
        hmac.update("4545").unwrap();
        assert_eq!(hmac.finalize().unwrap(), [97, 138, 163, 85, 66, 32, 118, 183, 129, 105, 183, 218, 198, 110, 29, 240, 21, 160, 122, 97, 114, 176, 125, 248, 94, 158, 192, 217, 156, 230, 141, 27]);
    }
}