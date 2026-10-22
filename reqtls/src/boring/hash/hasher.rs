use super::super::bindings::*;
use super::HashType;
use super::error::HashError;
use crate::boring::BoringResExt;
use crate::ffi::c_struct_free;
use std::ffi::c_void;
use std::os::raw::c_int;
use std::ptr::null_mut;

unsafe extern "C" {
    fn Hasher_init(hasher: *mut Hasher) -> c_int;
    fn Hasher_free(hasher: *mut Hasher);
    fn Hasher_current_hash(hasher: *mut Hasher) -> *const u8;
}

c_struct_free!(Hasher, Hasher_free);
#[repr(C)]
pub struct Hasher {
    ctx: *mut c_void,
    hash_type: HashType,
    buf: [u8; 64],
    len: usize,
    updated: bool,
}

impl Hasher {
    pub fn uninit() -> Hasher {
        Hasher {
            ctx: null_mut(),
            hash_type: HashType::Sha256,
            buf: [0; 64],
            len: 0,
            updated: false,
        }
    }
    pub fn new(sha: HashType) -> Result<Hasher, HashError> {
        let mut hasher = Hasher::uninit();
        hasher.init(sha)?;
        Ok(hasher)
    }

    pub fn init(&mut self, sha: HashType) -> Result<(), HashError> {
        self.hash_type = sha;
        unsafe { Hasher_init(self) }.ok(HashError::InitHasherError)
    }


    pub fn update(&mut self, buf: impl AsRef<[u8]>) -> Result<(), HashError> {
        debug_assert!(!self.ctx.is_null());
        self.updated = true;
        unsafe {
            EVP_DigestUpdate(self.ctx, buf.as_ref().as_ptr() as *const _, buf.as_ref().len())
        }.ok(HashError::DigestUpdateError)
    }

    pub fn current_hash(&mut self) -> Result<&[u8], HashError> {
        debug_assert!(!self.ctx.is_null());
        let ptr = unsafe { Hasher_current_hash(self) };
        if ptr.is_null() { return Err(HashError::DigestFinalError); }
        Ok(&self.buf[..self.len])
    }


    pub fn finalize(mut self) -> Result<Vec<u8>, HashError> {
        debug_assert!(!self.ctx.is_null());
        let mut len = 0;
        unsafe { EVP_DigestFinal_ex(self.ctx, self.buf.as_mut_ptr(), &mut len) }.ok(HashError::DigestFinalError)?;
        Ok(self.buf[..len as usize].to_vec())
    }

    pub fn hash_type(&self) -> &HashType {
        &self.hash_type
    }

    pub fn initialed(&self) -> bool {
        !self.ctx.is_null()
    }
}

#[cfg(test)]
mod tests {
    use crate::boring::HashType;
    use crate::boring::hash::hasher::Hasher;

    #[test]
    fn test_hasher() {
        let mut hasher = Hasher::new(HashType::Sha256).unwrap();
        hasher.update(b"hello world").unwrap();
        assert_eq!(hasher.finalize().unwrap(), [185, 77, 39, 185, 147, 77, 62, 8, 165, 46, 82, 215, 218, 125, 171, 250, 196, 132, 239, 227, 122, 83, 128, 238, 144, 136, 247, 172, 226, 239, 205, 233]);
        assert_eq!(super::super::sha256("hello world").unwrap(), [185, 77, 39, 185, 147, 77, 62, 8, 165, 46, 82, 215, 218, 125, 171, 250, 196, 132, 239, 227, 122, 83, 128, 238, 144, 136, 247, 172, 226, 239, 205, 233]);


        let mut hash_md5 = Hasher::new(HashType::MD5).unwrap();
        hash_md5.update(b"hello world").unwrap();
        assert_eq!(hash_md5.finalize().unwrap(), [94, 182, 59, 187, 224, 30, 238, 208, 147, 203, 34, 187, 143, 90, 205, 195]);
        assert_eq!(super::super::md5("hello world").unwrap(), [94, 182, 59, 187, 224, 30, 238, 208, 147, 203, 34, 187, 143, 90, 205, 195]);
    }
}