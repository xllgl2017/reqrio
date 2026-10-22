use std::ptr::null_mut;
use std::{mem, slice};
use crate::error::RlsResult;
use crate::hash::{HashType, Hasher, Hmac};
use crate::RlsError;

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn Hasher_new(ht: HashType) -> *mut Hasher {
    Hasher::new(ht).map(|x| Box::into_raw(Box::new(x))).unwrap_or(null_mut())
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn Hasher_update(hasher: *mut Hasher, data: *const u8, len: usize) -> i32 {
    || -> RlsResult<i32>{
        let hasher = unsafe { hasher.as_mut() }.ok_or(RlsError::NullPtr)?;
        let data = unsafe { slice::from_raw_parts(data, len) };
        hasher.update(data)?;
        Ok(0)
    }().unwrap_or(-1)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn Hasher_finalize(hasher: *mut Hasher, out: *mut *mut u8, out_len: &mut usize) -> i32 {
    || -> RlsResult<i32>{
        let hasher = unsafe { Box::from_raw(hasher) };
        let mut hash_bs = hasher.finalize()?;
        unsafe {
            *out = hash_bs.as_mut_ptr();
            *out_len = hash_bs.len();
        }
        mem::forget(hash_bs);
        Ok(0)
    }().unwrap_or(-1)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn Hasher_drop(hasher: *mut Hasher) {
    if hasher.is_null() { return; }
    let hasher = unsafe { Box::from_raw(hasher) };
    drop(hasher);
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn Hmac_new(key: *const u8, len: usize, ht: HashType) -> *mut Hmac {
    let key = unsafe { slice::from_raw_parts(key, len) };
    Hmac::new(key, ht).map(|h| Box::into_raw(Box::new(h))).unwrap_or(null_mut())
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn Hmac_update(hasher: *mut Hmac, data: *const u8, len: usize) -> i32 {
    || -> RlsResult<i32>{
        let hmac = unsafe { hasher.as_mut() }.ok_or(RlsError::NullPtr)?;
        let data = unsafe { slice::from_raw_parts(data, len) };
        hmac.update(data)?;
        Ok(0)
    }().unwrap_or(-1)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn Hmac_finalize(hasher: *mut Hmac, out: *mut *mut u8, out_len: &mut usize) -> i32 {
    || -> RlsResult<i32>{
        let mut hmac = unsafe { Box::from_raw(hasher) };
        let mut hash_bs = hmac.finalize()?.to_vec();
        unsafe {
            *out = hash_bs.as_mut_ptr();
            *out_len = hash_bs.len();
        }
        mem::forget(hash_bs);
        Ok(0)
    }().unwrap_or(-1)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn Hmac_free(hmac: *mut Hmac) {
    if hmac.is_null() { return; }
    let hasher = unsafe { Box::from_raw(hmac) };
    drop(hasher);
}
