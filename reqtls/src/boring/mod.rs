pub(crate) mod bindings;
pub mod hash;
mod signature;

pub(crate) mod rsa;

mod evp;
mod padding;
pub mod base64;

pub use evp::{cipher, Cipher, CipherType};
pub use evp::{AeadCtx, AeadDir, Iv};
pub use hash::*;
pub use padding::Padding;
pub use rsa::{certificate, RsaCipher, RsaKey, RsaPadding};
pub use signature::{AlgoSigner, SignatureAlgorithm};
use std::ffi::{CStr, c_int};
use std::os::raw::c_char;

pub trait BoringResExt {
    fn ok<E>(self, error: E) -> Result<(), E>;
}

impl BoringResExt for c_int {
    fn ok<E>(self, error: E) -> Result<(), E> {
        if self != 1 { return Err(error); }
        Ok(())
    }
}

unsafe extern "C" {
    fn BCZ_get_err() -> *const c_char;
}

pub trait BczExt {
    fn checked(self) -> Result<(), String>;
}

impl BczExt for c_int {
    fn checked(self) -> Result<(), String> {
        if self == 1 { return Ok(()); };
        unsafe {
            match CStr::from_ptr(BCZ_get_err()).to_str() {
                Ok(err) => Err(err.to_string()),
                Err(_) => Err("checked failed, get error fail".into())
            }
        }
    }
}