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
use std::ffi::c_int;

pub trait BoringResExt {
    fn ok<E>(self, error: E) -> Result<(), E>;
}

impl BoringResExt for c_int {
    fn ok<E>(self, error: E) -> Result<(), E> {
        if self != 1 { return Err(error); }
        Ok(())
    }
}