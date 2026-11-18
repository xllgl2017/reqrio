mod block;
mod derived;

use std::os::raw::c_int;
use std::slice;
pub use block::{KeyType, TlsSession};
pub(crate) use derived::DerivedKey;
pub(crate) use block::EchKey;
use crate::boring::BoringResExt;
use crate::error::RlsResult;
use crate::ffi::c_struct_free;
use crate::NamedCurve;

#[repr(C)]
pub struct TrafficSecret {
    client_traffic: [u8; 48],
    server_traffic: [u8; 48],
    size: usize,
}

impl TrafficSecret {
    pub fn client_traffic(&self) -> &[u8] {
        &self.client_traffic[..self.size]
    }

    pub fn client_traffic_mut(&mut self) -> &mut [u8] {
        &mut self.client_traffic[..self.size]
    }

    pub fn server_traffic(&self) -> &[u8] {
        &self.server_traffic[..self.size]
    }

    pub fn server_traffic_mut(&mut self) -> &mut [u8] {
        &mut self.server_traffic[..self.size]
    }
}

c_struct_free!(SecretKey, SecretKey_free);
unsafe extern "C" {
    fn SecretKey_init(secret_key: *mut SecretKey, curve: NamedCurve) -> c_int;
    fn SecretKey_free(secret_key: *mut SecretKey);
    fn SecretKey_pubkey(secret_key: *const SecretKey) -> *const u8;
    fn SecretKey_diffie_hellman(
        secret_key: *const SecretKey,
        pubkey: *const u8,
        pubkey_len: usize,
        out: *mut u8,
        out_len: *mut usize,
    ) -> c_int;
}


#[repr(C)]
pub struct SecretKey {
    curve: NamedCurve,
    pubkey_len: usize,
    rsv: [u8; 9104],
}

impl SecretKey {
    pub fn new(curve: NamedCurve) -> RlsResult<SecretKey> {
        let mut secret = SecretKey {
            curve,
            pubkey_len: 0,
            rsv: [0; 9104],
        };
        unsafe { SecretKey_init(&mut secret, curve) }.ok("invalid curve")?;
        Ok(secret)
    }

    pub fn pubkey(&self) -> RlsResult<&[u8]> {
        let ptr = unsafe { SecretKey_pubkey(self) };
        if ptr.is_null() { return Err("pubkey is null".into()); }
        Ok(unsafe { slice::from_raw_parts(ptr, self.pubkey_len) })
    }

    pub fn diffie_hellman(&self, pubkey: &[u8]) -> RlsResult<Vec<u8>> {
        let mut out = vec![0; 64];
        let mut out_len = out.len();
        unsafe {
            SecretKey_diffie_hellman(
                self,
                pubkey.as_ptr(),
                pubkey.len(),
                out.as_mut_ptr(),
                &mut out_len,
            )
        }.ok("diffie_hellman fail")?;
        out.truncate(out_len);
        Ok(out)
    }
}


#[cfg(test)]
mod tests {
    use crate::key::SecretKey;

    #[test]
    fn test_secret_key() {
        assert_eq!(size_of::<SecretKey>(), 9120);
    }
}