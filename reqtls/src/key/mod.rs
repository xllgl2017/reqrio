mod block;
mod derived;

use crate::boring::BoringResExt;
use crate::buffer::BufPtr;
use crate::error::RlsResult;
use crate::{ffi, Buf, BufferError, NamedCurve, Version};
use std::os::raw::c_int;
use crate::ffi::CPointer;
pub use block::{KeyType, TlsSession};
pub(crate) use derived::DerivedKey;

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

unsafe extern "C" {
    fn SecretKey_new(group: u16) -> *mut SECRET_KEY;
    fn SecretKey_new_pre_master_secret(ver: u16) -> *mut SECRET_KEY;
    fn SecretKey_free(secret_key: *mut SECRET_KEY);
    fn SecretKey_pubkey(secret_key: *const SECRET_KEY) -> *const u8;
    fn SecretKey_diffie_hellman(
        secret_key: *const SECRET_KEY,
        pubkey: *const u8,
        pubkey_len: usize,
        out: *mut u8,
        out_len: *mut usize,
    ) -> c_int;
}

ffi::c_pointer_free!(SECRET_KEY, SecretKey_free);

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct SECRET_KEY {
    group: u16,
}

pub struct SecretKey {
    group: NamedCurve,
    ptr: CPointer<SECRET_KEY>,
}

impl SecretKey {
    pub fn new(group: NamedCurve) -> Result<SecretKey, String> {
        let secret_key = unsafe { SecretKey_new(group.as_u16()) };
        Ok(SecretKey {
            group,
            ptr: CPointer::new_checked(secret_key, format!("group '{}' not supported", group))?,
        })
    }
}

impl SecretKey {
    pub fn new_pre_master_secret(version: &Version) -> Result<SecretKey, &'static str> {
        let secret_key = unsafe { SecretKey_new_pre_master_secret(version.as_u16()) };
        Ok(SecretKey {
            group: NamedCurve::PRE_MASTER,
            ptr: CPointer::new_checked(secret_key, "new pre-master-secret failed")?,
        })
    }

    pub fn diffie_hellman(&self, pub_key: impl AsRef<[u8]>) -> RlsResult<Vec<u8>> {
        let mut out = vec![0; 66];
        let mut len = 0;
        let pub_key = pub_key.as_ref();
        unsafe {
            SecretKey_diffie_hellman(
                self.ptr.as_ptr(),
                pub_key.as_ptr(),
                pub_key.len(),
                out.as_mut_ptr(),
                &mut len,
            )
        }.ok("diffie_hellman failed")?;
        out.truncate(len);
        Ok(out)
    }

    pub fn pub_key(&self) -> Result<Buf<'_>, BufferError> {
        let ptr = unsafe { SecretKey_pubkey(self.ptr.as_ptr()) };
        let mut ptr = BufPtr::from_ptr(ptr);
        ptr.check_ptr(self.group.pubkey_len())?;
        Ok(Buf::Ptr(ptr))
    }

    pub fn named_curve(&self) -> NamedCurve {
        self.group
    }
}

#[cfg(test)]
mod tests {
    use crate::{NamedCurve, SecretKey};

    #[test]
    fn test_secret_key() {
        let p256 = SecretKey::new(NamedCurve::SecP256r1).unwrap();
        assert_eq!(p256.pub_key().map(|x| x.len()).unwrap(), 65);
        let ec_p256 = SecretKey::new(NamedCurve::SecP256r1).unwrap();
        let s1 = p256.diffie_hellman(ec_p256.pub_key().unwrap()).unwrap();
        let s2 = ec_p256.diffie_hellman(p256.pub_key().unwrap()).unwrap();
        assert_eq!(s1, s2);

        let p384 = SecretKey::new(NamedCurve::SecP384r1).unwrap();
        assert_eq!(p384.pub_key().map(|x| x.len()).unwrap(), 97);
        let ec_p384 = SecretKey::new(NamedCurve::SecP384r1).unwrap();
        let s1 = p384.diffie_hellman(ec_p384.pub_key().unwrap()).unwrap();
        let s2 = ec_p384.diffie_hellman(p384.pub_key().unwrap()).unwrap();
        assert_eq!(s1, s2);

        let p521 = SecretKey::new(NamedCurve::SecP521r1).unwrap();
        assert_eq!(p521.pub_key().map(|x| x.len()).unwrap(), 133);
        let ec_p521 = SecretKey::new(NamedCurve::SecP521r1).unwrap();
        let s1 = p521.diffie_hellman(ec_p521.pub_key().unwrap()).unwrap();
        let s2 = ec_p521.diffie_hellman(p521.pub_key().unwrap()).unwrap();
        assert_eq!(s1, s2);

        let x25519 = SecretKey::new(NamedCurve::X25519).unwrap();
        assert_eq!(x25519.pub_key().map(|x| x.len()).unwrap(), 32);
        let evp_x25519 = SecretKey::new(NamedCurve::X25519).unwrap();
        let s1 = x25519.diffie_hellman(evp_x25519.pub_key().unwrap()).unwrap();
        let s2 = evp_x25519.diffie_hellman(x25519.pub_key().unwrap()).unwrap();
        assert_eq!(s1, s2);
    }
}