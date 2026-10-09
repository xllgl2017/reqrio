use std::os::raw::c_int;
use crate::boring::BoringResExt;
use crate::ffi::{c_pointer_free, CPointer};
use crate::gm_sm::SmError;

#[repr(C)]
#[allow(non_camel_case_types)]
struct SM2_KEY {
    _unused: [u8; 0],
}

#[repr(C)]
pub enum Sm2Model {
    C1C2C3 = 0,
    C1C3C2 = 1,
}

c_pointer_free!(SM2_KEY, SM2_KEY_free);

unsafe extern "C" {
    fn SM2_KEY_new() -> *mut SM2_KEY;
    fn SM2_KEY_free(key: *mut SM2_KEY);
    fn SM2_KEY_generate(key: *mut SM2_KEY) -> c_int;
    fn SM2_KEY_set_private_key(key: *mut SM2_KEY, d: *const u8, dlen: usize) -> c_int;
    fn SM2_KEY_set_public_key(key: *mut SM2_KEY, pubkey: *const u8, pubkey_len: usize) -> c_int;
    fn SM2_KEY_get_public_key(key: *const SM2_KEY, compressed: c_int, out: *mut u8, out_len: &mut usize) -> c_int;
    fn SM2_KEY_get_private_key(key: *const SM2_KEY, out: *mut u8, out_len: &mut usize) -> c_int;
    fn SM2_KEY_verify(
        key: *const SM2_KEY,
        id: *const u8,
        id_len: usize,
        msg: *const u8,
        msg_len: usize,
        r: *const u8,
        s: *const u8,
    ) -> c_int;
    fn SM2_KEY_sign(
        key: *const SM2_KEY,
        id: *const u8,
        id_len: usize,
        msg: *const u8,
        msg_len: usize,
        r: *mut u8,
        s: *mut u8,
    ) -> c_int;
    fn SM2_KEY_encrypt(
        key: *const SM2_KEY,
        msg: *const u8,
        msg_len: usize,
        mode: Sm2Model,
        compressed: c_int,
        out: *mut u8,
        out_len: *mut usize,
    ) -> c_int;

    fn SM2_KEY_decrypt(
        key: *const SM2_KEY,
        ciphertext: *const u8,
        ciphertext_len: usize,
        mode: Sm2Model,
        out: *mut u8,
        out_len: *mut usize,
    ) -> c_int;

    fn SM2_KEY_encrypt_premaster(
        key: *const SM2_KEY,
        pms: *const u8,
        pms_len: usize,
        out: *mut u8,
        out_len: *mut usize,
    ) -> c_int;

    fn SM2_KEY_verify_asn(
        key: *const SM2_KEY,
        id: *const u8,
        id_len: usize,
        data: *const u8,
        data_len: usize,
        sign: *const u8,
        sign_len: usize,
    ) -> c_int;
}

pub struct Sm2Key(CPointer<SM2_KEY>);

impl Sm2Key {
    pub const DEFAULT_ID: &[u8; 16] = b"1234567812345678";
    pub fn none() -> Sm2Key {
        Sm2Key(CPointer::nullptr())
    }
    
    pub fn is_null(&self) -> bool {
        self.0.is_null()
    }

    fn new() -> Result<Sm2Key, SmError> {
        let key = unsafe { SM2_KEY_new() };
        let key = CPointer::new_checked(key, SmError::Sm2KeyNew)?;
        Ok(Sm2Key(key))
    }

    pub fn generate() -> Result<Sm2Key, SmError> {
        let key = Sm2Key::new()?;
        unsafe { SM2_KEY_generate(key.0.as_mut_ptr()) }.ok(SmError::Sm2GenKeyFailed)?;
        Ok(key)
    }

    pub fn from_pri_key(d: impl AsRef<[u8]>) -> Result<Sm2Key, SmError> {
        let key = Sm2Key::new()?;
        let d = d.as_ref();
        unsafe { SM2_KEY_set_private_key(key.0.as_mut_ptr(), d.as_ptr(), d.len()) }.ok(SmError::Sm2GenKeyFailed)?;
        Ok(key)
    }

    pub fn from_pub_key(pubkey: impl AsRef<[u8]>) -> Result<Sm2Key, SmError> {
        let key = Sm2Key::new()?;
        let pubkey = pubkey.as_ref();
        unsafe { SM2_KEY_set_public_key(key.0.as_mut_ptr(), pubkey.as_ptr(), pubkey.len()) }.ok(SmError::Sm2GenKeyFailed)?;
        Ok(key)
    }

    pub fn verify(&self, id: Option<&'static str>, msg: impl AsRef<[u8]>, sign: impl AsRef<[u8]>) -> Result<(), SmError> {
        let id = id.as_ref().map(|d| d.as_bytes()).unwrap_or(Self::DEFAULT_ID);
        let msg = msg.as_ref();
        let sign = sign.as_ref();
        let r = &sign[0..32];
        let s = &sign[32..64];
        unsafe {
            SM2_KEY_verify(
                self.0.as_mut_ptr(),
                id.as_ptr(),
                id.len(),
                msg.as_ptr(),
                msg.len(),
                r.as_ptr(),
                s.as_ptr(),
            )
        }.ok(SmError::Sm2VerifyFailed)
    }


    pub fn verify_asn1(&self, data: impl AsRef<[u8]>, sign: impl AsRef<[u8]>) -> Result<(), SmError> {
        let data = data.as_ref();
        let sign = sign.as_ref();
        unsafe {
            SM2_KEY_verify_asn(
                self.0.as_mut_ptr(),
                Self::DEFAULT_ID.as_ptr(),
                Self::DEFAULT_ID.len(),
                data.as_ptr(),
                data.len(),
                sign.as_ptr(),
                sign.len(),
            )
        }.ok(SmError::Sm2VerifyFailed)
    }

    pub fn sign(&self, id: Option<impl AsRef<[u8]>>, msg: impl AsRef<[u8]>) -> Result<[u8; 64], SmError> {
        let mut sign = [0; 64];
        self.sign_extract(id, msg, &mut sign)?;
        Ok(sign)
    }

    pub fn sign_extract(&self, id: Option<impl AsRef<[u8]>>, msg: impl AsRef<[u8]>, out: &mut [u8]) -> Result<(), SmError> {
        let id = id.as_ref().map(|d| d.as_ref()).unwrap_or(Self::DEFAULT_ID);
        let msg = msg.as_ref();
        unsafe {
            SM2_KEY_sign(
                self.0.as_mut_ptr(),
                id.as_ptr(),
                id.len(),
                msg.as_ptr(),
                msg.len(),
                out[0..32].as_mut_ptr(),
                out[32..64].as_mut_ptr(),
            )
        }.ok(SmError::Sm2SignError)
    }

    pub fn encrypt(&self, mode: Sm2Model, compress: bool, msg: impl AsRef<[u8]>) -> Result<Vec<u8>, SmError> {
        let msg = msg.as_ref();
        let mut out = vec![0; if compress { 33 } else { 65 } + msg.len() + 32];
        let mut out_len = out.len();
        unsafe {
            SM2_KEY_encrypt(
                self.0.as_mut_ptr(),
                msg.as_ptr(),
                msg.len(),
                mode,
                compress as c_int,
                out.as_mut_ptr(),
                &mut out_len,
            )
        }.ok(SmError::Sm2EncryptError)?;
        Ok(out)
    }

    pub fn decrypt(&self, mode: Sm2Model, ciphertext: impl AsRef<[u8]>) -> Result<Vec<u8>, SmError> {
        let ciphertext = ciphertext.as_ref();
        let len = if ciphertext[0] == 4 { ciphertext.len() - 97 } else { ciphertext.len() - 65 };
        let mut out = vec![0; len];
        let mut out_len = out.len();
        unsafe {
            SM2_KEY_decrypt(
                self.0.as_mut_ptr(),
                ciphertext.as_ptr(),
                ciphertext.len(),
                mode,
                out.as_mut_ptr(),
                &mut out_len,
            )
        }.ok(SmError::Sm2DecryptFail)?;
        Ok(out)
    }

    pub fn pri_key(&self) -> Result<[u8; 32], SmError> {
        let mut key = [0; 32];
        let mut out_len = key.len();
        unsafe {
            SM2_KEY_get_private_key(self.0.as_ptr(), key.as_mut_ptr(), &mut out_len)
        }.ok(SmError::Sm2GetKeyFailed)?;
        Ok(key)
    }

    pub fn pub_key(&self, compress: bool) -> Result<Vec<u8>, SmError> {
        let mut len = if compress { 33 } else { 65 };
        let mut key = vec![0; len];
        unsafe {
            SM2_KEY_get_public_key(self.0.as_ptr(), compress as c_int, key.as_mut_ptr(), &mut len)
        }.ok(SmError::Sm2GetKeyFailed)?;
        Ok(key)
    }

    pub fn encrypt_premaster(&self, pms: impl AsRef<[u8]>) -> Result<Vec<u8>, SmError> {
        let mut out = vec![0; 160];
        let mut out_len = out.len();
        let pms = pms.as_ref();
        unsafe {
            SM2_KEY_encrypt_premaster(
                self.0.as_mut_ptr(),
                pms.as_ptr(),
                pms.len(),
                out.as_mut_ptr(),
                &mut out_len,
            )
        }.ok(SmError::Sm2EncryptError)?;
        out.truncate(out_len);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use crate::gm_sm::sm2::{Sm2Key, Sm2Model};
    use crate::rand;

    #[test]
    fn sm2_test() {
        let pub_key = [4, 165, 139, 156, 242, 170, 161, 246, 2, 255, 48, 131, 192, 157, 249, 167, 37, 157, 10, 54, 206, 74, 0, 3, 65, 193, 75, 15, 229, 96, 238, 69, 134, 8, 15, 140, 181, 43, 146, 84, 104, 148, 10, 142, 102, 158, 176, 161, 84, 175, 64, 88, 33, 247, 132, 216, 120, 12, 68, 38, 46, 4, 178, 78, 144];
        let sign = [189, 125, 217, 21, 1, 238, 194, 106, 137, 16, 179, 151, 226, 83, 121, 78, 243, 206, 24, 172, 187, 188, 172, 30, 80, 145, 190, 8, 167, 233, 86, 67, 254, 43, 253, 24, 31, 207, 100, 72, 170, 229, 73, 52, 142, 38, 45, 124, 182, 218, 239, 158, 205, 57, 25, 156, 166, 249, 102, 234, 33, 235, 196, 54];
        let key = Sm2Key::from_pub_key(pub_key).unwrap();
        assert!(key.verify(None::<&str>, "123", sign).is_ok());

        let pri_key = [19, 238, 7, 135, 31, 63, 80, 40, 250, 184, 86, 234, 236, 32, 132, 117, 46, 85, 104, 181, 74, 170, 152, 62, 92, 250, 163, 111, 118, 123, 50, 139];
        let key = Sm2Key::from_pri_key(pri_key).unwrap();
        assert_eq!(key.pub_key(false).unwrap(), pub_key);
        assert!(key.encrypt(Sm2Model::C1C2C3, false, "123").is_ok());
        assert!(key.encrypt(Sm2Model::C1C2C3, true, "123").is_ok());

        let en = [4, 194, 227, 127, 89, 65, 107, 106, 201, 25, 130, 185, 20, 77, 61, 206, 10, 96, 153, 107, 225, 177, 241, 27, 83, 160, 189, 43, 219, 166, 91, 67, 5, 71, 22, 158, 69, 49, 160, 5, 60, 120, 142, 38, 43, 134, 193, 236, 217, 1, 207, 54, 87, 132, 166, 202, 79, 212, 231, 59, 253, 55, 166, 215, 146, 251, 15, 41, 66, 158, 202, 98, 74, 249, 114, 109, 62, 68, 100, 161, 113, 231, 116, 171, 113, 245, 206, 213, 7, 180, 193, 86, 140, 65, 64, 140, 188, 118, 35, 225];
        assert_eq!(key.decrypt(Sm2Model::C1C3C2, en).unwrap(), b"123");

        let en = [4, 252, 246, 81, 71, 50, 70, 244, 36, 184, 164, 195, 51, 75, 81, 148, 158, 107, 142, 241, 131, 1, 155, 199, 50, 66, 119, 254, 161, 98, 141, 139, 2, 24, 187, 212, 105, 132, 112, 68, 110, 231, 32, 240, 208, 165, 12, 214, 69, 43, 19, 179, 211, 62, 24, 245, 26, 202, 132, 46, 95, 234, 103, 194, 201, 199, 137, 146, 76, 85, 145, 249, 33, 56, 69, 167, 34, 244, 125, 222, 8, 98, 145, 131, 228, 218, 88, 230, 186, 92, 64, 216, 77, 253, 89, 118, 180, 59, 135, 207];
        assert_eq!(key.decrypt(Sm2Model::C1C2C3, en).unwrap(), b"123");

        let en = [3, 127, 168, 41, 34, 225, 58, 137, 135, 102, 201, 209, 197, 101, 14, 117, 11, 136, 249, 19, 78, 33, 119, 166, 153, 18, 14, 126, 239, 129, 138, 212, 72, 197, 253, 98, 59, 57, 16, 209, 103, 42, 200, 233, 22, 101, 9, 99, 249, 87, 5, 58, 244, 138, 71, 138, 255, 228, 152, 44, 113, 115, 6, 147, 174, 183, 24, 110];
        assert_eq!(key.decrypt(Sm2Model::C1C2C3, en).unwrap(), b"123");


        let key = Sm2Key::from_pub_key([2, 165, 139, 156, 242, 170, 161, 246, 2, 255, 48, 131, 192, 157, 249, 167, 37, 157, 10, 54, 206, 74, 0, 3, 65, 193, 75, 15, 229, 96, 238, 69, 134]);
        assert!(key.is_ok());

        let key = Sm2Key::from_pub_key(pub_key).unwrap();
        let mut pms = [0; 48];
        pms[0] = 1;
        pms[1] = 1;
        rand::fill(&mut pms[2..]);
        let pre_master = key.encrypt_premaster(pms);
        assert!(pre_master.is_ok())
    }
}