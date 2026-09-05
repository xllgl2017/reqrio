use super::super::Padding;
use super::CipherType;
use crate::boring::BoringResExt;
use crate::error::RlsResult;
use crate::ffi::CPointer;
use crate::{base64, ffi};
use std::error::Error;
use std::fmt::Display;
use std::ops::{Deref, DerefMut};
use std::os::raw::c_int;
use std::ptr::null;

#[derive(Debug)]
pub enum CipherError {
    NewCipherCtx,
    CipherReset,
    CipherInit,
    SetKeyLen,
    SetPadding,
    CipherUpdate,
    CipherFinalize,
    InvalidMac,
}

impl Display for CipherError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for CipherError {}

#[repr(C)]
#[allow(clippy::upper_case_acronyms)]
#[allow(non_camel_case_types)]
pub struct CIPHER_CTX {
    _unused: [u8; 0],
}
ffi::c_pointer_free!(CIPHER_CTX, CIPHER_CTX_free);

unsafe extern "C" {
    fn CIPHER_CTX_new(cipher: CipherType) -> *mut CIPHER_CTX;
    fn CIPHER_CTX_free(ctx: *mut CIPHER_CTX);
    fn CIPHER_CTX_init(
        ctx: *const CIPHER_CTX,
        key: *const u8,
        key_len: usize,
        iv: *const u8,
        padding: c_int,
        enc: c_int,
    ) -> c_int;
    fn CIPHER_update(ctx: *const CIPHER_CTX, out: *mut u8, out_len: *mut c_int, in_: *const u8, in_len: c_int) -> c_int;
    fn CIPHER_final(ctx: *const CIPHER_CTX, out: *mut u8, out_len: *mut c_int) -> c_int;
}

struct CipherCtx(CPointer<CIPHER_CTX>);

impl CipherCtx {
    pub fn new(cipher: CipherType) -> CipherCtx {
        let ptr = unsafe { CIPHER_CTX_new(cipher) };
        CipherCtx(CPointer::new(ptr))
    }

    pub fn init(&self, key: &[u8], iv: &[u8], padding: i32, enc: i32) -> Result<(), CipherError> {
        let iv = if !iv.is_empty() { iv.as_ptr() } else { null() };
        unsafe { CIPHER_CTX_init(self.as_ptr(), key.as_ptr(), key.len(), iv, padding, enc) }.ok(CipherError::CipherInit)
    }
}

impl Deref for CipherCtx {
    type Target = CPointer<CIPHER_CTX>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for CipherCtx {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub struct Cipher {
    ctx: CipherCtx,
    evp_cipher: CipherType,
    padding: Padding,
    key: Vec<u8>,
    iv: Vec<u8>,
}

impl Cipher {
    pub(crate) fn new(cipher: CipherType) -> Cipher {
        Cipher {
            ctx: CipherCtx::new(cipher),
            evp_cipher: cipher,
            padding: Padding::PKCS7Padding,
            key: vec![],
            iv: vec![],
        }
    }

    pub fn aes_128_cbc() -> Cipher { Cipher::new(CipherType::AES_128_CBC) }

    pub fn aes_192_cbc() -> Cipher {
        Cipher::new(CipherType::AES_192_CBC)
    }

    pub fn aes_256_cbc() -> Cipher {
        Cipher::new(CipherType::AES_256_CBC)
    }

    pub fn aes_128_ecb() -> Cipher {
        Cipher::new(CipherType::AES_128_ECB)
    }

    pub fn aes_192_ecb() -> Cipher {
        Cipher::new(CipherType::AES_192_ECB)
    }

    pub fn aes_256_ecb() -> Cipher {
        Cipher::new(CipherType::AES_256_ECB)
    }

    pub fn aes_128_ctr() -> Cipher {
        Cipher::new(CipherType::AES_128_CTR)
    }

    pub fn aes_192_ctr() -> Cipher {
        Cipher::new(CipherType::AES_192_CTR)
    }

    pub fn aes_256_ctr() -> Cipher {
        Cipher::new(CipherType::AES_256_CTR)
    }

    pub fn aes_128_gcm() -> Cipher {
        Cipher::new(CipherType::AES_128_GCM)
    }

    pub fn aes_192_gcm() -> Cipher {
        Cipher::new(CipherType::AES_192_GCM)
    }

    pub fn aes_256_gcm() -> Cipher {
        Cipher::new(CipherType::AES_256_GCM)
    }

    pub fn aes_128_ofb() -> Cipher {
        Cipher::new(CipherType::AES_128_OFB)
    }

    pub fn aes_192_ofb() -> Cipher {
        Cipher::new(CipherType::AES_192_OFB)
    }

    pub fn aes_256_ofb() -> Cipher {
        Cipher::new(CipherType::AES_256_OFB)
    }

    pub fn des_cbc() -> Cipher {
        Cipher::new(CipherType::DES_CBC)
    }

    pub fn des_ecb() -> Cipher {
        Cipher::new(CipherType::DES_ECB)
    }

    pub fn rc4() -> Cipher { Cipher::new(CipherType::RC4) }

    pub fn sm4_ecb() -> Cipher { Cipher::new(CipherType::SM4_ECB) }

    pub fn sm4_cbc() -> Cipher { Cipher::new(CipherType::SM4_CBC) }

    pub fn sm4_ctr() -> Cipher { Cipher::new(CipherType::SM4_CTR) }

    pub fn sm4_ofb() -> Cipher { Cipher::new(CipherType::SM4_OFB) }

    pub fn sm4_cfb() -> Cipher { Cipher::new(CipherType::SM4_CFB) }

    /// 3DES-CBC
    pub fn des_ded3_cbc() -> Cipher { Cipher::new(CipherType::DES_DED3_CBC) }

    pub fn des_ded3_ecb() -> Cipher { Cipher::new(CipherType::DES_DED3_ECB) }

    pub fn with_secret_key<T: Into<Vec<u8>>>(mut self, key: T, iv: Option<T>) -> Self {
        self.set_secret_key(key, iv);
        self
    }

    pub fn set_secret_key<T: Into<Vec<u8>>>(&mut self, key: T, iv: Option<T>) {
        self.key = key.into();
        self.iv = iv.map(|iv| iv.into()).unwrap_or(vec![]);
    }

    pub fn with_padding(mut self, padding: Padding) -> Self {
        self.set_padding(padding);
        self
    }

    pub fn set_padding(&mut self, padding: Padding) {
        self.padding = padding;
    }

    pub fn encrypt(&self, context: impl AsRef<[u8]>) -> Result<Vec<u8>, CipherError> {
        self.init_cipher(&self.iv, 1)?;
        let mut out = vec![0; context.as_ref().len() + 16];
        let padding = if !matches!(self.evp_cipher, CipherType::RC4) { self.padding.add_padding(context.as_ref()) } else { vec![] };
        let ptr = context.as_ref().as_ptr();
        let out_ptr = out.as_mut_ptr();
        let block_len = self.update(ptr, context.as_ref().len(), out_ptr)?;
        let out_ptr = unsafe { out_ptr.add(block_len) };
        let padding_len = self.update(padding.as_ptr(), padding.len(), out_ptr)?;
        let out_ptr = unsafe { out_ptr.add(padding_len) };
        let final_len = self.finalize(out_ptr)?;
        out.truncate(block_len + padding_len + final_len);
        Ok(out)
    }

    pub fn decrypt(&self, context: impl Into<Vec<u8>>) -> Result<Vec<u8>, CipherError> {
        self.init_cipher(&self.iv, 0)?;
        let mut context = context.into();
        let ptr = context.as_ptr();
        let out = context.as_mut_ptr();
        let out_len = self.update(ptr, context.len(), out)?;
        let out = unsafe { out.add(out_len) };
        let final_len = self.finalize(out)?;
        context.truncate(out_len + final_len);
        if !matches!(self.evp_cipher, CipherType::RC4) { self.padding.remove_padding(&mut context); }
        Ok(context)
    }

    pub(crate) fn init_cipher(&self, iv: &[u8], enc: i32) -> Result<(), CipherError> {
        if self.ctx.is_null() { return Err(CipherError::NewCipherCtx); }
        self.ctx.init(&self.key, iv, 0, enc)
    }

    pub(crate) fn update(&self, context: *const u8, len: usize, out: *mut u8) -> Result<usize, CipherError> {
        let mut out_len = 0;
        unsafe {
            CIPHER_update(
                self.ctx.as_mut_ptr(),
                out,
                &mut out_len,
                context,
                len as i32,
            )
        }.ok(CipherError::CipherUpdate)?;
        Ok(out_len as usize)
    }

    pub(crate) fn finalize(&self, out: *mut u8) -> Result<usize, CipherError> {
        let mut final_len = 0;
        unsafe { CIPHER_final(self.ctx.as_mut_ptr(), out, &mut final_len) }.ok(CipherError::CipherFinalize)?;
        Ok(final_len as usize)
    }
}

pub fn en_b64<T: Into<Vec<u8>>>(typ: CipherType, key: T, iv: Option<T>, data: impl AsRef<[u8]>) -> RlsResult<String> {
    let cipher = Cipher::new(typ).with_secret_key(key, iv);
    let en_bs = cipher.encrypt(data)?;
    Ok(base64::b64encode(en_bs)?)
}

pub fn de_b64<T: Into<Vec<u8>>>(typ: CipherType, key: T, iv: Option<T>, data: impl AsRef<[u8]>) -> RlsResult<Vec<u8>> {
    let de_b64 = base64::b64decode(data)?;
    let cipher = Cipher::new(typ).with_secret_key(key, iv);
    Ok(cipher.decrypt(de_b64)?)
}

pub fn en_hex<T: Into<Vec<u8>>>(typ: CipherType, key: T, iv: Option<T>, data: impl AsRef<[u8]>) -> RlsResult<String> {
    let cipher = Cipher::new(typ).with_secret_key(key, iv);
    let en_bs = cipher.encrypt(data)?;
    Ok(hex::encode(en_bs))
}

pub fn de_hex<T: Into<Vec<u8>>>(typ: CipherType, key: T, iv: Option<T>, data: impl AsRef<[u8]>) -> RlsResult<Vec<u8>> {
    let de_hex = hex::decode(data)?;
    let cipher = Cipher::new(typ).with_secret_key(key, iv);
    Ok(cipher.decrypt(de_hex)?)
}


#[cfg(test)]
mod tests {
    use std::{env, fs};
    use crate::{Writer, Cipher, CipherType};

    fn test_one_cipher<T: Into<Vec<u8>>>(typ: CipherType, key: T, iv: Option<T>, data: &[u8], en: &[u8]) {
        let cipher = Cipher::new(typ).with_secret_key(key, iv);
        let en_bs = cipher.encrypt(data).unwrap();
        assert_eq!(en_bs, en);

        let de_bs = cipher.decrypt(en_bs).unwrap();
        assert_eq!(de_bs, data)
    }

    #[test]
    fn test_cipher() {
        let token = fs::read_to_string("../TOKEN").unwrap_or_else(|_| {
            env::var("REQRIO_TOKEN").unwrap_or("".to_string())
        });
        Writer::check_subscription(token).unwrap();
        let k16 = "1234567812345678";
        let k24 = "123456781234567812345678";
        let k32 = "12345678123456781234567812345678";

        let iv8 = "12345678";
        let iv16 = "1234567812345678";
        test_one_cipher(CipherType::AES_128_CBC, k16, Some(iv16), b"hello world", &[107, 100, 169, 51, 126, 231, 189, 86, 45, 6, 117, 71, 162, 117, 252, 235]);
        test_one_cipher(CipherType::AES_192_CBC, k24, Some(iv16), b"hello world", &[112, 230, 39, 80, 184, 157, 131, 154, 85, 102, 84, 183, 111, 20, 203, 165]);
        test_one_cipher(CipherType::AES_256_CBC, k32, Some(iv16), b"hello world", &[110, 146, 35, 67, 140, 149, 192, 43, 116, 68, 194, 52, 36, 51, 159, 76]);


        let cipher = Cipher::rc4().with_secret_key("7d1a840419e1648c4e247b70f4a1e472", None);
        let res = cipher.decrypt([35, 35, 52, 190, 118, 125, 64, 163, 60, 89, 220, 195, 147, 90, 228, 21]).unwrap();
        assert_eq!(res, [112, 107, 105, 73, 79, 122, 72, 108, 69, 84, 76, 80, 100, 69, 85, 113]);

        let key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10];
        let cipher = Cipher::sm4_ecb().with_secret_key(&key, None);
        let data = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10];
        let en = cipher.encrypt(data).unwrap();
        assert_eq!(&en[..16], [104, 30, 223, 52, 210, 6, 150, 94, 134, 179, 233, 79, 83, 110, 66, 70]);
        let de = cipher.decrypt(en).unwrap();
        assert_eq!(de, data);

        let cipher = Cipher::sm4_cbc().with_secret_key(&key, Some(&key));
        let en = cipher.encrypt(data).unwrap();
        assert_eq!(en, [38, 119, 244, 107, 9, 193, 34, 204, 151, 85, 51, 16, 91, 212, 162, 42, 59, 136, 14, 104, 103, 119, 37, 34, 174, 85, 210, 240, 174, 116, 120, 174]);
        let de = cipher.decrypt(en).unwrap();
        assert_eq!(de, data);


        test_one_cipher(CipherType::SM4_OFB, &key, Some(&key), b"foobar", &[14, 113, 176, 86, 179, 116, 156, 84, 140, 185, 227, 69, 89, 100, 72, 76]);
        test_one_cipher(CipherType::DES_DED3_ECB, k24, None, b"123456", &[174, 178, 153, 127, 23, 12, 103, 74, 131, 158, 104, 246, 82, 9, 158, 46]);
        test_one_cipher(CipherType::DES_DED3_CBC, k24, Some(iv8), b"123456", &[58, 76, 232, 32, 246, 19, 229, 87, 101, 150, 190, 118, 110, 62, 110, 218]);
    }
}