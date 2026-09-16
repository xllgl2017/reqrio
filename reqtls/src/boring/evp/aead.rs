use crate::boring::bindings::EVP_AEAD_DEFAULT_TAG_LENGTH;
use crate::boring::BoringResExt;
use crate::buffer::{CipherEncodeBuffer, TlsDecodeBuffer};
use crate::error::RlsResult;
use crate::extend::Aead;
use crate::RlsError;
use std::os::raw::{c_int, c_void};
use std::ptr::null_mut;
use super::iv::Iv;


#[repr(C)]
pub enum AeadDir {
    Open = 0,
    Seal = 1,
}

#[repr(C)]
pub struct AeadCtx {
    pub(crate) aead: Aead,
    pub(crate) seq: u64,
    pub(crate) iv: Iv,
    tag_len: c_int,
    enc: AeadDir,
    ctx: *mut c_void,
    rsv: [u32; 32],

}

unsafe impl Sync for AeadCtx {}
unsafe impl Send for AeadCtx {}

impl Drop for AeadCtx {
    fn drop(&mut self) {
        unsafe { AEAD_CTX_free(self) }
    }
}

unsafe extern "C" {
    fn AEAD_CTX_init(ctx: *mut AeadCtx, key: *const u8, key_len: usize) -> c_int;
    fn AEAD_CTX_free(ctx: *mut AeadCtx);
    fn AEAD_CTX_seal(
        ctx: *const AeadCtx,
        out: *mut u8,
        out_len: *mut usize,
        max_out_len: usize,
        nonce: *const u8,
        nonce_len: usize,
        in_: *const u8,
        in_len: usize,
        aad: *const u8,
        aad_len: usize,
    ) -> c_int;

    fn AEAD_CTX_open(
        ctx: *const AeadCtx,
        out: *mut u8,
        out_len: *mut usize,
        max_out_len: usize,
        nonce: *const u8,
        nonce_len: usize,
        input: *const u8,
        in_len: usize,
        aad: *const u8,
        aad_len: usize,
    ) -> c_int;
}

impl AeadCtx {
    pub(crate) fn new(aead: Aead, enc: AeadDir) -> AeadCtx {
        AeadCtx {
            aead,
            seq: 0,
            iv: Iv::new(),
            tag_len: EVP_AEAD_DEFAULT_TAG_LENGTH,
            enc,
            rsv: [0; 32],
            ctx: null_mut(),
        }
    }

    pub(crate) fn init(mut self, key: &[u8]) -> RlsResult<Self> {
        unsafe { AEAD_CTX_init(&mut self, key.as_ptr(), key.len()) }.ok(RlsError::AeadCryptError)?;
        Ok(self)
    }

    pub(crate) fn init_aead(&mut self, aead: Aead, dir: AeadDir, key: &[u8], iv: &[u8]) -> RlsResult<()> {
        self.aead = aead;
        self.enc = dir;
        self.iv.init(iv);
        self.seq = 0;
        unsafe { AEAD_CTX_init(self, key.as_ptr(), key.len()) }.ok(RlsError::AeadCryptError)?;
        Ok(())
    }

    pub fn none() -> AeadCtx {
        AeadCtx {
            aead: Aead::AES_128_GCM,
            enc: AeadDir::Open,
            tag_len: EVP_AEAD_DEFAULT_TAG_LENGTH,
            seq: 0,
            ctx: null_mut(),
            rsv: [0; 32],
            iv: Iv::new(),
        }
    }

    pub fn new_with_key(aead: Aead, dir: AeadDir, key: &[u8]) -> RlsResult<AeadCtx> {
        AeadCtx::new(aead, dir).init(key)
    }

    pub fn with_iv(mut self, iv: &[u8]) -> Self {
        self.iv.init(iv);
        self
    }

    pub(crate) fn seal(&self, nonce: &[u8], aad: &[u8], buf: &mut CipherEncodeBuffer) -> RlsResult<()> {
        debug_assert!(!self.is_null());
        let mut out_len = 0;
        let payload = buf.payload();
        unsafe {
            AEAD_CTX_seal(
                self,
                payload.encoded_payload().as_mut_ptr(),
                &mut out_len,
                payload.encoded_payload().len(),
                nonce.as_ptr(),
                nonce.len(),
                payload.origin_payload().as_ptr(),
                payload.origin_payload().len(),
                aad.as_ptr(),
                aad.len(),
            )
        }.ok(RlsError::AeadEncryptError)?;
        buf.set_encrypted_len(out_len);
        Ok(())
    }

    pub fn seal_bytes(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> RlsResult<Vec<u8>> {
        debug_assert!(!self.is_null());
        let mut output = vec![0u8; plaintext.len() + 16];
        let mut output_len = 0usize;
        unsafe {
            AEAD_CTX_seal(
                self,
                output.as_mut_ptr(),
                &mut output_len,
                output.len(),
                nonce.as_ptr(),
                nonce.len(),
                plaintext.as_ptr(),
                plaintext.len(),
                aad.as_ptr(),
                aad.len(),
            )
        }.ok(RlsError::AeadEncryptError)?;
        output.truncate(output_len);
        Ok(output)
    }

    pub(crate) fn open(&self, nonce: &[u8], aad: &[u8], buf: &mut TlsDecodeBuffer) -> RlsResult<usize> {
        debug_assert!(!self.is_null());
        let mut out_len = 0usize;
        unsafe {
            AEAD_CTX_open(
                self,
                buf.decrypted_buffer().as_mut_ptr(),
                &mut out_len,
                buf.decrypted_buffer().len(),
                nonce.as_ptr(),
                nonce.len(),
                buf.encrypted_payload().as_ptr(),
                buf.encrypted_payload().len(),
                aad.as_ptr(),
                aad.len(),
            )
        }.ok(RlsError::AeadDecryptError)?;
        Ok(out_len)
    }

    pub fn open_bytes(&self, nonce: &[u8], aad: &[u8], cipher_bytes: &[u8]) -> RlsResult<Vec<u8>> {
        debug_assert!(!self.is_null());
        let mut output = vec![0u8; cipher_bytes.len() - 16];
        let mut output_len = 0usize;
        unsafe {
            AEAD_CTX_open(
                self,
                output.as_mut_ptr(),
                &mut output_len,
                output.len(),
                nonce.as_ptr(),
                nonce.len(),
                cipher_bytes.as_ptr(),
                cipher_bytes.len(),
                aad.as_ptr(),
                aad.len(),
            )
        }.ok(RlsError::AeadEncryptError)?;
        output.truncate(output_len);
        Ok(output)
    }

    pub fn is_null(&self) -> bool {
        self.ctx.is_null() && self.rsv == [0; 32]
    }
}


#[cfg(test)]
mod aead_tests {
    use crate::boring::evp::aead::AeadDir;
    use crate::boring::AeadCtx;
    use crate::buffer::{CipherEncodeBuffer, TlsDecodeBuffer};
    use crate::{CipherSuite, RecordType, Version, Writer};
    use std::{env, fs};

    fn test_aead(suite: &'static CipherSuite, key: &[u8], size: usize, en: &[u8]) {
        let ctx = AeadCtx::new_with_key(*suite.aead(), AeadDir::Open, key).unwrap();
        let payload = [1, 2, 3, 4, 5, 61, 2, 3, 4, 5, 6, 7, 8, 9, 23, 23];
        let iv = [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4];
        let mut buffer = [0; 1024];
        let mut record_buffer = CipherEncodeBuffer::new_tls(RecordType::HandShake, &mut buffer, &payload, suite);
        record_buffer.add_explicit_iv(&iv);
        let aad = record_buffer.aad(0);
        ctx.seal(&[0; 12], &aad, &mut record_buffer).unwrap();
        let len = record_buffer.record_len();
        assert_eq!(len, size);
        assert_eq!(&buffer[..len], en);
        let mut decoded_buffer = vec![0; 1024];
        let mut record_buffer = TlsDecodeBuffer::from_buffer(&buffer[..len], &mut decoded_buffer, suite).unwrap();
        let aad = record_buffer.aad(0).unwrap();
        let mut len = ctx.open(&[0; 12], &aad, &mut record_buffer).unwrap();
        if let &Version::TLS_1_3 = suite.version {
            len -= 1;
        }
        assert_eq!(len, 16);
        assert_eq!(&decoded_buffer[..len], payload);
    }

    #[test]
    fn test_aead_ctx() {
        let token = fs::read_to_string("../TOKEN").unwrap_or_else(|_| {
            env::var("REQRIO_TOKEN").unwrap_or("".to_string())
        });
        Writer::check_subscription(token).unwrap();
        let key = [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        test_aead(
            &CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 
            &key, 
            45, 
            &[22, 3, 3, 0, 40, 5, 6, 7, 8, 1, 2, 3, 4, 73, 124, 57, 79, 141, 133, 227, 18, 144, 234, 121, 155, 242, 80, 24, 135, 186, 135, 31, 85, 210, 190, 133, 14, 120, 110, 158, 242, 184, 89, 14, 110]
        );
        let key = [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        test_aead(
            &CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, 
            &key, 
            45, 
            &[22, 3, 3, 0, 40, 5, 6, 7, 8, 1, 2, 3, 4, 212, 216, 11, 46, 55, 11, 51, 6, 9, 103, 221, 215, 100, 98, 203, 62, 17, 75, 66, 161, 168, 255, 72, 59, 189, 213, 196, 182, 248, 164, 109, 233]
        );
        test_aead(
            &CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, 
            &key, 
            37, 
            &[22, 3, 3, 0, 32, 117, 245, 41, 12, 78, 148, 113, 238, 9, 193, 134, 57, 89, 54, 164, 34, 16, 30, 205, 190, 166, 146, 81, 111, 237, 224, 212, 24, 176, 182, 162, 76]
        );

        let key = [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        test_aead(
            &CipherSuite::TLS_AES_128_GCM_SHA256, 
            &key, 
            38, 
            &[23, 3, 3, 0, 33, 73, 124, 57, 79, 141, 133, 227, 18, 144, 234, 121, 155, 242, 80, 24, 135, 242, 85, 24, 178, 65, 169, 220, 3, 194, 146, 52, 174, 244, 106, 123, 230, 31]
        );
        // test_aead(&CipherSuite::TLS_SM4_GCM_SM3, &key, 38, &[23, 3, 3, 0, 33, 230, 37, 165, 245, 42, 213, 2, 105, 130, 26, 88, 111, 64, 103, 112, 27, 4, 49, 122, 222, 51, 209, 20, 222, 149, 172, 18, 163, 84, 66, 244, 154, 211]);

        let key = [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        test_aead(
            &CipherSuite::TLS_AES_256_GCM_SHA384, 
            &key, 
            38, 
            &[23, 3, 3, 0, 33, 212, 216, 11, 46, 55, 11, 51, 6, 9, 103, 221, 215, 100, 98, 203, 62, 129, 117, 41, 52, 75, 226, 135, 56, 115, 180, 125, 134, 114, 206, 161, 50, 134]
        );
        test_aead(
            &CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
            &key, 
            38, 
            &[23, 3, 3, 0, 33, 117, 245, 41, 12, 78, 148, 113, 238, 9, 193, 134, 57, 89, 54, 164, 34, 117, 170, 210, 251, 96, 6, 14, 229, 70, 1, 117, 118, 12, 51, 77, 24, 208]
        );
    }
}