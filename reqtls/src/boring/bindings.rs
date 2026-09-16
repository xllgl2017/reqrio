use std::os::raw::{c_char, c_int, c_uint, c_void};

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub(crate) struct ENGINE {
    _unused: [u8; 0],
}

pub(crate) const EVP_AEAD_DEFAULT_TAG_LENGTH: i32 = 0;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub(crate) struct EVP_CIPHER {
    _unused: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub(crate) struct EVP_MD {
    _unused: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub(crate) struct EVP_ENCODE_CTX {
    pub(crate) data_used: c_uint,
    pub(crate) data: [u8; 48usize],
    pub(crate) eof_seen: c_char,
    pub(crate) error_encountered: c_char,
}


unsafe extern "C" {

    pub(crate) fn HMAC(
        evp_md: *const EVP_MD,
        key: *const c_void,
        key_len: usize,
        data: *const u8,
        data_len: usize,
        out: *mut u8,
        out_len: *mut c_uint,
    ) -> *mut u8;


    pub(crate) fn EVP_ENCODE_CTX_new() -> *mut EVP_ENCODE_CTX;

    pub(crate) fn EVP_ENCODE_CTX_free(ctx: *mut EVP_ENCODE_CTX);

    pub(crate) fn EVP_EncodeUpdate(
        ctx: *mut EVP_ENCODE_CTX,
        out: *mut u8,
        out_len: *mut c_int,
        in_: *const u8,
        in_len: usize,
    );

    pub(crate) fn EVP_EncodeFinal(
        ctx: *mut EVP_ENCODE_CTX,
        out: *mut u8,
        out_len: *mut c_int,
    );

    pub(crate) fn EVP_DecodeUpdate(
        ctx: *mut EVP_ENCODE_CTX,
        out: *mut u8,
        out_len: *mut c_int,
        in_: *const u8,
        in_len: usize,
    ) -> c_int;

    pub(crate) fn EVP_DecodeFinal(
        ctx: *mut EVP_ENCODE_CTX,
        out: *mut u8,
        out_len: *mut c_int,
    ) -> c_int;
}


unsafe extern "C" {

    pub(crate) fn OPENSSL_free(ptr: *mut c_void);
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub(crate) struct EVP_PKEY {
    _unused: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub(crate) struct EVP_PKEY_CTX {
    _unused: [u8; 0],
}

unsafe extern "C" {
    pub(crate) fn EVP_PKEY_new() -> *mut EVP_PKEY;

    pub(crate) fn EVP_PKEY_CTX_free(ctx: *mut EVP_PKEY_CTX);

    pub(crate) fn EVP_PKEY_CTX_new(pkey: *mut EVP_PKEY, e: *mut ENGINE) -> *mut EVP_PKEY_CTX;

    pub(crate) fn EVP_PKEY_free(pkey: *mut EVP_PKEY);

}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub(crate) struct HMAC_CTX {
    pub(crate) md: *const EVP_MD,
    pub(crate) md_ctx: EVP_MD_CTX,
    pub(crate) i_ctx: EVP_MD_CTX,
    pub(crate) o_ctx: EVP_MD_CTX,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub(crate) struct EVP_MD_CTX {
    pub(crate) digest: *const EVP_MD,
    pub(crate) md_data: *mut c_void,
    pub(crate) pctx: *mut EVP_PKEY_CTX,
    pub(crate) pctx_ops: *const evp_md_pctx_ops,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub(crate) struct evp_md_pctx_ops {
    _unused: [u8; 0],
}
pub(crate) const RSA_PKCS1_PADDING: i32 = 1;
pub(crate) const RSA_NO_PADDING: i32 = 3;
pub(crate) const RSA_PKCS1_OAEP_PADDING: i32 = 4;
pub(crate) const RSA_PKCS1_PSS_PADDING: i32 = 6;

unsafe extern "C" {
    pub(crate) fn EVP_md5() -> *const EVP_MD;

    pub(crate) fn EVP_sha1() -> *const EVP_MD;

    pub(crate) fn EVP_sha224() -> *const EVP_MD;

    pub(crate) fn EVP_sha256() -> *const EVP_MD;

    pub(crate) fn EVP_sha384() -> *const EVP_MD;

    pub(crate) fn EVP_sha512() -> *const EVP_MD;

    pub(crate) fn EVP_sm3() -> *const EVP_MD;

    pub(crate) fn HMAC_CTX_new() -> *mut HMAC_CTX;

    pub(crate) fn HMAC_CTX_free(ctx: *mut HMAC_CTX);

    pub(crate) fn EVP_MD_CTX_new() -> *mut EVP_MD_CTX;

    pub(crate) fn EVP_MD_CTX_free(ctx: *mut EVP_MD_CTX);

    pub(crate) fn EVP_PKEY_CTX_set_rsa_padding(ctx: *mut EVP_PKEY_CTX, padding: c_int) -> c_int;

    pub(crate) fn EVP_PKEY_CTX_set_rsa_mgf1_md(ctx: *mut EVP_PKEY_CTX, md: *const EVP_MD) -> c_int;

    pub(crate) fn EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx: *mut EVP_PKEY_CTX, salt_len: c_int) -> c_int;

    pub(crate) fn EVP_MD_CTX_copy_ex(
        out: *mut EVP_MD_CTX,
        in_: *const EVP_MD_CTX,
    ) -> c_int;

    pub(crate) fn HMAC_Init_ex(
        ctx: *mut HMAC_CTX,
        key: *const c_void,
        key_len: usize,
        md: *const EVP_MD,
        impl_: *mut ENGINE,
    ) -> c_int;

    pub(crate) fn HMAC_Update(
        ctx: *mut HMAC_CTX,
        data: *const u8,
        data_len: usize,
    ) -> c_int;

    pub(crate) fn HMAC_Final(
        ctx: *mut HMAC_CTX,
        out: *mut u8,
        out_len: *mut c_uint,
    ) -> c_int;

    pub(crate) fn EVP_DigestInit_ex(
        ctx: *mut EVP_MD_CTX,
        type_: *const EVP_MD,
        engine: *mut ENGINE,
    ) -> c_int;

    pub(crate) fn EVP_DigestUpdate(
        ctx: *mut EVP_MD_CTX,
        data: *const c_void,
        len: usize,
    ) -> c_int;

    pub(crate) fn EVP_DigestFinal_ex(
        ctx: *mut EVP_MD_CTX,
        md_out: *mut u8,
        out_size: *mut c_uint,
    ) -> c_int;

    pub(crate) fn EVP_Digest(
        data: *const c_void,
        len: usize,
        md_out: *mut u8,
        md_out_size: *mut c_uint,
        type_: *const EVP_MD,
        impl_: *mut ENGINE,
    ) -> c_int;

    pub(crate) fn EVP_DigestSignInit(
        ctx: *mut EVP_MD_CTX,
        pctx: *mut *mut EVP_PKEY_CTX,
        type_: *const EVP_MD,
        e: *mut ENGINE,
        pkey: *mut EVP_PKEY,
    ) -> c_int;

    pub(crate) fn EVP_DigestSign(
        ctx: *mut EVP_MD_CTX,
        out_sig: *mut u8,
        out_sig_len: *mut usize,
        data: *const u8,
        data_len: usize,
    ) -> c_int;

    pub(crate) fn EVP_DigestVerifyInit(
        ctx: *mut EVP_MD_CTX,
        pctx: *mut *mut EVP_PKEY_CTX,
        type_: *const EVP_MD,
        e: *mut ENGINE,
        pkey: *mut EVP_PKEY,
    ) -> c_int;

    pub(crate) fn EVP_DigestVerify(
        ctx: *mut EVP_MD_CTX,
        sig: *const u8,
        sig_len: usize,
        data: *const u8,
        len: usize,
    ) -> c_int;

    pub(crate) fn PKCS5_PBKDF2_HMAC(
        password: *const c_char,
        password_len: usize,
        salt: *const u8,
        salt_len: usize,
        iterations: u32,
        digest: *const EVP_MD,
        key_len: usize,
        out_key: *mut u8,
    ) -> c_int;
}