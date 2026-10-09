use std::os::raw::{c_char, c_int, c_long, c_uchar, c_uint, c_void};
use crate::boring::bindings::*;

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub(crate) struct openssl_method_common_st {
    pub(crate) references: c_int,
    pub(crate) is_static: c_char,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub(crate) struct RSA_METHOD {
    pub(crate) common: openssl_method_common_st,
    pub(crate) app_data: *mut c_void,
    pub(crate) init: Option<unsafe extern "C" fn(rsa: *mut RSA) -> c_int>,
    pub(crate) finish: Option<unsafe extern "C" fn(rsa: *mut RSA) -> c_int>,
    pub(crate) size: Option<unsafe extern "C" fn(rsa: *const RSA) -> usize>,
    pub(crate) sign: Option<
        unsafe extern "C" fn(
            type_: c_int,
            m: *const u8,
            m_length: c_uint,
            sigret: *mut u8,
            siglen: *mut c_uint,
            rsa: *const RSA,
        ) -> c_int,
    >,
    pub(crate) sign_raw: Option<
        unsafe extern "C" fn(
            rsa: *mut RSA,
            out_len: *mut usize,
            out: *mut u8,
            max_out: usize,
            in_: *const u8,
            in_len: usize,
            padding: c_int,
        ) -> c_int,
    >,
    pub(crate) decrypt: Option<
        unsafe extern "C" fn(
            rsa: *mut RSA,
            out_len: *mut usize,
            out: *mut u8,
            max_out: usize,
            in_: *const u8,
            in_len: usize,
            padding: c_int,
        ) -> c_int,
    >,
    pub(crate) private_transform: Option<
        unsafe extern "C" fn(
            rsa: *mut RSA,
            out: *mut u8,
            in_: *const u8,
            len: usize,
        ) -> c_int,
    >,
    pub(crate) flags: c_int,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub(crate) struct stack_st_void {
    _unused: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub(crate) struct CRYPTO_EX_DATA {
    pub(crate) sk: *mut stack_st_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
#[allow(non_camel_case_types)]
pub(crate) union CRYPTO_MUTEX {
    pub(crate) handle: *mut c_void,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(non_camel_case_types, non_snake_case)]
pub(crate) struct BN_MONT_CTX {
    pub(crate) RR: BIGNUM,
    pub(crate) N: BIGNUM,
    pub(crate) n0: [u64; 2usize],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub(crate) struct BN_BLINDING {
    _unused: [u8; 0],
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct __BindgenBitfieldUnit<Storage> {
    storage: Storage,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct RSA {
    _unused: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) struct BIGNUM {
    pub(crate) d: *mut u64,
    pub(crate) width: c_int,
    pub(crate) dmax: c_int,
    pub(crate) neg: c_int,
    pub(crate) flags: c_int,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub(crate) struct BN_GENCB {
    pub(crate) arg: *mut c_void,
    pub(crate) callback: Option<
        unsafe extern "C" fn(
            event: c_int,
            n: c_int,
            arg1: *mut BN_GENCB,
        ) -> c_int,
    >,
}

#[allow(non_camel_case_types)]
pub(crate) type bio_info_cb = Option<
    unsafe extern "C" fn(
        bio: *mut BIO,
        event: c_int,
        parg: *const c_char,
        cmd: c_int,
        larg: c_long,
        return_value: c_long,
    ) -> c_long,
>;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub(crate) struct BIO_METHOD {
    _unused: [u8; 0],
}

#[allow(non_camel_case_types)]
pub(crate) type pem_password_cb = Option<
    unsafe extern "C" fn(
        buf: *mut c_char,
        size: c_int,
        rwflag: c_int,
        userdata: *mut c_void,
    ) -> c_int,
>;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub(crate) struct BIO {
    _unused: [u8; 0],
}

pub(crate) const RSA_F4: i32 = 65537;
pub(crate) const MBSTRING_ASC: i32 = 4097;
#[allow(non_upper_case_globals)]
pub(crate) const NID_basic_constraints: i32 = 87;
#[allow(non_upper_case_globals)]
pub(crate) const NID_key_usage: i32 = 83;
#[allow(non_upper_case_globals)]
pub(crate) const NID_subject_key_identifier: i32 = 82;
#[allow(non_upper_case_globals)]
pub(crate) const NID_ext_key_usage: i32 = 126;
#[allow(non_upper_case_globals)]
pub(crate) const NID_subject_alt_name: i32 = 85;
#[allow(non_upper_case_globals)]
pub(crate) const NID_info_access: i32 = 177;
#[allow(non_upper_case_globals)]
pub(crate) const NID_ad_ca_issuers: i32 = 179;

pub(crate) const X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT: i32 = 2;

pub(crate) const X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY: i32 = 20;

pub(crate) const GEN_URI: i32 = 6;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct X509 {
    _unused: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub(crate) struct OPENSSL_STACK {
    _unused: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct X509_STORE {
    _unused: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub(crate) struct X509_STORE_CTX {
    _unused: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub(crate) struct stack_st_X509 {
    _unused: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub(crate) struct ASN1_INTEGER {
    pub(crate) length: c_int,
    pub(crate) type_: c_int,
    pub(crate) data: *mut c_uchar,
    pub(crate) flags: c_long,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub(crate) struct ASN1_TIME {
    pub(crate) length: c_int,
    pub(crate) type_: c_int,
    pub(crate) data: *mut c_uchar,
    pub(crate) flags: c_long,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub(crate) struct X509_NAME {
    _unused: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub(crate) struct X509_REQ {
    _unused: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub(crate) struct X509_CRL {
    _unused: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub(crate) struct CONF {
    _unused: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub(crate) struct X509V3_CTX {
    pub(crate) flags: c_int,
    pub(crate) issuer_cert: *const X509,
    pub(crate) subject_cert: *const X509,
    pub(crate) subject_req: *const X509_REQ,
    pub(crate) crl: *const X509_CRL,
    pub(crate) db: *const CONF,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub(crate) struct X509_EXTENSION {
    _unused: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub(crate) struct AUTHORITY_INFO_ACCESS {
    _unused: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub(crate) struct ASN1_OBJECT {
    _unused: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub(crate) struct ACCESS_DESCRIPTION {
    pub(crate) method: *mut ASN1_OBJECT,
    pub(crate) location: *mut GENERAL_NAME,
}

#[repr(C)]
#[derive(Copy, Clone)]
#[allow(non_camel_case_types)]
pub(crate) struct GENERAL_NAME {
    pub(crate) type_: c_int,
    pub(crate) d: GENERAL_NAME_st__bindgen_ty_1,
}

#[repr(C)]
#[derive(Copy, Clone)]
#[allow(non_camel_case_types)]
pub(crate) struct ASN1_TYPE;

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) struct OTHERNAME {
    pub(crate) type_id: *mut ASN1_OBJECT,
    pub(crate) value: *mut ASN1_TYPE,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub(crate) struct ASN1_IA5STRING {
    pub(crate) length: c_int,
    pub(crate) type_: c_int,
    pub(crate) data: *mut c_uchar,
    pub(crate) flags: c_long,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub(crate) struct ASN1_STRING {
    pub(crate) length: c_int,
    pub(crate) type_: c_int,
    pub(crate) data: *mut c_uchar,
    pub(crate) flags: c_long,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
pub(crate) struct EDIPARTYNAME {
    pub(crate) nameAssigner: *mut ASN1_STRING,
    pub(crate) partyName: *mut ASN1_STRING,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub(crate) struct ASN1_OCTET_STRING {
    pub(crate) length: c_int,
    pub(crate) type_: c_int,
    pub(crate) data: *mut c_uchar,
    pub(crate) flags: c_long,
}

#[repr(C)]
#[derive(Copy, Clone)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
pub(crate) union GENERAL_NAME_st__bindgen_ty_1 {
    pub(crate) ptr: *mut c_char,
    pub(crate) otherName: *mut OTHERNAME,
    pub(crate) rfc822Name: *mut ASN1_IA5STRING,
    pub(crate) dNSName: *mut ASN1_IA5STRING,
    pub(crate) x400Address: *mut ASN1_STRING,
    pub(crate) directoryName: *mut X509_NAME,
    pub(crate) ediPartyName: *mut EDIPARTYNAME,
    pub(crate) uniformResourceIdentifier: *mut ASN1_IA5STRING,
    pub(crate) iPAddress: *mut ASN1_OCTET_STRING,
    pub(crate) registeredID: *mut ASN1_OBJECT,
    pub(crate) ip: *mut ASN1_OCTET_STRING,
    pub(crate) dirn: *mut X509_NAME,
    pub(crate) ia5: *mut ASN1_IA5STRING,
    pub(crate) rid: *mut ASN1_OBJECT,
}

unsafe extern "C" {
    pub(crate) fn RSA_new() -> *mut RSA;

    pub(crate) fn RSA_free(rsa: *mut RSA);

    pub(crate) fn BN_new() -> *mut BIGNUM;

    pub(crate) fn BN_free(bn: *mut BIGNUM);

    pub(crate) fn BIO_new(method: *const BIO_METHOD) -> *mut BIO;

    pub(crate) fn BIO_new_mem_buf(buf: *const c_void, len: isize) -> *mut BIO;

    pub(crate) fn BIO_free(bio: *mut BIO) -> c_int;

    pub(crate) fn BIO_s_mem() -> *const BIO_METHOD;

    pub(crate) fn BN_set_word(bn: *mut BIGNUM, value: u64) -> c_int;

    pub(crate) fn EVP_PKEY_assign_RSA(pkey: *mut EVP_PKEY, key: *mut RSA) -> c_int;

    pub(crate) fn BIO_get_mem_data(bio: *mut BIO, contents: *mut *mut c_char) -> c_long;

    pub(crate) fn PEM_write_bio_PUBKEY(bp: *mut BIO, x: *mut EVP_PKEY) -> c_int;

    pub(crate) fn i2d_PrivateKey(key: *const EVP_PKEY, outp: *mut *mut u8) -> c_int;

    pub(crate) fn i2d_PUBKEY(pkey: *const EVP_PKEY, outp: *mut *mut u8) -> c_int;

    pub(crate) fn EVP_PKEY_encrypt_init(ctx: *mut EVP_PKEY_CTX) -> c_int;

    pub(crate) fn EVP_PKEY_decrypt_init(ctx: *mut EVP_PKEY_CTX) -> c_int;

    pub(crate) fn X509_get_pubkey(x509: *const X509) -> *mut EVP_PKEY;

    pub(crate) fn X509_new() -> *mut X509;

    pub(crate) fn X509_free(x509: *mut X509);

    pub(crate) fn i2d_X509(x509: *const X509, outp: *mut *mut u8) -> c_int;

    pub(crate) fn X509_set_version(x509: *mut X509, version: c_long) -> c_int;

    pub(crate) fn sk_new_null() -> *mut OPENSSL_STACK;

    pub(crate) fn sk_push(sk: *mut OPENSSL_STACK, p: *mut c_void) -> usize;

    pub(crate) fn sk_free(sk: *mut OPENSSL_STACK);

    pub(crate) fn sk_num(sk: *const OPENSSL_STACK) -> usize;

    pub(crate) fn sk_value(sk: *const OPENSSL_STACK, i: usize) -> *mut c_void;

    pub(crate) fn X509_STORE_new() -> *mut X509_STORE;

    pub(crate) fn X509_STORE_add_cert(ctx: *mut X509_STORE, x: *mut X509) -> c_int;

    pub(crate) fn X509_STORE_free(v: *mut X509_STORE);

    pub(crate) fn X509_STORE_CTX_new() -> *mut X509_STORE_CTX;

    pub(crate) fn X509_STORE_CTX_free(ctx: *mut X509_STORE_CTX);

    pub(crate) fn X509_verify_cert(ctx: *mut X509_STORE_CTX) -> c_int;

    pub(crate) fn X509_STORE_CTX_get_error(ctx: *const X509_STORE_CTX) -> c_int;

    pub(crate) fn X509_verify_cert_error_string(err: c_long) -> *const c_char;

    pub(crate) fn ASN1_INTEGER_new() -> *mut ASN1_INTEGER;

    pub(crate) fn ASN1_INTEGER_free(str_: *mut ASN1_INTEGER);

    pub(crate) fn ASN1_INTEGER_set(a: *mut ASN1_INTEGER, v: c_long) -> c_int;

    pub(crate) fn X509_set_serialNumber(x509: *mut X509, serial: *const ASN1_INTEGER) -> c_int;

    pub(crate) fn X509_gmtime_adj(s: *mut ASN1_TIME, offset_sec: c_long) -> *mut ASN1_TIME;

    pub(crate) fn X509_get_notBefore(x509: *const X509) -> *mut ASN1_TIME;

    pub(crate) fn X509_get_notAfter(x509: *const X509) -> *mut ASN1_TIME;

    pub(crate) fn X509_set_pubkey(x509: *mut X509, pkey: *mut EVP_PKEY) -> c_int;

    pub(crate) fn X509_NAME_new() -> *mut X509_NAME;

    pub(crate) fn X509_NAME_free(name: *mut X509_NAME);

    pub(crate) fn X509_set_subject_name(x509: *mut X509, name: *const X509_NAME) -> c_int;

    pub(crate) fn X509_get_subject_name(x509: *const X509) -> *mut X509_NAME;

    pub(crate) fn X509_set_issuer_name(x509: *mut X509, name: *const X509_NAME) -> c_int;

    pub(crate) fn X509_EXTENSION_free(ex: *mut X509_EXTENSION);

    pub(crate) fn X509_add_ext(x: *mut X509, ex: *const X509_EXTENSION, loc: c_int) -> c_int;

    pub(crate) fn X509_sign(x509: *mut X509, pkey: *mut EVP_PKEY, md: *const EVP_MD) -> c_int;

    pub(crate) fn PEM_write_bio_X509(bp: *mut BIO, x: *mut X509) -> c_int;

    pub(crate) fn AUTHORITY_INFO_ACCESS_free(a: *mut AUTHORITY_INFO_ACCESS);

    pub(crate) fn OBJ_obj2nid(obj: *const ASN1_OBJECT) -> c_int;

    pub(crate) fn ASN1_STRING_get0_data(str_: *const ASN1_STRING) -> *const c_uchar;

    pub(crate) fn ASN1_STRING_length(str_: *const ASN1_STRING) -> c_int;

    pub(crate) unsafe fn EVP_PKEY_id(pkey: *const EVP_PKEY) -> c_int;

    pub(crate) fn RSA_generate_key_ex(
        rsa: *mut RSA,
        bits: c_int,
        e: *const BIGNUM,
        cb: *mut BN_GENCB,
    ) -> c_int;

    pub(crate) fn PEM_write_bio_PrivateKey(
        bp: *mut BIO,
        x: *mut EVP_PKEY,
        enc: *const EVP_CIPHER,
        kstr: *mut c_uchar,
        klen: c_int,
        cb: pem_password_cb,
        u: *mut c_void,
    ) -> c_int;

    pub(crate) fn EVP_PKEY_encrypt(
        ctx: *mut EVP_PKEY_CTX,
        out: *mut u8,
        out_len: *mut usize,
        in_: *const u8,
        in_len: usize,
    ) -> c_int;

    pub(crate) fn EVP_PKEY_decrypt(
        ctx: *mut EVP_PKEY_CTX,
        out: *mut u8,
        out_len: *mut usize,
        in_: *const u8,
        in_len: usize,
    ) -> c_int;

    pub(crate) fn PEM_read_bio_PUBKEY(
        bp: *mut BIO,
        x: *mut *mut EVP_PKEY,
        cb: pem_password_cb,
        u: *mut c_void,
    ) -> *mut EVP_PKEY;

    pub(crate) fn d2i_AutoPrivateKey(
        out: *mut *mut EVP_PKEY,
        inp: *mut *const u8,
        len: c_long,
    ) -> *mut EVP_PKEY;

    pub(crate) fn d2i_PUBKEY(
        out: *mut *mut EVP_PKEY,
        inp: *mut *const u8,
        len: c_long,
    ) -> *mut EVP_PKEY;

    pub(crate) fn PEM_read_bio_PrivateKey(
        bp: *mut BIO,
        x: *mut *mut EVP_PKEY,
        cb: pem_password_cb,
        u: *mut c_void,
    ) -> *mut EVP_PKEY;

    pub(crate) fn PEM_read_bio_X509(
        bp: *mut BIO,
        x: *mut *mut X509,
        cb: pem_password_cb,
        u: *mut c_void,
    ) -> *mut X509;

    pub(crate) fn d2i_X509(
        out: *mut *mut X509,
        inp: *mut *const u8,
        len: c_long,
    ) -> *mut X509;

    pub(crate) fn X509_check_host(
        x: *const X509,
        chk: *const c_char,
        chklen: usize,
        flags: c_uint,
        peername: *mut *mut c_char,
    ) -> c_int;

    pub(crate) fn X509_STORE_CTX_init(
        ctx: *mut X509_STORE_CTX,
        store: *mut X509_STORE,
        x509: *mut X509,
        chain: *mut stack_st_X509,
    ) -> c_int;

    pub(crate) fn X509_NAME_add_entry_by_txt(
        name: *mut X509_NAME,
        field: *const c_char,
        type_: c_int,
        bytes: *const u8,
        len: isize,
        loc: c_int,
        set: c_int,
    ) -> c_int;

    pub(crate) fn X509V3_EXT_nconf_nid(
        conf: *const CONF,
        ctx: *const X509V3_CTX,
        ext_nid: c_int,
        value: *const c_char,
    ) -> *mut X509_EXTENSION;

    pub(crate) fn BN_bin2bn(
        in_: *const u8,
        len: usize,
        ret: *mut BIGNUM,
    ) -> *mut BIGNUM;

    pub(crate) fn BN_to_ASN1_INTEGER(
        bn: *const BIGNUM,
        ai: *mut ASN1_INTEGER,
    ) -> *mut ASN1_INTEGER;

    pub(crate) fn RSA_set0_key(
        rsa: *mut RSA,
        n: *mut BIGNUM,
        e: *mut BIGNUM,
        d: *mut BIGNUM,
    ) -> c_int;

    pub(crate) unsafe fn X509_get_ext_d2i(
        x509: *const X509,
        nid: c_int,
        out_critical: *mut c_int,
        out_idx: *mut c_int,
    ) -> *mut c_void;

    pub(crate) fn X509_sm2_pub_key(
        cert: *const u8,
        cert_len: usize,
        pubkey: *mut *mut u8,
        pubkey_len: *mut usize,
        key_usage: *mut u16,
    ) -> c_int;
}