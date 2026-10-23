mod finger;
mod response;
mod body;

use crate::export::{check_run, handle_err1, handle_err2, BUILTIN};
use crate::time::Timeout;
use crate::*;
use crate::Fingerprint;
use std::ffi::{c_char, CStr, CString};
use std::fs;
use std::ops::{Deref};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr::{null, null_mut};
use crate::stream::StreamMessage;

#[cfg(feature = "log")]
const LOGER: Logger = Logger {
    module: &[],
    debug_file: None,
    info_file: None,
    warn_file: None,
    error_file: None,
    out_file: None,
};

#[unsafe(no_mangle)]
#[cfg(feature = "log")]
pub extern "system" fn init_log(level: LevelFilter) {
    let _ = set_logger(&LOGER);
    set_max_level(level);
}

#[unsafe(no_mangle)]
#[cfg(feature = "log")]
pub extern "system" fn set_max_log_level(level: LevelFilter) {
    set_max_level(level);
}


#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_new(ignore_hdr_sort: bool) -> *mut ScReq {
    let mut sc = ScReq::new();
    sc.ignore_order = ignore_hdr_sort;
    Box::into_raw(Box::new(sc))
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_set_header_json(req: *mut ScReq, header: *const c_char) -> *mut c_char {
    check_run(move || {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        let header = unsafe { CStr::from_ptr(header) }.to_bytes();
        let header = json::from_bytes(header)?;
        req.set_headers_json(header);
        Ok(null_mut())
    }, handle_err2)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_add_header(req: *mut ScReq, key: *const c_char, value: *const c_char, reversed: bool) -> *mut c_char {
    check_run(move || {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        let name = unsafe { CStr::from_ptr(key) }.to_str()?;
        let value = unsafe { CStr::from_ptr(value) }.to_str()?;
        let key = HeaderItem::new(name, value).with_reserved(reversed);
        ReqExt::header_mut(req).add_item(key);
        Ok(null_mut())
    }, handle_err2)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_remove_header(req: *mut ScReq, key: *const c_char) -> *mut c_char {
    check_run(move || {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        let key = unsafe { CStr::from_ptr(key) }.to_str()?;
        req.remove_header(key);
        Ok(null_mut())
    }, handle_err2)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_set_alpn(req: *mut ScReq, alpn: *const c_char) -> *mut c_char {
    check_run(move || {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        let alpn = unsafe { CStr::from_ptr(alpn) }.to_bytes();
        let alpn = ALPN::from_slice(alpn);
        req.set_alpn(alpn);
        Ok(null_mut())
    }, handle_err2)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_set_verify(req: *mut ScReq, verify: bool) -> *mut c_char {
    check_run(move || {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        req.set_verify(verify);
        Ok(null_mut())
    }, handle_err2)
}


#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_set_redirect(req: *mut ScReq, redirect: bool) -> *mut c_char {
    check_run(move || {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        req.set_auto_redirect(redirect);
        Ok(null_mut())
    }, handle_err2)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_set_key_log(req: *mut ScReq, key_log: *const c_char) -> *mut c_char {
    check_run(move || {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        let key_log = unsafe { CStr::from_ptr(key_log) }.to_str()?;
        req.set_key_log(key_log);
        Ok(null_mut())
    }, handle_err2)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_set_fingerprint(req: *mut ScReq, fingerprint: *mut Fingerprint) -> *mut c_char {
    check_run(move || {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        req.set_fingerprint(unsafe { *Box::from_raw(fingerprint) });
        Ok(null_mut())
    }, handle_err2)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_with_builtin(req: *mut ScReq, name: *const c_char, token: *const c_char) -> *mut c_char {
    check_run(move || {
        if !fs::exists("builtin.dat")? {
            fs::write("builtin.dat", BUILTIN)?;
        }
        let req = unsafe { req.as_mut() }.ok_or(HlsError::NullPointer)?;
        let name = unsafe { CStr::from_ptr(name) }.to_str()?;
        let token = unsafe { CStr::from_ptr(token) }.to_str()?;
        Fingerprint::check_subscription(token);
        let (headers, fingerprint) = Fingerprint::from_builtin(name)?;
        for (name, value) in headers {
            req.insert_header(name, value);
        }
        req.set_fingerprint(fingerprint);
        Ok(null_mut())
    }, handle_err2)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_with_finger_idx(req: *mut ScReq, idx: usize, auth: *const c_char) -> *mut c_char {
    check_run(move || {
        let req = unsafe { req.as_mut() }.ok_or(HlsError::NullPointer)?;
        let auth = unsafe { CStr::from_ptr(auth) }.to_str()?;
        let (headers, fingerprint) = Fingerprint::from_idx(idx, auth)?;
        for (name, value) in headers {
            req.insert_header(name, value);
        }
        req.set_fingerprint(fingerprint);
        Ok(null_mut())
    }, handle_err2)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_set_proxy(req: *mut ScReq, addr: *const c_char) -> *mut c_char {
    check_run(move || {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        let addr = unsafe { CStr::from_ptr(addr) }.to_str()?.to_string();
        let proxy = Proxy::try_from(addr)?;
        req.set_proxy(proxy);
        Ok(null_mut())
    }, handle_err2)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_set_timeout(req: *mut ScReq, timeout: *const c_char) -> *mut c_char {
    check_run(move || {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        let timeout = unsafe { CStr::from_ptr(timeout) }.to_bytes();
        let data = json::from_bytes(timeout)?;
        let timeout = Timeout::try_from(data)?;
        req.set_timeout(timeout);
        Ok(null_mut())
    }, handle_err2)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_set_cookie(req: *mut ScReq, cookie: *const c_char) -> *mut c_char {
    check_run(move || {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        let cookie = unsafe { CStr::from_ptr(cookie) }.to_str()?;
        ReqExt::header_mut(req).set_cookie(cookie);
        Ok(null_mut())
    }, handle_err2)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_add_cookie(req: *mut ScReq, name: *const c_char, value: *const c_char) -> *mut c_char {
    check_run(move || {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        let name = unsafe { CStr::from_ptr(name) }.to_str()?;
        let value = unsafe { CStr::from_ptr(value) }.to_str()?;
        let cookie = Cookie::new_cookie(name, value);
        ReqExt::header_mut(req).add_cookie(cookie);
        Ok(null_mut())
    }, handle_err2)
}


///注意: 流式请求返回的是引用
#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ScReq_do_http(
    req: *mut ScReq,
    method: Method,
    url: *mut Url,
    body: *mut Body<'static>,
    stream: bool,
    err: *mut *mut c_char,
) -> *mut Response {
    catch_unwind(AssertUnwindSafe(|| {
        check_run(move || {
            let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
            let url = unsafe { Box::from_raw(url) };
            let body = unsafe { Box::from_raw(body) };
            let resp = match stream {
                true => {
                    let resp = req.send_stream(method, *url, *body)?;
                    resp as *const StreamMessage as *mut Response
                }
                false => Box::into_raw(Box::new(req.do_http(method, *url, body.deref())?))
            };
            Ok(resp)
        }, |e| handle_err1(e, err, null_mut()))
    })).unwrap_or_else(|_| handle_err1("程序panic", err, null_mut()))
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_recv_stream(req: *mut ScReq, sid: u64, len: *mut usize, err: *mut *mut c_char) -> *const u8 {
    catch_unwind(AssertUnwindSafe(move || {
        check_run(move || {
            let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
            match req.next_chunk(sid)? {
                Some(chunk) => {
                    unsafe { *len = chunk.len(); }
                    Ok(chunk.as_ptr())
                }
                None => Ok(null())
            }
        }, |e| handle_err1(e, err, null()))
    })).unwrap_or_else(|_| handle_err1("程序崩溃", err, null()))
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_reconnect(req: *mut ScReq) -> *mut c_char {
    catch_unwind(AssertUnwindSafe(|| {
        check_run(move || {
            let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
            req.re_conn(None)?;
            Ok(null_mut())
        }, handle_err2)
    })).unwrap_or_else(|_| handle_err2("程序panic"))
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_connect(req: *mut ScReq, url: *const c_char, sni: *const c_char) -> *mut c_char {
    catch_unwind(AssertUnwindSafe(|| {
        check_run(move || {
            let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
            let mut url: Url = unsafe { CStr::from_ptr(url) }.to_str()?.try_into()?;
            if !sni.is_null() && let Ok(sni) = unsafe { CStr::from_ptr(sni) }.to_str() {
                url.set_domain(sni);
            }
            req.re_conn(Some(&url))?;
            Ok(null_mut())
        }, handle_err2)
    })).unwrap_or_else(|_| handle_err2("程序panic"))
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn ScReq_close_stream(req: *mut ScReq) -> *mut c_char {
    check_run(move || {
        let req = unsafe { req.as_mut() }.ok_or(HlsError::NullPointer)?;
        let _ = req.http_stream_mut().stream_mut().and_then(|stream| stream.shutdown().wait());
        Ok(null_mut())
    }, handle_err2)
}


#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn ScReq_drop(req: *mut ScReq) {
    if req.is_null() { return; }
    let mut req = unsafe { Box::from_raw(req) };
    let _ = req.http_stream_mut().stream_mut().and_then(|stream| stream.shutdown().wait());
    drop(req);
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn char_free(ptr: *mut c_char) {
    if ptr.is_null() { return; }
    unsafe { let _ = CString::from_raw(ptr); }
}












