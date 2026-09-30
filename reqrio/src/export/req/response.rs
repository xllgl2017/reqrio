use crate::export::{check_run, handle_err1, CONVERT_ERROR};
use crate::{json, HlsError, Response};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr::{null, null_mut};

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn Response_status_code(resp: *const Response, err: *mut *mut c_char) -> u16 {
    check_run(move || {
        let resp = unsafe { resp.as_ref() }.ok_or(HlsError::NullPointer)?;
        Ok(resp.status().code())
    }, |e| handle_err1(e, err, 0))
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn Response_sid(resp: *const Response, err: *mut *mut c_char) -> u64 {
    check_run(move || {
        let resp = unsafe { resp.as_ref() }.ok_or(HlsError::NullPointer)?;
        Ok(resp.sid)
    }, |e| handle_err1(e, err, 0))
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn Response_bytes(resp: *const Response, len: &mut usize, err: *mut *mut c_char) -> *const u8 {
    check_run(move || {
        let resp = unsafe { resp.as_ref() }.ok_or(HlsError::NullPointer)?;
        let res = resp.as_bytes();
        *len = res.len();
        Ok(res.as_ptr())
    }, |e| handle_err1(e, err, null()))
}
#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn Response_header_keys(resp: *const Response, err: *mut *mut c_char) -> *mut c_char {
    check_run(move || {
        let resp = unsafe { resp.as_ref() }.ok_or(HlsError::NullPointer)?;
        let keys=resp.header().keys().iter().map(|x|x.name()).collect::<Vec<&str>>();
        Ok(CString::new(keys.join(",,,,"))?.into_raw())
    }, |e| handle_err1(e, err, null_mut()))
}


#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn Response_get_header(resp: *const Response, name: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    check_run(move || {
        let resp = unsafe { resp.as_ref() }.ok_or(HlsError::NullPointer)?;
        let name = unsafe { CStr::from_ptr(name) }.to_str()?;
        let value = resp.header().get(name).ok_or(format!("not found header by key `{}`", name))?;
        let res = CString::new(value.to_string()).unwrap_or_else(|_| CONVERT_ERROR.clone());
        Ok(res.into_raw())
    }, |e| handle_err1(e, err, null_mut()))
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn Response_cookies(resp: *const Response, err: *mut *mut c_char) -> *mut c_char {
    check_run(move || {
        let resp = unsafe { resp.as_ref() }.ok_or(HlsError::NullPointer)?;
        let mut res = json::array![];
        if let Some(cookies) = resp.header().cookies() {
            for cookie in cookies {
                res.push(cookie)
            }
        }
        match CString::new(res.dump()) {
            Ok(res) => Ok(res.into_raw()),
            Err(_) => Ok(CONVERT_ERROR.clone().into_raw())
        }
    }, |e| handle_err1(e, err, null_mut()))
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn Response_drop(resp: *mut Response) {
    if resp.is_null() { return; }
    let resp = unsafe { Box::from_raw(resp) };
    drop(resp);
}