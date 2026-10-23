use std::ffi::CString;
use std::os::raw::c_char;
use std::sync::LazyLock;
use crate::error::HlsResult;
use crate::HlsError;

mod req;
mod wss;

static CONVERT_ERROR: LazyLock<CString> = LazyLock::new(|| unsafe { CString::from_vec_unchecked(b"convert error fail".to_vec()) });

static BUILTIN:&[u8]=include_bytes!("../../builtin.dat");


fn handle_err1<T, E: ToString>(e: E, err: *mut *mut c_char, t: T) -> T {
    let ce = CString::new(e.to_string().replace("\0", "")).unwrap_or_else(|_| CONVERT_ERROR.clone());
    unsafe { *err = ce.into_raw(); }
    t
}

fn handle_err2<E: ToString>(e: E) -> *mut c_char {
    let ce = CString::new(e.to_string().replace("\0", "")).unwrap_or_else(|_| CONVERT_ERROR.clone());
    ce.into_raw()
}

fn check_run<T>(mut func: impl FnMut() -> HlsResult<T>, handle: impl Fn(HlsError) -> T) -> T {
    func().unwrap_or_else(handle)
}
























