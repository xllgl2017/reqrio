use crate::error::HlsResult;
use crate::{Fingerprint, Method, Proxy, ReqExt, ScReq, ALPN};
use std::collections::HashMap;
use std::ffi::{c_char, CStr, CString};
use std::sync::{LazyLock, Mutex};

static CONNECTIONS: LazyLock<Mutex<HashMap<i32, ScReq>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
fn unique_id() -> i32 {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let res = nanos << 8;
    (res as i32).abs()
}

#[unsafe(no_mangle)]
pub extern "system" fn init_http() -> i32 {
    || -> HlsResult<i32> {
        let id = unique_id();
        let sc = ScReq::new();
        let mut scs = CONNECTIONS.lock()?;
        scs.insert(id, sc);
        Ok(id)
    }().unwrap_or(-1)
}

#[unsafe(no_mangle)]
pub extern "system" fn set_header_json(id: i32, header: *const c_char) -> i32 {
    || -> HlsResult<i32> {
        let header = unsafe { CStr::from_ptr(header) }.to_str()?.to_string();
        let header = json::parse(header)?;
        let mut params = CONNECTIONS.lock()?;
        params.get_mut(&id).ok_or("id 不存在")?.set_headers_json(header)?;
        Ok(0)
    }().unwrap_or(-1)
}

#[unsafe(no_mangle)]
pub extern "system" fn add_header(id: i32, key: *const c_char, value: *const c_char) -> i32 {
    || -> HlsResult<i32> {
        let key = unsafe { CStr::from_ptr(key) }.to_str()?.to_string();
        let value = unsafe { CStr::from_ptr(value) }.to_str()?.to_string();
        let mut params = CONNECTIONS.lock()?;
        params.get_mut(&id).ok_or("id 不存在")?.header_mut().insert(key, value)?;
        Ok(0)
    }().unwrap_or(-1)
}

#[unsafe(no_mangle)]
pub extern "system" fn set_alpn(id: i32, alpn: *const c_char) -> i32 {
    || -> HlsResult<i32> {
        let alpn = unsafe { CStr::from_ptr(alpn) }.to_bytes();
        let alpn = ALPN::from_slice(alpn);
        let mut params = CONNECTIONS.lock()?;
        params.get_mut(&id).ok_or("id 不存在")?.set_alpn(alpn);
        Ok(0)
    }().unwrap_or(-1)
}

#[unsafe(no_mangle)]
pub extern "system" fn set_fingerprint(id: i32, fingerprint: *const c_char) -> i32 {
    || -> HlsResult<i32> {
        let fingerprint = unsafe { CStr::from_ptr(fingerprint) }.to_str()?.to_string();
        let fingerprint = Fingerprint::from_hex_all(fingerprint)?;
        let mut params = CONNECTIONS.lock()?;
        params.get_mut(&id).ok_or("id 不存在")?.set_fingerprint(fingerprint);
        Ok(0)
    }().unwrap_or(-1)
}

#[unsafe(no_mangle)]
pub extern "system" fn set_ja3(id: i32, ja3: *const c_char) -> i32 {
    || -> HlsResult<i32> {
        let ja3 = unsafe { CStr::from_ptr(ja3) }.to_str()?.to_string();
        let mut fingerprint = Fingerprint::default()?;
        fingerprint.set_ja3(&ja3)?;
        let mut params = CONNECTIONS.lock()?;
        params.get_mut(&id).ok_or("id 不存在")?.set_fingerprint(fingerprint);
        Ok(0)
    }().unwrap_or(-1)
}

#[unsafe(no_mangle)]
pub extern "system" fn set_proxy(id: i32, addr: *const c_char) -> i32 {
    || -> HlsResult<i32> {
        let addr = unsafe { CStr::from_ptr(addr) }.to_str()?.to_string();
        let proxy = Proxy::try_from(addr)?;
        let mut params = CONNECTIONS.lock()?;
        params.get_mut(&id).ok_or("id 不存在")?.set_proxy(proxy);
        Ok(0)
    }().unwrap_or(-1)
}

#[unsafe(no_mangle)]
pub extern "system" fn set_url(id: i32, url: *const c_char) -> i32 {
    || -> HlsResult<i32> {
        let url = unsafe { CStr::from_ptr(url) }.to_str()?.to_string();
        let mut params = CONNECTIONS.lock()?;
        params.get_mut(&id).ok_or("id 不存在")?.set_url(url)?;
        Ok(0)
    }().unwrap_or(-1)
}

#[unsafe(no_mangle)]
pub extern "system" fn add_param(id: i32, name: *const c_char, value: *const c_char) -> i32 {
    || -> HlsResult<i32> {
        let name = unsafe { CStr::from_ptr(name) }.to_str()?.to_string();
        let value = unsafe { CStr::from_ptr(value) }.to_str()?.to_string();
        let mut params = CONNECTIONS.lock()?;
        params.get_mut(&id).ok_or("id 不存在")?.add_param(&name, &value);
        Ok(0)
    }().unwrap_or(-1)
}

#[unsafe(no_mangle)]
pub extern "system" fn set_data(id: i32, data: *const c_char) -> i32 {
    || -> HlsResult<i32> {
        let data = unsafe { CStr::from_ptr(data) }.to_bytes();
        let data = json::from_bytes(data)?;
        let mut params = CONNECTIONS.lock()?;
        params.get_mut(&id).ok_or("id 不存在")?.set_data(data);
        Ok(0)
    }().unwrap_or(-1)
}

#[unsafe(no_mangle)]
pub extern "system" fn set_json(id: i32, data: *const c_char) -> i32 {
    || -> HlsResult<i32> {
        let data = unsafe { CStr::from_ptr(data) }.to_bytes();
        let data = json::from_bytes(data)?;
        let mut params = CONNECTIONS.lock()?;
        params.get_mut(&id).ok_or("id 不存在")?.set_json(data);
        Ok(0)
    }().unwrap_or(-1)
}


fn send(id: i32, method: Method) -> *mut c_char {
    let res = || -> HlsResult<String> {
        let mut acs = CONNECTIONS.lock()?;
        let mut ac = acs.remove(&id).ok_or("id  不存在")?;
        drop(acs);
        ac.header_mut().set_method(method);
        let resp = ac.stream_io()?;
        let res = json::object! {
            "header":resp.header(),
            "body":hex::encode(resp.decode_body()?),
        };
        let mut acs = CONNECTIONS.lock()?;
        acs.insert(id, ac);
        Ok(hex::encode(res.dump()))
    };
    match res() {
        Ok(res) => {
            println!("res: {}", res.len());
            CString::new(res).unwrap().into_raw()
        }
        Err(e) => {
            println!("{}", e.to_string());
            CString::new(hex::encode(e.to_string())).unwrap().into_raw()
        }
    }
}


#[unsafe(no_mangle)]
pub extern "system" fn get(id: i32) -> *mut c_char {
    send(id, Method::GET)
}


#[unsafe(no_mangle)]
pub extern "system" fn post(id: i32) -> *mut c_char {
    send(id, Method::POST)
}

#[unsafe(no_mangle)]
pub extern "system" fn options(id: i32) -> *mut c_char {
    send(id, Method::OPTIONS)
}

#[unsafe(no_mangle)]
pub extern "system" fn put(id: i32) -> *mut c_char {
    send(id, Method::PUT)
}

#[unsafe(no_mangle)]
pub extern "system" fn head(id: i32) -> *mut c_char {
    send(id, Method::HEAD)
}

#[unsafe(no_mangle)]
pub extern "system" fn delete(id: i32) -> *mut c_char {
    send(id, Method::DELETE)
}

#[unsafe(no_mangle)]
pub extern "system" fn trach(id: i32) -> *mut c_char {
    send(id, Method::TRACH)
}

#[unsafe(no_mangle)]
pub extern "C" fn destroy(id: i32) {
    if let Ok(mut acs) = CONNECTIONS.lock() {
        acs.remove(&id);
        println!("remove {}", id);
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn free_pointer(ptr: *mut c_char) {
    if ptr.is_null() { return; }
    unsafe { let _ = CString::from_raw(ptr); }
}