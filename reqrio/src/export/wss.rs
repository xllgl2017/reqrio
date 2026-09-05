use crate::error::HlsResult;
use crate::*;
use std::ffi::{c_char, CStr, CString};
use std::ptr::null_mut;


#[unsafe(no_mangle)]
pub extern "system" fn ws_open(url: *const c_char, hdr: *const c_char) -> *mut WebSocket {
    || -> HlsResult<*mut WebSocket>{
        let header = json::from_bytes(unsafe { CStr::from_ptr(hdr).to_bytes() })?;
        let url = unsafe { CStr::from_ptr(url).to_str()? };
        let mut req = ScReq::new().with_header_json(header)?;
        let resp = req.get(url, None)?;
        let ws = WebSocket::new(resp, req.into_stream()?)?;
        Ok(Box::into_raw(Box::new(ws)))
    }().unwrap_or_else(|e| {
        println!("{}", e);
        null_mut()
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn ws_open_raw(url: *const c_char, context: *const c_char) -> *mut WebSocket {
    || -> HlsResult<*mut WebSocket>{
        let url = unsafe { CStr::from_ptr(url) }.to_str()?;
        let context = unsafe { CStr::from_ptr(context) }.to_bytes();
        let mut buffer = Writer::with_capacity(16469);
        let mut stream = ScReq::new().connect(url)?.into_stream()?;
        buffer.write_slice(context)?;
        stream.write(&mut buffer).wait()?;
        let mut resp = Response::new();
        loop {
            stream.read(&mut buffer).wait()?;
            if resp.extend_buffer(&mut buffer)? { break; };
        }
        let ws = WebSocket::new_with_buffer(resp, stream, buffer)?;
        Ok(Box::into_raw(Box::new(ws)))
    }().unwrap_or(null_mut())
}

#[unsafe(no_mangle)]
pub extern "system" fn ws_read(websocket: *mut WebSocket) -> *mut c_char {
    || -> HlsResult<*mut c_char>{
        let websocket = unsafe { websocket.as_mut() }.ok_or(HlsError::NullPointer)?;
        let frame = websocket.read_frame().wait()?;
        let res = json::object! {
            "opcode":*frame.frame_type().op_code() as u8,
            "payload":frame.payload().as_bytes(),
        };
        let res = CString::new(res.dump()).unwrap();
        Ok(res.into_raw())
    }().unwrap_or_else(|e| {
        let res = CString::new(e.to_string()).unwrap();
        res.into_raw()
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn ws_write(websocket: *mut WebSocket, op_code: i32, payload: *const c_char) -> i32 {
    || -> HlsResult<i32> {
        let websocket = unsafe { websocket.as_mut() }.ok_or(HlsError::NullPointer)?;
        let payload = unsafe { CStr::from_ptr(payload) }.to_bytes();
        websocket.send_frame((op_code as u8).into(), payload).wait()?;
        Ok(0)
    }().unwrap_or(-1)
}

#[unsafe(no_mangle)]
pub extern "system" fn ws_close(websocket: *mut WebSocket) {
    println!("{}", websocket.is_null());
    if websocket.is_null() { return; }
    let mut websocket = unsafe { Box::from_raw(websocket) };
    let _ = websocket.shutdown().wait();
}