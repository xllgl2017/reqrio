#[cfg(feature = "quic")]
use crate::packet::{H3Frame, H3Setting};
use crate::*;
use std::ffi::CString;
#[cfg(debug_assertions)]
use std::fmt::Debug;
use std::os::raw::{c_char, c_int};
use std::ptr::null_mut;
use std::slice;
use std::sync::Arc;

unsafe extern "C" {
    fn Finger_build_h2(finger: *const Finger, writer: *mut Writer) -> c_int;
    #[cfg(feature = "quic")]
    fn Finger_build_h3(finger: *const Finger, writer: *mut Writer) -> c_int;
    fn get_compute_id() -> *const u8;
    fn Finger_get_builtin(name: *const u8, name_len: usize, finger: *mut Finger) -> c_int;
    fn Finger_get(idx: usize, auth: *const u8, auth_len: usize, finger: *mut Finger) -> c_int;
}


#[cfg_attr(debug_assertions, derive(Debug))]
pub struct H2Finger {
    ///setting frame
    pub frames: Vec<H2Frame<'static>>,
    ///weight
    pub weight: u8,
    ///priority
    pub priority: bool,
    pub adv: Option<Arc<Finger>>,
}

impl Default for H2Finger {
    fn default() -> Self {
        H2Finger {
            frames: vec![
                H2Frame::new_setting(vec![
                    H2Setting::HeaderTableSize(65536),
                    H2Setting::EnablePush(0),
                    H2Setting::InitialWindowSize(6291456),
                    H2Setting::MaxHeaderListSize(242144)
                ]),
                H2Frame::new_window_update(2147418112)
            ],
            weight: 147,
            priority: true,
            adv: None,
        }
    }
}

impl H2Finger {
    pub fn build_settings(&self, writer: &mut Writer) -> Result<(), BufferError> {
        if let Some(ref adv) = self.adv {
            let start = writer.end();
            let ret = unsafe { Finger_build_h2(adv.as_ref(), writer) };
            if ret != 1 { return Err(BufferError::InvalidCEncode); }
            if start != writer.end() { return Ok(()); }
        }
        for frame in self.frames.iter() {
            frame.write_to(writer)?;
        }
        Ok(())
    }

    pub fn add_frame(&mut self, frame: H2Frame<'static>) {
        self.frames.push(frame)
    }

    pub fn set_priority(&mut self, priority: bool, weight: u8) {
        self.priority = priority;
        self.weight = weight;
    }

    pub fn with_priority(mut self, priority: bool, weight: u8) -> Self {
        self.set_priority(priority, weight);
        self
    }
}


/// H3 frames; used only for the post-handshake `settings` stream.
#[cfg(feature = "quic")]
#[cfg_attr(debug_assertions, derive(Debug))]
pub struct H3Finger {
    pub frames: Vec<H3Frame<'static>>,
    pub adv: Option<Arc<Finger>>,
}

#[cfg(feature = "quic")]
impl H3Finger {
    pub fn build_settings(&self, writer: &mut Writer) -> Result<(), BufferError> {
        if let Some(ref adv) = self.adv {
            let start = writer.end();
            let ret = unsafe { Finger_build_h3(adv.as_ref(), writer) };
            if ret != 1 { return Err(BufferError::InvalidCEncode); }
            if start != writer.end() { return Ok(()); }
        }
        for frame in self.frames.iter() {
            frame.write_to(writer)?;
        }
        Ok(())
    }
}

#[cfg(feature = "quic")]
impl Default for H3Finger {
    fn default() -> Self {
        H3Finger {
            frames: vec![
                H3Frame::Settings(vec![
                    H3Setting::new(H3Setting::MaxTableCapacity, 65536),
                    H3Setting::new(H3Setting::MaxFieldSectionSize, 262144),
                    H3Setting::new(H3Setting::BlockedStreams, 100),
                    H3Setting::new(H3Setting::EnableDatagram, 1),
                    H3Setting::new(0x7c3b6e5b0, 4089453656)
                ]),
                H3Frame::Reserved {
                    typ: 0x11d4c4c93c,
                    payload: Buf::new_ref(&[0x54]),
                }
            ],
            adv: None,
        }
    }
}


#[cfg_attr(debug_assertions, derive(Debug))]
pub struct Fingerprint {
    tls: TlsFinger<'static>,
    h2: H2Finger,
    #[cfg(feature = "quic")]
    h3: H3Finger,
    /// Built-in fingerprints and VIP fingerprints.
    pub(crate) adv: Option<Arc<Finger>>,
    /// Whether to use the full `sec-*` request headers.
    pub(crate) sec_full: bool,
}

impl Fingerprint {
    pub fn from_idx<'a>(idx: usize, auth: &str, sec_full: bool) -> HlsResult<Fingerprint> {
        let mut finger = Finger {
            hdr_count: 0,
            hdr: null_mut(),
            _rsv: [0; 88],
        };
        let ret = unsafe { Finger_get(idx, auth.as_ptr(), auth.len(), &mut finger) };
        if ret != 1 { return Err("not subscribed or file not exists!".into()); }
        Ok(Fingerprint::from_adv(finger, sec_full))
    }

    pub fn from_builtin<'a>(name: &'static str, token: &str, sec_full: bool) -> HlsResult<Fingerprint> {
        Fingerprint::check_subscription(token);
        let mut finger = Finger {
            hdr_count: 0,
            hdr: null_mut(),
            _rsv: [0; 88],
        };
        let ret = unsafe { Finger_get_builtin(name.as_ptr(), name.len(), &mut finger) };
        if ret != 1 { return Err(format!("`{}` - not in builtin or not subscribed", name).into()); }
        Ok(Fingerprint::from_adv(finger, sec_full))
    }

    fn from_adv(finger: Finger, sec_full: bool) -> Fingerprint {
        let finger = Arc::new(finger);
        Fingerprint {
            tls: TlsFinger::Adv(finger.clone()),
            h2: H2Finger {
                adv: Some(finger.clone()),
                ..Default::default()
            },
            #[cfg(feature = "quic")]
            h3: H3Finger {
                adv: Some(finger.clone()),
                ..Default::default()
            },
            adv: Some(finger),
            sec_full,
        }
    }


    pub fn new_custom(record_version: Version, message_version: Version, token: impl AsRef<str>) -> Fingerprint {
        Fingerprint::check_subscription(token);
        Fingerprint {
            tls: TlsFinger::Custom {
                record_version,
                message_version,
                suites: vec![],
                extensions: vec![],
            },
            h2: H2Finger {
                frames: vec![],
                weight: 0,
                priority: false,
                adv: None,
            },
            #[cfg(feature = "quic")]
            h3: H3Finger {
                frames: vec![],
                adv: None,
            },
            adv: None,
            sec_full: false,
        }
    }

    pub fn new_h2(tls: TlsFinger<'static>, h2: H2Finger, token: impl AsRef<str>) -> HlsResult<Self> {
        Fingerprint::check_subscription(token);
        Ok(Fingerprint {
            tls,
            h2,
            #[cfg(feature = "quic")]
            h3: H3Finger::default(),
            adv: None,
            sec_full: false,
        })
    }

    #[cfg(feature = "quic")]
    pub fn new_h3(tls: TlsFinger<'static>, h3: H3Finger, token: impl AsRef<str>) -> HlsResult<Self> {
        Fingerprint::check_subscription(token);
        Ok(Fingerprint {
            tls,
            h2: H2Finger::default(),
            h3,
            adv: None,
            sec_full: false,
        })
    }

    pub fn new_tls(tls: TlsFinger<'static>, token: impl AsRef<str>) -> HlsResult<Self> {
        Fingerprint::check_subscription(token);
        Ok(Fingerprint {
            tls,
            ..Default::default()
        })
    }

    pub fn h2(&self) -> &H2Finger {
        &self.h2
    }

    pub fn h2_mut(&mut self) -> &mut H2Finger {
        &mut self.h2
    }

    pub fn tls(&self) -> &TlsFinger<'_> { &self.tls }

    pub fn tls_mut(&mut self) -> &mut TlsFinger<'static> { &mut self.tls }

    #[cfg(feature = "quic")]
    pub fn h3(&self) -> &H3Finger {
        &self.h3
    }

    #[cfg(feature = "quic")]
    pub fn h3_mut(&mut self) -> &mut H3Finger {
        &mut self.h3
    }

    pub fn compute_id() -> String {
        let id = unsafe { slice::from_raw_parts(get_compute_id(), 32) };
        hex::encode(id)
    }
}

impl Fingerprint {
    pub fn random(token: impl AsRef<str>) -> Fingerprint {
        Fingerprint::check_subscription(token);
        Fingerprint {
            tls: TlsFinger::random(),
            ..Default::default()
        }
    }

    ///client hello bytes prefix: [1, 0, .]
    pub fn from_client_hello(record_version: Version, ch: Vec<u8>, token: impl AsRef<str>) -> HlsResult<Fingerprint> {
        Fingerprint::check_subscription(token);
        Ok(Fingerprint {
            tls: TlsFinger::ClientHello { record_version, bytes: Buf::Vec(ch) },
            ..Default::default()
        })
    }

    ///record hex prefix: 220303
    pub fn from_record_hex(hex_str: impl AsRef<str>, token: impl AsRef<str>) -> HlsResult<Fingerprint> {
        Fingerprint::check_subscription(token);
        Ok(Fingerprint {
            tls: TlsFinger::from_record_hex(hex_str)?,
            ..Default::default()
        })
    }

    pub fn from_ja3(ja3: impl AsRef<str>, token: impl AsRef<str>) -> HlsResult<Fingerprint> {
        Fingerprint::check_subscription(token);
        Ok(Fingerprint {
            tls: TlsFinger::from_ja3(ja3)?,
            ..Default::default()
        })
    }

    pub fn from_ja4(ja4: impl AsRef<str>, token: impl AsRef<str>) -> HlsResult<Fingerprint> {
        Fingerprint::check_subscription(token);
        Ok(Fingerprint {
            tls: TlsFinger::from_ja4(ja4)?,
            ..Default::default()
        })
    }

    pub fn check_subscription(token: impl AsRef<str>) -> bool {
        unsafe extern "C" {
            fn is_subscription(token: *const c_char) -> bool;
        }
        let is_subscribed = unsafe {
            let token = CString::from_vec_unchecked(token.as_ref().to_string().into_bytes());
            is_subscription(token.as_ptr())
        };
        if !is_subscribed {
            println!("\x1b[01;33m[Fingerprint] WARN \x1b[0m You have not subscribed yet, so this call will be ignored.");
        }
        is_subscribed
    }
}

impl Default for Fingerprint {
    fn default() -> Fingerprint {
        Fingerprint {
            tls: TlsFinger::Default,
            h2: H2Finger::default(),
            #[cfg(feature = "quic")]
            h3: H3Finger::default(),
            adv: None,
            sec_full: false,
        }
    }
}