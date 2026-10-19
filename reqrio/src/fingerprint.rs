use std::borrow::Cow;
use std::ffi::CString;
use std::fmt::Debug;
use std::os::raw::c_char;
use crate::*;
#[cfg(feature = "quic")]
use crate::packet::{H3Frame, H3Setting};

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct H2Finger {
    ///setting frame
    pub frames: Vec<H2Frame<'static>>,
    ///weight
    pub weight: u8,
    ///priority
    pub priority: bool,
}

impl Default for H2Finger {
    fn default() -> Self {
        H2Finger {
            frames: vec![
                H2Frame::new_setting(Cow::Owned(vec![
                    H2Setting::HeaderTableSize(65536),
                    H2Setting::EnablePush(0),
                    H2Setting::InitialWindowSize(6291456),
                    H2Setting::MaxHeaderListSize(242144)
                ])),
                H2Frame::new_window_update(2147418112)
            ],
            weight: 147,
            priority: true,
        }
    }
}

impl H2Finger {
    pub fn build_setting(&self, writer: &mut Writer) -> Result<(), BufferError> {
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


///h3帧，仅用于握手后`setting stream`
#[cfg(feature = "quic")]
#[cfg_attr(debug_assertions, derive(Debug))]
pub struct H3Finger {
    pub frames: Vec<H3Frame<'static>>,
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
            ]
        }
    }
}

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct Fingerprint {
    tls: TlsFinger<'static>,
    h2: H2Finger,
    #[cfg(feature = "quic")]
    h3: H3Finger,
}

impl Fingerprint {
    pub fn new_custom(token: impl AsRef<str>) -> Fingerprint {
        Fingerprint::check_subscription(token);
        Fingerprint {
            tls: TlsFinger::Custom {
                record_version: Version::TLS_1_0,
                message_version: Version::TLS_1_2,
                suites: vec![],
                extensions: vec![],
            },
            h2: H2Finger {
                frames: vec![],
                weight: 0,
                priority: false,
            },
            #[cfg(feature = "quic")]
            h3: H3Finger {
                frames: vec![]
            },
        }
    }

    pub fn new_h2(tls: TlsFinger<'static>, h2: H2Finger, token: impl AsRef<str>) -> HlsResult<Self> {
        Fingerprint::check_subscription(token);
        Ok(Fingerprint {
            tls,
            h2,
            #[cfg(feature = "quic")]
            h3: H3Finger::default(),
        })
    }

    #[cfg(feature = "quic")]
    pub fn new_h3(tls: TlsFinger<'static>, h3: H3Finger, token: impl AsRef<str>) -> HlsResult<Self> {
        Fingerprint::check_subscription(token);
        Ok(Fingerprint {
            tls,
            h2: H2Finger::default(),
            h3,
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

    pub fn check_subscription(token: impl AsRef<str>) {
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
    }
}

impl Default for Fingerprint {
    fn default() -> Fingerprint {
        Fingerprint {
            tls: TlsFinger::Default,
            h2: H2Finger::default(),
            #[cfg(feature = "quic")]
            h3: H3Finger::default(),
        }
    }
}