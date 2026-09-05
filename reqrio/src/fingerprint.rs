use std::fmt::Debug;
use crate::*;
use crate::packet::{H2EncodeFrame};
#[cfg(feature = "quic")]
use crate::packet::{H3Frame, H3Setting};

#[derive(Debug)]
pub struct H2Finger {
    ///SETTING
    pub setting: Vec<H2Setting>,
    ///WINDOW UPDATE: window size increment
    pub window_size: u32,
    ///weight
    pub weight: u8,
    ///priority
    pub priority: bool,
}

impl Default for H2Finger {
    fn default() -> Self {
        H2Finger {
            setting: vec![
                H2Setting::HeaderTableSize(65536),
                H2Setting::EnablePush(0),
                H2Setting::InitialWindowSize(6291456),
                H2Setting::MaxHeaderListSize(242144)
            ],
            window_size: 2147418112,
            weight: 147,
            priority: true,
        }
    }
}

impl H2Finger {
    pub fn build_setting(&self) -> H2EncodeFrame<'_> {
        H2EncodeFrame::new_setting(&self.setting)
    }

    pub fn build_window_update(&self) -> H2EncodeFrame<'_> {
        H2EncodeFrame::new_window_update(&self.window_size)
    }

    pub fn add_setting(&mut self, setting: H2Setting) {
        self.setting.push(setting);
    }

    pub fn set_window_size(&mut self, window_size: u32) {
        self.window_size = window_size;
    }

    pub fn set_priority(&mut self, priority: bool, weight: u8) {
        self.priority = priority;
        self.weight = weight;
    }
}

#[cfg(feature = "quic")]
///h3帧，仅用于握手后`setting stream`
#[derive(Debug)]
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
                    payload: Buf::Ref(&[0x54]),
                }
            ]
        }
    }
}

#[derive(Debug)]
pub struct Fingerprint {
    tls: TlsFinger,
    h2: H2Finger,
    #[cfg(feature = "quic")]
    h3: H3Finger,
    legal_subscript: i32,
}

impl Fingerprint {
    pub fn new_custom(token: impl AsRef<str>) -> Fingerprint {
        Fingerprint {
            tls: TlsFinger::Custom {
                record_version: Version::TLS_1_0,
                message_version: Version::TLS_1_2,
                suites: vec![],
                extensions: vec![],
            },
            h2: H2Finger {
                setting: vec![],
                window_size: 0,
                weight: 0,
                priority: false,
            },
            #[cfg(feature = "quic")]
            h3: H3Finger {
                frames: vec![]
            },
            legal_subscript: Writer::check_subscription(token).unwrap_or(-2),
        }
    }

    pub fn new_h2(tls: TlsFinger, h2: H2Finger, token: impl AsRef<str>) -> HlsResult<Self> {
        Ok(Fingerprint {
            tls,
            h2,
            #[cfg(feature = "quic")]
            h3: H3Finger::default(),
            legal_subscript: Writer::check_subscription(token)?,
        })
    }

    #[cfg(feature = "quic")]
    pub fn new_h3(tls: TlsFinger, h3: H3Finger, token: impl AsRef<str>) -> HlsResult<Self> {
        Ok(Fingerprint {
            tls,
            h2: H2Finger::default(),
            h3,
            legal_subscript: Writer::check_subscription(token)?,
        })
    }

    pub fn new_tls(tls: TlsFinger, token: impl AsRef<str>) -> HlsResult<Self> {
        Ok(Fingerprint {
            tls,
            legal_subscript: Writer::check_subscription(token)?,
            ..Default::default()
        })
    }

    pub fn h2(&self) -> &H2Finger {
        &self.h2
    }

    pub fn h2_mut(&mut self) -> &mut H2Finger {
        &mut self.h2
    }

    pub fn legal_subscript(&self) -> i32 {
        self.legal_subscript
    }

    pub fn tls(&self) -> &TlsFinger { &self.tls }

    pub fn tls_mut(&mut self) -> &mut TlsFinger { &mut self.tls }

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
        Fingerprint {
            tls: TlsFinger::random(),
            legal_subscript: Writer::check_subscription(token).unwrap_or(-2),
            ..Default::default()
        }
    }

    ///client hello bytes prefix: [1, 0, .]
    pub fn from_client_hello(record_version: Version, ch: Vec<u8>, token: impl AsRef<str>) -> HlsResult<Fingerprint> {
        Ok(Fingerprint {
            tls: TlsFinger::ClientHello { record_version, bytes: Bytes::new(ch) },
            legal_subscript: Writer::check_subscription(token)?,
            ..Default::default()
        })
    }

    ///record hex prefix: 220303
    pub fn from_record_hex(hex_str: impl AsRef<str>, token: impl AsRef<str>) -> HlsResult<Fingerprint> {
        Ok(Fingerprint {
            tls: TlsFinger::from_record_hex(hex_str)?,
            legal_subscript: Writer::check_subscription(token)?,
            ..Default::default()
        })
    }

    pub fn from_ja3(ja3: impl AsRef<str>, token: impl AsRef<str>) -> HlsResult<Fingerprint> {
        Ok(Fingerprint {
            tls: TlsFinger::from_ja3(ja3)?,
            legal_subscript: Writer::check_subscription(token)?,
            ..Default::default()
        })
    }

    pub fn from_ja4(ja4: impl AsRef<str>, token: impl AsRef<str>) -> HlsResult<Fingerprint> {
        Ok(Fingerprint {
            tls: TlsFinger::from_ja4(ja4)?,
            legal_subscript: Writer::check_subscription(token)?,
            ..Default::default()
        })
    }
}

impl Default for Fingerprint {
    fn default() -> Fingerprint {
        Fingerprint {
            tls: TlsFinger::Default,
            h2: H2Finger::default(),
            #[cfg(feature = "quic")]
            h3: H3Finger::default(),
            legal_subscript: -2,
        }
    }
}