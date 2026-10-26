use std::fmt::{Debug, Display};

#[repr(C)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct H2FrameType(u8);

#[allow(non_upper_case_globals)]
impl H2FrameType {
    pub const Data: H2FrameType = H2FrameType::new(0x00);
    pub const Headers: H2FrameType = H2FrameType::new(0x01);
    pub const Priority: H2FrameType = H2FrameType::new(0x02);
    pub const RstStream: H2FrameType = H2FrameType::new(0x03);
    pub const Settings: H2FrameType = H2FrameType::new(0x04);
    pub const PushPromise: H2FrameType = H2FrameType::new(0x05);
    pub const Ping: H2FrameType = H2FrameType::new(0x06);
    pub const Goaway: H2FrameType = H2FrameType::new(0x07);
    pub const WindowUpdate: H2FrameType = H2FrameType::new(0x08);
    pub const Continuation: H2FrameType = H2FrameType::new(0x09);
}


impl H2FrameType {
    pub const fn new(val: u8) -> H2FrameType {
        H2FrameType(val)
    }
    pub const fn into_inner(self) -> u8 { self.0 }

    pub const fn inner(&self) -> u8 { self.0 }

    pub const fn spec(&self) -> &str {
        match *self {
            H2FrameType::Data => "Data",
            H2FrameType::Headers => "Headers",
            H2FrameType::Priority => "Priority",
            H2FrameType::RstStream => "RstStream",
            H2FrameType::Settings => "Settings",
            H2FrameType::PushPromise => "PushPromise",
            H2FrameType::Ping => "Ping",
            H2FrameType::Goaway => "Goaway",
            H2FrameType::WindowUpdate => "WindowUpdate",
            H2FrameType::Continuation => "Continuation",
            _ => "Unknown",
        }
    }
}

impl Debug for H2FrameType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}


impl Display for H2FrameType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}(0x({:02x}))", self.spec(), self.inner())
    }
}