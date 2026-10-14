use std::ops::{BitOr, BitOrAssign};
#[derive(Clone, Copy)]
pub struct H2FrameFlag(u8);


#[allow(non_upper_case_globals)]
impl H2FrameFlag {
    pub const Priority: H2FrameFlag = H2FrameFlag(0b0010_0000);
    pub const Padding: H2FrameFlag = H2FrameFlag(0b0000_1000);
    pub const EndHeader: H2FrameFlag = H2FrameFlag(0b0000_0100);
    pub const EndStream: H2FrameFlag = H2FrameFlag(0b0000_0001);
}

impl H2FrameFlag {
    pub const fn new(byte: u8) -> H2FrameFlag {
        H2FrameFlag(byte)
    }

    pub const fn into_inner(self) -> u8 {
        self.0
    }

    pub const fn priority(&self) -> bool {
        self.0 & H2FrameFlag::Priority.0 == 0b0010_0000
    }

    pub const fn padding(&self) -> bool {
        self.0 & H2FrameFlag::Padding.0 == 0b0000_1000
    }

    pub const fn end_header(&self) -> bool {
        self.0 & H2FrameFlag::EndHeader.0 == 0b0000_0100
    }

    pub const fn end_stream(&self) -> bool {
        self.0 & H2FrameFlag::EndStream.0 == 0b0000_0001
    }

    pub const fn inner(&self) -> u8 { self.0 }
}

#[cfg(debug_assertions)]
impl std::fmt::Debug for H2FrameFlag {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        if self.priority() {
            write!(fmt, "Priority")?
        }
        if self.padding() {
            write!(fmt, "|Padding")?
        }
        if self.end_header() {
            write!(fmt, "EndHeader")?
        }
        if self.end_stream() {
            write!(fmt, "EndStream")?
        }
        Ok(())
    }
}

impl BitOrAssign for H2FrameFlag {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl BitOr for H2FrameFlag {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        H2FrameFlag(self.0 | rhs.0)
    }
}