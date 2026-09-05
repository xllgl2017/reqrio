use std::array::TryFromSliceError;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::ops::Range;
use std::str::Utf8Error;

#[derive(Debug)]
pub enum BufferError {
    ///内容长度过小
    Insufficient,
    InvalidQUICVariant,
    CapacityTooSmall {
        needed: usize,
        current: usize,
        file: &'static str,
        line: u32,
    },
    Overflow { capacity: usize, len: usize, need: usize },
    IndexOutBound {
        index: usize,
        want: usize,
        size: usize,
    },
    RangeEdgeError(Range<usize>),
    Nullptr,
    ResizeFail {
        current: usize,
        at_least: usize,
        new: usize,
    },
    SliceConvertError(TryFromSliceError),
    Utf8Error(Utf8Error),
    UdpMsgTooLarge,
}

impl Display for BufferError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            BufferError::Insufficient => write!(f, "Insufficient decoding data"),
            BufferError::CapacityTooSmall {
                needed,
                current,
                file,
                line,
            } => write!(f, "The required capacity is {}, but the current capacity is {} at {}:{}.", needed, current, file, line),
            BufferError::Overflow { capacity, len, need } => write!(f, "The buffer capacity is {}, but write {} out of it.", capacity, len + need),
            BufferError::IndexOutBound { size, index, want } => write!(f, "The index {} out of bounds {} ", index + want, size),
            BufferError::RangeEdgeError(range) => write!(f, "The range is {:?} of Buffer is fail", range),
            BufferError::Nullptr => write!(f, "Nullptr"),
            BufferError::ResizeFail { current, new, at_least } => write!(f, "resize to {} fail from {}, need: {}", new, current, at_least),
            BufferError::InvalidQUICVariant => write!(f, "Invalid variant"),
            BufferError::SliceConvertError(er) => write!(f, "SliceConvertError({})", er),
            BufferError::Utf8Error(e) => write!(f, "Utf8Error({})", e),
            BufferError::UdpMsgTooLarge => write!(f, "udp msg must less then 1500"),
        }
    }
}

impl Error for BufferError {}

impl From<TryFromSliceError> for BufferError {
    fn from(value: TryFromSliceError) -> Self {
        BufferError::SliceConvertError(value)
    }
}

impl From<Utf8Error> for BufferError {
    fn from(value: Utf8Error) -> Self {
        BufferError::Utf8Error(value)
    }
}