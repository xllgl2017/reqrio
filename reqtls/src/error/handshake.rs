use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum HandShakeError {
    ClockSlow,
    ClockFast,
    PollWhileFinish,
    HasherNone(String),
}

impl Display for HandShakeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            HandShakeError::ClockSlow => write!(f, "the clock is slow"),
            HandShakeError::ClockFast => write!(f, "the clock is fast"),
            HandShakeError::HasherNone(hasher) => write!(f, "unsupported hasher-{}", hasher),
            HandShakeError::PollWhileFinish => write!(f, "call poll while in finish"),
        }
    }
}