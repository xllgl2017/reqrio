#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FrameFlag {
    ACK,
    EndStream,
    EndHeaders,
    Padded,
    Priority,
}

impl FrameFlag {
    pub fn from_u8(byte: u8) -> Vec<FrameFlag> {
        let mut res = vec![];
        if byte & 1 == 1 { res.push(FrameFlag::EndStream); }
        if byte & 4 == 4 { res.push(FrameFlag::EndHeaders); }
        if byte & 8 == 8 { res.push(FrameFlag::Padded); }
        if byte & 32 == 32 { res.push(FrameFlag::Priority); }
        if byte == 0 { res.push(FrameFlag::ACK); }
        res
    }
}