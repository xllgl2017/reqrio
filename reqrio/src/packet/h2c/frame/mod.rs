pub use flag::FrameFlag;
pub use typo::FrameType;

use setting::Setting;
mod setting;
mod typo;
mod flag;

use std::fmt::{Debug, Display, Formatter};
use std::ptr;
use crate::Buffer;
use crate::error::HlsResult;

#[derive(Clone, Debug)]
pub struct Frame {
    len: usize,
    frame_type: FrameType,
    flags: Vec<FrameFlag>,
    stream_identifier: u32,
    stream_dependency: u32,
    weight: u8,
    payload: Vec<u8>,
    settings: Vec<Setting>,
}

impl Display for Frame {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let s = format!("Frame {{ len: {}, frame_type: {:?}, flags: {:?}, stream_identifier: {}, stream_dependency: {}, weight: {}, settings: {:?} payload: {:?} }}",
                        self.len, self.frame_type, self.flags, self.stream_identifier, self.stream_dependency, self.weight, self.settings, if self.frame_type == FrameType::Data { vec![] } else { self.payload.clone() }
        );
        f.write_str(&s)
    }
}

impl Frame {
    pub fn none_frame() -> Frame {
        Frame {
            len: 0,
            frame_type: FrameType::Data,
            flags: vec![],
            stream_identifier: 0,
            stream_dependency: 0,
            weight: 0,
            payload: vec![],
            settings: vec![],
        }
    }

    pub fn from_bytes(buffer: &mut Buffer) -> HlsResult<Frame> {
        if buffer.len() < 9 { return Err("byte not enough".into()); }
        let len = u32::from_be_bytes([0, buffer[0], buffer[1], buffer[2]]) as usize;
        let frame_type = FrameType::from_u8(buffer[3])?;
        let flags = FrameFlag::from_u8(buffer[4]);
        let mut stream_identifier = u32::from_be_bytes(buffer[5..9].try_into()?);
        stream_identifier &= !2147483648;
        if buffer.len() < 9 + len { return Err("byte not enough".into()); }
        let (dependency, weight, payload_range) = if flags.contains(&FrameFlag::Priority) {
            (u32::from_be_bytes(buffer[9..13].try_into()?), buffer[13], 14..9 + len)
        } else {
            (0, 0, 9..9 + len)
        };
        let mut payload: Vec<u8> = Vec::with_capacity(payload_range.end - payload_range.start);
        unsafe {
            let dst = payload.as_mut_ptr().add(0);
            ptr::copy_nonoverlapping(buffer[payload_range].as_ptr(), dst, len);
            payload.set_len(len);
        }
        buffer.copy_within(9 + len..buffer.len(), 0);
        buffer.set_len(buffer.len() - len - 9);


        let mut settings = vec![];
        if frame_type == FrameType::Settings {
            let mut cl = 0;
            while cl < payload.len() {
                let setting = Setting::from_bytes(&payload[cl..cl + 6])?;
                settings.push(setting);
                cl += 6;
            }
        }


        Ok(Frame {
            len,
            frame_type,
            flags,
            stream_identifier,
            stream_dependency: dependency,
            weight,
            payload,
            settings,
        })
    }

    pub fn to_bytes(mut self) -> Vec<u8> {
        let mut res = (if self.flags.contains(&FrameFlag::Priority) { self.payload.len() + 5 } else { self.payload.len() } as u32).to_be_bytes()[1..].to_vec();
        res.push(self.frame_type.clone().to_u8());
        let mut flag = 0;
        let mut dep_bs = vec![];
        if self.flags.contains(&FrameFlag::EndStream) { flag |= 1; }
        if self.flags.contains(&FrameFlag::EndHeaders) { flag |= 4; }
        if self.flags.contains(&FrameFlag::Padded) { flag |= 8; }
        if self.flags.contains(&FrameFlag::Priority) {
            flag |= 32;
            self.stream_dependency |= 2147483648;
            dep_bs = self.stream_dependency.to_be_bytes().to_vec();

            dep_bs.push(self.weight);
        }
        res.push(flag);
        let stream_identifier = self.stream_identifier;
        res.extend(stream_identifier.to_be_bytes());
        res.extend(dep_bs);
        res.extend(self.payload);
        res
    }

    pub fn window_update() -> Frame {
        let mut frame = Frame::none_frame();
        frame.len = 4;
        frame.frame_type = FrameType::WindowUpdate;
        frame.flags.push(FrameFlag::ACK);
        frame.payload = vec![0, 239, 0, 1];
        frame
    }

    pub fn default_setting() -> Frame {
        let settings = Setting::default();
        let mut payload = vec![];
        for setting in &settings {
            payload.extend(setting.to_bytes());
        }
        Frame {
            len: payload.len(),
            frame_type: FrameType::Settings,
            flags: vec![FrameFlag::ACK],
            stream_identifier: 0,
            stream_dependency: 0,
            weight: 0,
            settings,
            payload,
        }
    }

    pub fn new_header(hdr_bs: Vec<u8>, body_len: usize, sid: u32) -> Frame {
        let mut res = Frame {
            len: hdr_bs.len(),
            frame_type: FrameType::Headers,
            flags: vec![FrameFlag::EndHeaders],
            stream_identifier: sid,
            stream_dependency: 0,
            weight: 0,
            payload: hdr_bs,
            settings: vec![],
        };
        if body_len == 0 { res.flags.push(FrameFlag::EndStream); }
        res
    }

    pub fn new_body(mut body: Vec<u8>, sid: u32) -> Vec<Frame> {
        if body.len() == 0 { return vec![]; }
        let max_len = u32::from_be_bytes([0, 255, 255, 255]) as usize;
        let mut res = vec![];
        loop {
            let pos = if body.len() >= max_len { max_len } else { body.len() };
            let payload = body[..pos].to_vec();
            res.push(Frame {
                len: payload.len(),
                frame_type: FrameType::Data,
                flags: vec![],
                stream_identifier: sid,
                stream_dependency: 0,
                weight: 0,
                payload,
                settings: vec![],
            });
            if pos >= body.len() { break; }
            body = body[pos..].to_vec();
        }
        if res.len() != 0 { res.last_mut().unwrap().flags.push(FrameFlag::EndStream); }
        res
    }

    pub fn flags(&self) -> &Vec<FrameFlag> {
        &self.flags
    }

    pub fn frame_type(&self) -> &FrameType {
        &self.frame_type
    }

    pub fn payload(&self) -> &Vec<u8> { &self.payload }
    pub fn to_payload(self) -> Vec<u8> { self.payload }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn frame_id(&self) -> u32 {
        self.stream_identifier
    }

    pub fn set_frame_type(&mut self, frame_type: FrameType) {
        self.frame_type = frame_type;
    }

    pub fn set_flags(&mut self, flags: Vec<FrameFlag>) {
        self.flags = flags;
    }

    pub fn set_weight(&mut self, weight: u8) {
        self.weight = weight;
    }

    pub fn add_flag(&mut self, flag: FrameFlag) {
        self.flags.push(flag);
    }

    pub fn set_stream_identifier(&mut self, stream_identifier: u32) {
        self.stream_identifier = stream_identifier;
    }

    pub fn stream_identifier(&self) -> u32 {
        self.stream_identifier
    }

    pub fn is_end_frame(&self) -> bool {
        self.flags.contains(&FrameFlag::EndStream) &&
            (self.frame_type == FrameType::Data || self.frame_type == FrameType::Headers)
    }
}