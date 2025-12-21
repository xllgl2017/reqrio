use crate::error::HlsResult;

#[derive(Clone, Debug)]
pub enum Setting {
    SettingsHeaderTableSize(u32),
    SettingsEnablePush(u32),
    SettingsMaxConcurrentStreams(u32),
    SettingsInitialWindowSize(u32),
    SettingsMaxFrameSize(u32),
    SettingsMaxHeaderListSize(u32),
}

impl Setting {
    pub(crate) fn from_bytes(context: &[u8]) -> HlsResult<Setting> {
        let k = u16::from_be_bytes([context[0], context[1]]);
        Ok(match k {
            0x1 => Setting::SettingsHeaderTableSize(u32::from_be_bytes(context[2..6].try_into()?)),
            0x2 => Setting::SettingsEnablePush(u32::from_be_bytes(context[2..6].try_into()?)),
            0x3 => Setting::SettingsMaxConcurrentStreams(u32::from_be_bytes(context[2..6].try_into()?)),
            0x4 => Setting::SettingsInitialWindowSize(u32::from_be_bytes(context[2..6].try_into()?)),
            0x5 => Setting::SettingsMaxFrameSize(u32::from_be_bytes(context[2..6].try_into()?)),
            0x6 => Setting::SettingsMaxHeaderListSize(u32::from_be_bytes(context[2..6].try_into()?)),
            _ => return Err(format!("frame byte error: {:?}", context).into()),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Setting::SettingsHeaderTableSize(v) => {
                let mut res = 0x1u16.to_be_bytes().to_vec();
                res.extend(v.to_be_bytes());
                res
            }
            Setting::SettingsEnablePush(v) => {
                let mut res = 0x2u16.to_be_bytes().to_vec();
                res.extend(v.to_be_bytes());
                res
            }
            Setting::SettingsMaxConcurrentStreams(v) => {
                let mut res = 0x3u16.to_be_bytes().to_vec();
                res.extend(v.to_be_bytes());
                res
            }
            Setting::SettingsInitialWindowSize(v) => {
                let mut res = 0x4u16.to_be_bytes().to_vec();
                res.extend(v.to_be_bytes());
                res
            }
            Setting::SettingsMaxFrameSize(v) => {
                let mut res = 0x5u16.to_be_bytes().to_vec();
                res.extend(v.to_be_bytes());
                res
            }
            Setting::SettingsMaxHeaderListSize(v) => {
                let mut res = 0x6u16.to_be_bytes().to_vec();
                res.extend(v.to_be_bytes());
                res
            }
        }
    }

    pub fn default() -> Vec<Setting> {
        vec![
            Setting::SettingsHeaderTableSize(65535),
            Setting::SettingsEnablePush(0),
            Setting::SettingsInitialWindowSize(6291456),
            Setting::SettingsMaxHeaderListSize(242144)
        ]
    }
}