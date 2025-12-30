use std::time::Duration;
use json::JsonValue;
use crate::error::HlsError;

pub struct Timeout {
    //连接超时
    connect: Duration,
    //读取超时，单次
    read: Duration,
    //写出超时，单次
    write: Duration,
    //处理超时，总超时
    handle: Duration,

    //连接尝试次数
    connect_times: i32,
    //处理次数
    handle_times: i32,
}

impl Timeout {
    pub fn new() -> Timeout {
        Timeout {
            connect: Duration::from_secs(3),
            read: Duration::from_secs(3),
            write: Duration::from_secs(3),
            handle: Duration::from_secs(30),
            connect_times: 3,
            handle_times: 3,
        }
    }

    pub fn is_peer_closed(&self, status: impl AsRef<str>) -> bool {
        let close_status = vec!["broken pipe", "reset by peer", "peer close", "关闭"];
        let status = status.as_ref().to_lowercase();
        close_status.into_iter().find(|x| status.contains(x)).is_some()
    }

    pub fn connect(&self) -> Duration {
        self.connect
    }

    pub fn read(&self) -> Duration {
        self.read
    }

    pub fn write(&self) -> Duration {
        self.write
    }

    pub fn handle(&self) -> Duration {
        self.handle
    }

    pub fn connect_times(&self) -> i32 {
        self.connect_times
    }

    pub fn handle_times(&self) -> i32 {
        self.handle_times
    }

    pub fn set_connect(&mut self, connect: u64) {
        self.connect = Duration::from_secs(connect);
    }

    pub fn set_read(&mut self, read: u64) {
        self.read = Duration::from_secs(read);
    }

    pub fn set_write(&mut self, write: u64) {
        self.write = Duration::from_secs(write);
    }

    pub fn set_handle(&mut self, handle: u64) {
        self.handle = Duration::from_secs(handle);
    }

    pub fn set_connect_times(&mut self, connect_times: i32) {
        self.connect_times = connect_times;
    }

    pub fn set_handle_times(&mut self, handle_times: i32) {
        self.handle_times = handle_times;
    }
}

impl TryFrom<JsonValue> for Timeout {
    type Error = HlsError;
    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        Ok(Timeout {
            connect: Duration::from_secs(value["connect"].as_u64()?),
            read:Duration::from_secs(value["read"].as_u64()?),
            write:Duration::from_secs(value["write"].as_u64()?),
            handle:Duration::from_secs(value["handle"].as_u64()?),
            connect_times:value["connect_times"].as_i32()?,
            handle_times:value["handle_times"].as_i32()?,
        })
    }
}