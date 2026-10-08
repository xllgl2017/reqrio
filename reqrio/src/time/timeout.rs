use crate::error::HlsError;
use crate::json::JsonValue;
#[cfg(feature = "aync")]
use std::pin::Pin;
#[cfg(feature = "aync")]
use std::task::{Context, Poll};
use std::time::Duration;
#[cfg(feature = "aync")]
use tokio::time::Sleep;
#[cfg(feature = "aync")]
use crate::TimeError;

pub struct Timeout {
    //连接超时
    #[cfg(feature = "aync")]
    connect_time: Option<Pin<Box<Sleep>>>,
    connect_timeout: Duration,
    //读取超时，单次
    #[cfg(feature = "aync")]
    read_time: Option<Pin<Box<Sleep>>>,
    read_timeout: Duration,
    //写出超时，单次
    #[cfg(feature = "aync")]
    write_time: Option<Pin<Box<Sleep>>>,
    write_timeout: Duration,
    //处理超时，总超时
    handle: Duration,
    //连接尝试次数
    connect_times: i32,
    //处理次数
    handle_times: i32,
}

impl Default for Timeout {
    fn default() -> Self {
        Timeout::new_same(3000, 3)
    }
}

impl Timeout {
    pub fn new_same(timeout: u64, handles: i32) -> Timeout {
        Timeout {
            #[cfg(feature = "aync")]
            connect_time: None,
            connect_timeout: Duration::from_millis(timeout),
            #[cfg(feature = "aync")]
            read_time: None,
            read_timeout: Duration::from_millis(timeout),
            #[cfg(feature = "aync")]
            write_time: None,
            write_timeout: Duration::from_millis(timeout),
            handle: Duration::from_millis(timeout),
            connect_times: handles,
            handle_times: handles,
        }
    }

    pub fn longer() -> Timeout {
        Timeout::new_same(u64::MAX, 3)
    }

    pub fn is_peer_closed(&self, status: impl AsRef<str>) -> bool {
        let close_status = vec!["broken pipe", "reset by peer", "关闭", "中止了", "close"];
        let status = status.as_ref().to_lowercase();
        close_status.into_iter().any(|x| status.contains(x))
    }

    pub fn connect(&self) -> Duration {
        self.connect_timeout
    }

    pub fn read(&self) -> Duration {
        self.read_timeout
    }

    pub fn write(&self) -> Duration {
        self.write_timeout
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

    pub fn set_connect(&mut self, millis: u64) {
        self.connect_timeout = Duration::from_millis(millis);
    }

    pub fn set_read(&mut self, millis: u64) {
        self.read_timeout = Duration::from_millis(millis);
    }

    pub fn set_write(&mut self, millis: u64) {
        self.write_timeout = Duration::from_millis(millis);
    }

    pub fn set_handle(&mut self, millis: u64) {
        self.handle = Duration::from_millis(millis);
    }

    pub fn set_connect_times(&mut self, connect_times: i32) {
        self.connect_times = connect_times;
    }

    pub fn set_handle_times(&mut self, handle_times: i32) {
        self.handle_times = handle_times;
        self.connect_times = handle_times;
    }

    #[cfg(feature = "aync")]
    pub fn read_timeout(&mut self, cx: &mut Context) -> Result<(), TimeError> {
        let Some(read_time) = self.read_time.as_mut() else { return Ok(()) };
        match read_time.as_mut().poll(cx) {
            Poll::Ready(_) => Err(TimeError::ReadTimeout),
            Poll::Pending => Ok(())
        }
    }

    #[cfg(feature = "aync")]
    pub fn write_timeout(&mut self, cx: &mut Context) -> Result<(), TimeError> {
        let Some(write_time) = self.write_time.as_mut() else { return Ok(()) };
        match write_time.as_mut().poll(cx) {
            Poll::Ready(_) => Err(TimeError::WriteTimeout),
            Poll::Pending => Ok(())
        }
    }

    #[cfg(feature = "aync")]
    pub fn connect_timeout(&mut self, cx: &mut Context) -> Result<(), TimeError> {
        let Some(connect_time) = self.connect_time.as_mut() else { return Ok(()) };
        match connect_time.as_mut().poll(cx) {
            Poll::Ready(_) => Err(TimeError::ConnectTimeout),
            Poll::Pending => Ok(())
        }
    }

    #[cfg(feature = "aync")]
    pub fn reset_read(&mut self) {
        self.read_time = Some(Box::pin(tokio::time::sleep(self.read_timeout)));
    }

    #[cfg(feature = "aync")]
    pub fn reset_write(&mut self) {
        self.write_time = Some(Box::pin(tokio::time::sleep(self.write_timeout)));
    }

    #[cfg(feature = "aync")]
    pub fn reset_connect(&mut self) {
        self.connect_time = Some(Box::pin(tokio::time::sleep(self.connect_timeout)));
    }
}

impl TryFrom<JsonValue> for Timeout {
    type Error = HlsError;
    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        let connect = Duration::from_millis(value["connect"].as_u64()?);
        let read = Duration::from_millis(value["read"].as_u64()?);
        let write = Duration::from_millis(value["write"].as_u64()?);
        Ok(Timeout {
            #[cfg(feature = "aync")]
            connect_time: None,
            connect_timeout: connect,
            #[cfg(feature = "aync")]
            read_time: None,
            read_timeout: read,
            #[cfg(feature = "aync")]
            write_time: None,
            write_timeout: write,
            handle: Duration::from_millis(value["handle"].as_u64()?),
            connect_times: value["connect_times"].as_i32()?,
            handle_times: value["handle_times"].as_i32()?,
        })
    }
}

impl Clone for Timeout {
    fn clone(&self) -> Self {
        Timeout {
            #[cfg(feature = "aync")]
            connect_time: None,
            connect_timeout: self.connect_timeout,
            #[cfg(feature = "aync")]
            read_time: None,
            read_timeout: self.read_timeout,
            #[cfg(feature = "aync")]
            write_time: None,
            write_timeout: self.write_timeout,
            handle: self.handle,
            connect_times: self.connect_times,
            handle_times: self.handle_times,
        }
    }
}