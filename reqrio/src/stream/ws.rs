use std::io;
use crate::body::Body;
use crate::error::HlsResult;
use crate::ext::ReqPriExt;
use crate::stream::Stream;
use crate::*;

pub struct WebSocketBuilder<S: ReqExt>(S);

impl<S: ReqExt> WebSocketBuilder<S> {
    pub fn with_proxy(mut self, proxy: Proxy) -> WebSocketBuilder<S> {
        self.0.set_proxy(proxy);
        self
    }

    pub fn set_proxy(&mut self, proxy: Proxy) {
        self.0.set_proxy(proxy);
    }

    pub fn with_origin(mut self, origin: impl ToString) -> HlsResult<WebSocketBuilder<S>> {
        self.0.header_mut().set_origin(origin)?;
        Ok(self)
    }

    pub fn with_cookie(mut self, cookie: impl AsRef<str>) -> HlsResult<WebSocketBuilder<S>> {
        self.0.header_mut().set_cookie(cookie)?;
        Ok(self)
    }

    pub fn with_user_agent(mut self, user_agent: impl ToString) -> HlsResult<WebSocketBuilder<S>> {
        self.0.header_mut().set_user_agent(user_agent)?;
        Ok(self)
    }

    pub fn with_header(mut self, key: impl AsRef<str>, val: impl ToString) -> HlsResult<WebSocketBuilder<S>> {
        self.add_header(key, val)?;
        Ok(self)
    }

    pub fn add_header(&mut self, key: impl AsRef<str>, val: impl ToString) -> HlsResult<()> {
        self.0.header_mut().insert(key, val)
    }

    pub fn set_uri(&mut self, uri: impl TryInto<Uri>) -> Result<(), RlsError> {
        self.0.header_mut().set_uri(uri.try_into().map_err(|_| UrlError::ParseUriError)?);
        Ok(())
    }

    pub fn with_uri(mut self, uri: impl TryInto<Uri>) -> HlsResult<WebSocketBuilder<S>> {
        self.set_uri(uri)?;
        Ok(self)
    }
}

impl WebSocketBuilder<ScReq> {
    pub fn build(mut self, url: &Url) -> HlsResult<WebSocket> {
        self.0.re_conn(Some(url))?;
        WebSocket::add_header(self.0.header_mut())?;
        Ok(WebSocket::new(WebSocket::connect_sync(self.0, url)?))
    }
}

#[cfg(feature = "aync")]
impl WebSocketBuilder<AcReq> {
    pub async fn build(mut self, url: &Url) -> HlsResult<WebSocket> {
        self.0.re_conn(Some(url)).await?;
        WebSocket::add_header(self.0.header_mut())?;
        Ok(WebSocket::new(WebSocket::connect_async(self.0).await?))
    }
}


#[cfg_attr(feature = "export", repr(C))]
pub struct WebSocket {
    stream: Stream,
    buffer: Buffer,
}

impl WebSocket {
    fn add_header(headers: &mut Header) -> HlsResult<()> {
        match headers.get_mut("Sec-WebSocket-Key") {
            None => headers.insert("Sec-WebSocket-Key", "3eGwJ19k4qUKxRPJZUNYLw==")?,
            Some(value) => if value.to_string() == "" { *value = HeaderValue::String("3eGwJ19k4qUKxRPJZUNYLw==".to_string()) }
        }
        match headers.get_mut("Connection") {
            None => headers.set_connection("Upgrade")?,
            Some(value) => if value.to_string() == "" { headers.set_connection("Upgrade")? }
        }
        match headers.get_mut("Sec-WebSocket-Version") {
            None => headers.insert("Sec-WebSocket-Version", "13")?,
            Some(value) => if value.to_string() == "" { *value = HeaderValue::String("13".to_string()) }
        }
        match headers.get_mut("Sec-WebSocket-Extensions") {
            None => headers.insert("Sec-WebSocket-Extensions", "permessage-deflate; client_max_window_bits")?,
            Some(value) => if value.to_string() == "" { *value = HeaderValue::String("permessage-deflate; client_max_window_bits".to_string()) }
        }
        match headers.get_mut("Upgrade") {
            None => headers.insert("Upgrade", "websocket")?,
            Some(value) => if value.to_string() == "" { *value = HeaderValue::String("websocket".to_string()) }
        }
        Ok(())
    }
}

impl WebSocket {
    fn new(stream: Stream) -> Self {
        WebSocket {
            stream,
            buffer: Buffer::with_capacity(0xFFFF),
        }
    }
}

impl WebSocket {
    pub fn sync_build() -> WebSocketBuilder<ScReq> {
        WebSocketBuilder(ScReq::new().with_timeout(Timeout::longer()))
    }


    fn connect_sync(mut req: ScReq, url: &Url) -> HlsResult<Stream> {
        let resp = req.handle_io(Method::GET, url, &Body::none())?;
        let status = resp.header().status();
        if status != &HttpStatus::SwitchingProtocols { return Err(format!("Connect fail with code-{}", status).into()); }
        Ok(req.into_stream())
    }

    pub fn open(url: impl AsRef<str>) -> HlsResult<WebSocket> {
        Self::sync_build().build(&Url::try_from(url.as_ref())?)
    }

    pub fn open_raw(url: impl AsRef<str>, context: impl AsRef<[u8]>) -> HlsResult<WebSocket> {
        let mut req = ScReq::new().with_timeout(Timeout::longer());
        req.req_param().buffer.write_slice(context.as_ref())?;
        Ok(WebSocket::new(Self::connect_sync(req, &Url::try_from(url.as_ref())?)?))
    }


    pub fn write_frame(&mut self, frame: WsFrame) -> io::Result<()> {
        self.stream.sync_write(&frame.to_bytes())
    }

    pub fn read_frame(&mut self) -> HlsResult<WsFrame> {
        if let Ok(frame) = WsFrame::from_buffer(&mut self.buffer) {
            return Ok(frame);
        }
        loop {
            self.stream.sync_read(&mut self.buffer)?;
            if let Ok(frame) = WsFrame::from_buffer(&mut self.buffer) {
                return Ok(frame);
            }
        }
    }

    pub fn shutdown(mut self) -> HlsResult<()> {
        self.stream.sync_shutdown()
    }
}

#[cfg(feature = "aync")]
impl WebSocket {
    pub fn async_build() -> WebSocketBuilder<AcReq> {
        WebSocketBuilder(AcReq::new().with_timeout(Timeout::longer()))
    }

    async fn connect_async(mut req: AcReq) -> HlsResult<Stream> {
        let resp = req.h1_io().await?;
        // println!("{}", resp.raw_string());
        let status = resp.header().status();
        if status != &HttpStatus::SwitchingProtocols { return Err(format!("Connect fail with code-{}", status).into()); }
        Ok(req.into_stream())
    }

    pub async fn open_async(url: impl AsRef<str>) -> HlsResult<WebSocket> {
        Self::async_build().build(&Url::try_from(url.as_ref())?).await
    }

    pub async fn open_async_raw(url: impl AsRef<str>, context: impl AsRef<[u8]>) -> HlsResult<WebSocket> {
        let mut req = AcReq::new().with_timeout(Timeout::longer());
        req.req_param().buffer.write_slice(context.as_ref())?;
        req.set_url(&Url::try_from(url.as_ref())?).await?;
        Ok(WebSocket::new(Self::connect_async(req).await?))
    }


    pub async fn async_write_frame(&mut self, frame: WsFrame) -> HlsResult<()> {
        self.stream.async_write(&frame.to_bytes()).await
    }

    pub async fn async_read_frame(&mut self) -> HlsResult<WsFrame> {
        if let Ok(frame) = WsFrame::from_buffer(&mut self.buffer) {
            return Ok(frame);
        }
        loop {
            self.stream.async_read(&mut self.buffer).await?;
            if let Ok(frame) = WsFrame::from_buffer(&mut self.buffer) {
                return Ok(frame);
            }
        }
    }

    pub async fn async_shutdown(mut self) -> HlsResult<()> {
        self.stream.async_shutdown().await
    }
}