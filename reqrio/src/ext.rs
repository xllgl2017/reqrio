use json::JsonValue;
use crate::{coder, Proxy, ALPN};
#[cfg(use_cls)]
use reqtls::Fingerprint;
use crate::body::BodyType;
use crate::error::HlsResult;
use crate::file::HttpFile;
use crate::packet::*;
use crate::timeout::Timeout;
use crate::url::Url;

pub trait ReqExt: Sized {
    fn body_type(&self) -> &BodyType;
    fn body_type_mut(&mut self) -> &mut BodyType;
    fn set_data(&mut self, data: JsonValue) {
        *self.body_type_mut() = BodyType::WwwForm(data);
        self.header_mut().set_content_type(ContentType::Application(Application::XWwwFormUrlencoded));
    }
    fn set_text(&mut self, text: impl ToString) {
        *self.body_type_mut() = BodyType::Text(text.to_string());
        self.header_mut().set_content_type(ContentType::Text(Text::Plain));
    }
    fn set_bytes(&mut self, bs: Vec<u8>) {
        *self.body_type_mut() = BodyType::Bytes(bs);
    }
    /// * 文件上传示例
    /// ```rust
    /// let files=vec![]
    /// files.push(HttpFile::new_fp("path/to/file1"));
    /// files.push(HttpFile::new_fp("path/to/file1"));
    /// let data=json::object!{"key":"value"};
    /// req.set_files(data,files)
    /// ```
    fn set_files(&mut self, data: JsonValue, files: Vec<HttpFile>) {
        *self.body_type_mut() = BodyType::Files((data, files));
        self.header_mut().set_content_type(ContentType::File("".to_string()))
    }
    fn add_file(&mut self, file: HttpFile) {
        if let BodyType::Files((_, files)) = self.body_type_mut() {
            files.push(file);
        } else {
            *self.body_type_mut() = BodyType::Files((JsonValue::Null, vec![file]));
        }
        self.header_mut().set_content_type(ContentType::File("".to_string()))
    }
    fn header_mut(&mut self) -> &mut Header;
    fn header(&self) -> &Header;
    fn set_timeout(&mut self, timeout: Timeout);
    fn timeout(&self) -> &Timeout;
    fn url(&self) -> &Url;
    fn url_mut(&mut self) -> &mut Url;
    fn set_proxy(&mut self, proxy: Proxy);
    fn with_proxy(mut self, proxy: Proxy) -> Self {
        self.set_proxy(proxy);
        self
    }
    /// *必须在建立tls连接（即：set_url/with_url）前设置, 否则需要调re_conn
    fn set_alpn(&mut self, alpn: ALPN);
    fn with_alpn(mut self, alpn: ALPN) -> Self {
        self.set_alpn(alpn);
        self
    }
    #[cfg(use_cls)]
    fn set_fingerprint(&mut self, fingerprint: Fingerprint);
    #[cfg(use_cls)]
    fn with_fingerprint(mut self, fingerprint: Fingerprint) -> Self {
        self.set_fingerprint(fingerprint);
        self
    }
    fn set_headers(&mut self, mut headers: Header, keep_cookie: bool) {
        if keep_cookie {
            let cks = self.header_mut().cookies().unwrap_or(&vec![]).clone();
            headers.set_cookies(cks);
        }
        *self.header_mut() = headers;
    }

    fn set_headers_json(&mut self, headers: JsonValue) -> HlsResult<()> {
        self.header_mut().set_by_json(headers)
    }

    fn set_json(&mut self, data: JsonValue) {
        self.set_data(data);
        self.header_mut().set_content_type(ContentType::Application(Application::Json))
    }

    fn insert_header(&mut self, k: impl AsRef<str>, v: impl ToString) -> HlsResult<()> {
        self.header_mut().insert(k, v)?;
        Ok(())
    }

    fn remove_header(&mut self, k: impl AsRef<str>) -> Option<HeaderValue> {
        self.header_mut().remove(k)
    }

    fn set_params(&mut self, params: JsonValue) {
        let uri = self.url_mut().uri_mut();
        uri.clear_params();
        for (k, v) in params.entries() {
            uri.insert_param(k, v);
        }
    }

    fn add_param(&mut self, name: impl ToString, value: impl ToString) {
        let uri = self.url_mut().uri_mut();
        uri.insert_param(name, value);
    }

    fn remove_param(&mut self, name: impl ToString) -> Option<String> {
        let uri = self.url_mut().uri_mut();
        uri.remove_param(name)
    }
}


pub(crate) trait ReqPriExt: ReqExt {
    // fn format_file_header(&mut self, md5: &str, body_len: usize) -> HlsResult<Vec<u8>> {
    //     self.header_mut().set_content_type(ContentType::File(md5.to_string()));
    //     let mut headers = self.header_mut().as_raw(body_len)?;
    //     headers.insert(0, format!("{} {} HTTP/1.1", self.header().method(), self.url().uri()));
    //     headers.push("".to_string());
    //     headers.push("".to_string());
    //     Ok(headers.join("\r\n").into_bytes())
    // }

    fn format_file_body((data, files): &(JsonValue, Vec<HttpFile>), md5: &str) -> HlsResult<Vec<u8>> {
        let mut body = vec![];
        for (k, v) in data.entries() {
            body.push(format!("--{}", md5));
            body.push(format!("Content-Disposition: form-data; name=\"{}\"", k));
            body.push("".to_string());
            body.push(v.dump());
            body.push("".to_string());
        };
        let mut body = body.join("\r\n").into_bytes();
        for file in files {
            body.extend(format!("--{}\r\nContent-Disposition: form-data; name=\"{}\"; filename=\"{}\"\r\n", md5, file.filed_name(), file.filename()).into_bytes());
            if file.file_type() != "" {
                body.extend(format!("Content-Type: {}\r\n", file.file_type()).into_bytes());
            }
            body.extend_from_slice(b"\r\n");
            body.extend(file.raw_bytes());
            body.append(&mut "\r\n".as_bytes().to_vec());
        }
        body.append(&mut format!("--{}--\r\n", md5).as_bytes().to_vec());
        Ok(body)
    }

    // fn format_file_bytes(&mut self) -> HlsResult<Vec<u8>> {
    //     let md5 = "abcde12345abcdebbeeaaccafeacb454";
    //     let body_bytes = self.format_file_body(&md5)?;
    //     let mut header_bytes = self.format_file_header(&md5, body_bytes.len())?;
    //     header_bytes.extend(body_bytes);
    //     Ok(header_bytes)
    // }

    fn format_body(&mut self, md5: &str) -> HlsResult<Vec<u8>> {
        match self.body_type() {
            BodyType::Text(text) => Ok(text.as_bytes().to_vec()),
            BodyType::Bytes(bytes) => Ok(bytes.to_vec()),
            BodyType::Files(fds) => {
                // let md5 = "abcde12345abcdebbeeaaccafeacb454";
                let body_bytes = Self::format_file_body(fds, md5)?;
                Ok(body_bytes)
            }
            BodyType::WwwForm(form) => Ok(form.entries().map(|(k, v)| {
                format!("{}={}", k, coder::url_encode(v.dump()))
            }).collect::<Vec<_>>().join("&").into_bytes()),
            BodyType::Json(jd) => Ok(jd.dump().into_bytes()),
        }


        // let content_type = self.header().content_type();
        // Ok(match content_type {
        //     Some(content_type) => match content_type {
        //         ContentType::Application(Application::Json) | ContentType::Text(Text::Plain) => self.data().dump(),
        //         ContentType::Application(Application::XWwwFormUrlencoded) => {
        //             self.data().entries().map(|(k, v)| {
        //                 let v = coder::url_encode(v.dump());
        //                 format!("{}={}", k, v)
        //             }).collect::<Vec<_>>().join("&")
        //         }
        //         _ => "".to_string()
        //     }
        //     _ => "".to_string()
        // })
    }

    fn format_header(&mut self, md5: &str, body_len: usize) -> HlsResult<Vec<u8>> {
        if let BodyType::Files(_) = self.body_type() {
            self.header_mut().set_content_type(ContentType::File(md5.to_string()));
        }
        let mut headers = self.header_mut().as_raw(body_len)?;
        headers.insert(0, format!("{} {} HTTP/1.1", self.header().method(), self.url().uri()));
        headers.push("".to_string());
        headers.push("".to_string());
        Ok(headers.join("\r\n").into_bytes())
    }

    // fn format_common_bytes(&mut self) -> HlsResult<Vec<u8>> {
    //     let md5 = "abcde12345abcdebbeeaaccafeacb454";
    //     let body = self.format_body(md5)?;
    //     let mut header = self.format_header(md5, body.len())?;
    //     header.extend(body);
    //     Ok(header)
    // }

    #[cfg(anys)]
    fn update_cookie(&mut self, response: &Response) {
        for cookie in response.header().cookies().unwrap_or(&vec![]) {
            if cookie.name() == "" && cookie.value() == "" { continue; }
            self.header_mut().add_cookie(cookie.clone());
        }
    }

    #[cfg(anys)]
    fn check_status(&self, response: &Response) -> HlsResult<()> {
        let status = response.header().status().status_num();
        match status {
            400..600 => Err(format!("网络请求错误-{}", status).into()),
            _ => Ok(())
        }
    }

    #[cfg(anys)]
    fn check_res(&self, response: Response, k: impl AsRef<str>, v: impl ToString, e: Vec<impl AsRef<str>>) -> HlsResult<JsonValue> {
        let data = response.to_json()?;
        if data[k.as_ref()].to_string() != v.to_string() {
            for e in e {
                if !data[e.as_ref()].is_null() { return Err(data[e.as_ref()].to_string().into()); }
            }
            Err(format!("check fail: key: {}; value: {}", k.as_ref(), v.to_string()).into())
        } else { Ok(data) }
    }
}

#[allow(private_bounds)]
pub trait ReqGenExt: ReqPriExt {
    fn gen_h1(&mut self) -> HlsResult<Vec<u8>> {
        let host = self.url().addr().to_string().replace(":80", "").replace(":443", "");
        match self.header().host() {
            None => self.header_mut().set_host(host)?,
            Some(key_host) => if key_host.is_empty() || key_host != host { self.header_mut().set_host(host)? }
        }
        let md5 = "abcde12345abcdebbeeaaccafeacb454";
        let body = self.format_body(md5)?;
        let mut content = self.format_header(md5, body.len())?;
        content.extend(body);
        Ok(content)
        // self.format_common_bytes()
        // match self.header_mut().content_type().unwrap_or(&ContentType::Application(Application::XWwwFormUrlencoded)) {
        //     ContentType::File(_) => self.format_file_bytes(),
        //     _ => self.format_common_bytes()
        // }
    }

    fn gen_h2_header(&mut self) -> HlsResult<Vec<HeaderKey>> {
        let mut headers = self.header().as_h2c()?;
        headers.insert(1, HeaderKey::new(":authority".to_string(), HeaderValue::String(self.url().addr().to_string().replace(":80", "").replace(":443", ""))));
        headers.insert(2, HeaderKey::new(":scheme".to_string(), HeaderValue::String("https".to_string())));
        headers.insert(3, HeaderKey::new(":path".to_string(), HeaderValue::String(self.url().uri().to_string())));
        Ok(headers)
    }


    fn gen_h2_body(&mut self) -> HlsResult<Vec<u8>> {
        // match self.header_mut().content_type().unwrap_or(&ContentType::Application(Application::XWwwFormUrlencoded)) {
        //     ContentType::File(_) => {
        //         self.header_mut().set_content_type(ContentType::File("abcde12345abcdebbeeaaccafeacb454".to_string()));
        //         self.format_file_body("abcde12345abcdebbeeaaccafeacb454")
        //     }
        //     _ => Ok(self.format_body("abcde12345abcdebbeeaaccafeacb454")?.into_bytes()),
        // }
        self.format_body("abcde12345abcdebbeeaaccafeacb454")
    }
}