use reqrio::{json, HlsError, Method, ReqExt, ScReq, Timeout, ALPN, Cipher};
use std::fs::File;
use std::io::Write;

struct M3u8DownEngine {
    req: ScReq,
    key_url: String,
    sequence: u128,
    index_url: String,
    ts_urls: Vec<String>,
    cipher: Cipher,
}

impl M3u8DownEngine {
    fn new(index: impl ToString) -> M3u8DownEngine {
        let mut req = ScReq::new().with_alpn(ALPN::Http20); //.with_proxy(Proxy::new_http_plain("127.0.0.1", 10809));
        req.set_headers_json(json::object! {
            "Host": "",
            "sec-ch-ua-platform": "Android",
            "user-agent": "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36",
            "sec-ch-ua": r#""Android WebView";v="135", "Not-A.Brand";v="8", "Chromium";v="135""#,
            "sec-ch-ua-mobile": "?1",
            "accept": "*/*",
            "origin": "",
            "x-requested-with": "mark.via",
            "sec-fetch-site": "cross-site",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": "",
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": "en,zh-CN;q=0.9,zh;q=0.8,en-US;q=0.7",
            "priority": "u=1, i"
        }).unwrap();
        M3u8DownEngine {
            req,
            index_url: index.to_string(),
            sequence: 0,
            key_url: "".to_string(),
            ts_urls: vec![],
            cipher: Cipher::aes_128_ecb(),
        }
    }

    fn down_ts(&mut self) -> Result<(), HlsError> {
        let mut file = File::create("4.mp4")?;
        for (index, ts_url) in self.ts_urls.iter().enumerate() {
            println!("Downloading: {:3}/{}; url:{}", index, self.ts_urls.len(), ts_url);
            let body = self.req.get(ts_url, None)?.bytes();
            file.write_all(&if self.key_url.is_empty() { body } else { self.cipher.decrypt(body)? })?;
        }
        Ok(())
    }

    fn get_key(&mut self) -> Result<(), HlsError> {
        println!("key url: {}", self.key_url);
        let key = self.req.send_check(Method::GET, self.key_url.as_str(), None)?.text()?;
        println!("key: {}; sequence: {}", key, self.sequence);
        self.cipher.set_secret_key(key.into_bytes(), Some(self.sequence.to_be_bytes().to_vec()));
        Ok(())
    }

    fn download(&mut self) -> Result<(), HlsError> {
        let body = self.req.send_check(Method::GET, &self.index_url, None)?.text()?;
        println!("{}", body);
        for line in body.replace("\r\n", "\n").split("\n") {
            let line = line.replace(" ", "");
            if line.starts_with("#EXT-X-MEDIA-SEQUENCE:") {
                self.sequence = line.trim().replace("#EXT-X-MEDIA-SEQUENCE:", "").parse()?;
                continue;
            }
            if line.starts_with("#EXT-X-KEY") {
                let pos = line.find("URI =\"");
                if let Some(pos) = pos {
                    self.key_url = line[pos + 4..].trim().replace("\"", "");
                }
                if line.contains("=AES-128,") {
                    self.cipher = Cipher::aes_128_cbc();
                }
                continue;
            }
            if line.ends_with(".ts") {
                if line.starts_with("http") {
                    self.ts_urls.push(line.trim().to_string());
                } else {
                    self.ts_urls.push(format!("/{}", line))
                }
            }
        }
        let mut timeout = Timeout::new_same(5000, 30000);
        timeout.set_handle_times(10);
        self.req.set_timeout(timeout);
        if !self.key_url.is_empty() { self.get_key()?; }
        self.down_ts()?;
        Ok(())
    }
}


fn main() {
    let index = "";
    let mut engine = M3u8DownEngine::new(index);
    engine.download().unwrap();
    println!("{:?} {:?}", engine.key_url, engine.ts_urls);
}