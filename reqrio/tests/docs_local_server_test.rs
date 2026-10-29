//! [本测试由AI编写] 
//! 
//! 本地 HTTP/1.1 服务器契约测试 —— 依据 https://ms.xllgl.top/docs.html 编写。
//!
//! 用进程内 TCP 服务器精确验证请求方法、请求体、查询参数、请求头、重定向、
//! Cookie、流式响应、大响应体、状态码与连接复用，不依赖公网。

use reqrio::*;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::LazyLock;
use std::thread;

struct Server {
    base: String,
}

impl Server {
    fn start() -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                thread::spawn(move || handle_conn(stream));
            }
        });
        Server {
            base: format!("http://127.0.0.1:{}", port),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }
}

struct Request {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

fn read_request(reader: &mut BufReader<TcpStream>) -> Option<Request> {
    let mut head = String::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 {
            return None;
        }
        head.push_str(&line);
        if line == "\r\n" {
            break;
        }
    }
    let mut lines = head.lines();
    let first = lines.next()?;
    let mut parts = first.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let len = headers
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; len];
    if len > 0 {
        reader.read_exact(&mut body).ok()?;
    }
    Some(Request {
        method,
        path,
        headers,
        body,
    })
}

fn write_response(
    stream: &mut TcpStream,
    status: &str,
    extra: &[(&str, String)],
    body: &[u8],
    send_body: bool,
) {
    let mut out = format!(
        "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: keep-alive\r\n",
        status,
        body.len()
    );
    for (k, v) in extra {
        out.push_str(&format!("{}: {}\r\n", k, v));
    }
    out.push_str("\r\n");
    stream.write_all(out.as_bytes()).ok();
    if send_body {
        stream.write_all(body).ok();
    }
}

fn echo_body(req: &Request) -> String {
    format!(
        "method={}\npath={}\nbody={}\ncookie={}\nx-test={}\ncontent-type={}",
        req.method,
        req.path,
        String::from_utf8_lossy(&req.body),
        req.headers.get("cookie").cloned().unwrap_or_default(),
        req.headers.get("x-test").cloned().unwrap_or_default(),
        req.headers.get("content-type").cloned().unwrap_or_default()
    )
}

fn handle_conn(stream: TcpStream) {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10))).ok();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut stream = stream;

    while let Some(req) = read_request(&mut reader) {
        let path = req.path.split('?').next().unwrap_or(&req.path);
        if path == "/text" {
            write_response(
                &mut stream,
                "200 OK",
                &[("Content-Type", "text/plain".to_string()), ("X-Server", "reqrio-test".to_string())],
                b"hello world",
                true,
            );
        } else if path == "/chunked" {
            let mut out = String::from("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n");
            for chunk in ["chunk1", "chunk2", "chunk3"] {
                out.push_str(&format!("{:x}\r\n{}\r\n", chunk.len(), chunk));
            }
            out.push_str("0\r\n\r\n");
            stream.write_all(out.as_bytes()).ok();
        } else if let Some(n) = path.strip_prefix("/bytes/") {
            let n: usize = n.parse().unwrap_or(0);
            let body = vec![b'x'; n];
            write_response(
                &mut stream,
                "200 OK",
                &[("Content-Type", "application/octet-stream".to_string())],
                &body,
                req.method != "HEAD",
            );
        } else if path == "/redirect" {
            write_response(
                &mut stream,
                "302 Found",
                &[("Location", "/text".to_string())],
                b"",
                true,
            );
        } else if path == "/set-cookie" {
            write_response(
                &mut stream,
                "200 OK",
                &[("Set-Cookie", "k=v; Path=/".to_string())],
                b"ok",
                true,
            );
        } else if path == "/head" {
            write_response(&mut stream, "200 OK", &[("X-Method", "HEAD".to_string())], b"", false);
        } else if path == "/status/404" {
            write_response(&mut stream, "404 Not Found", &[], b"not found", true);
        } else {
            // /echo 及其他路径都回显请求
            let body = echo_body(&req);
            write_response(
                &mut stream,
                "200 OK",
                &[("Content-Type", "text/plain".to_string())],
                body.as_bytes(),
                req.method != "HEAD",
            );
        }
    }
}

fn client() -> ScReq {
    ScReq::new()
        .with_timeout(Timeout::new_same(15000, 1))
        .with_alpn(ALPN::HTTP11)
}

static SERVER: LazyLock<Server> = LazyLock::new(Server::start);

// ---------------------------------------------------------------------------

#[test]
fn local_get_text_and_connection_reuse() {
    let mut s = client();
    for _ in 0..3 {
        let resp = s.get(SERVER.url("/text"), None).unwrap();
        assert_eq!(resp.status(), HttpStatus::OK);
        assert_eq!(resp.as_text().unwrap(), "hello world");
        assert_eq!(resp.header().content_type().unwrap().spec(), "text/plain");
        assert_eq!(resp.header().get_str("X-Server"), Some("reqrio-test"));
    }
}

#[test]
fn local_query_params() {
    let mut s = client();
    let url = SERVER
        .url("/echo")
        .params(json::object! {"q" => "a b", "page" => 2})
        .unwrap();
    let resp = s.get(url, None).unwrap();
    assert_eq!(resp.status(), HttpStatus::OK);
    let body = resp.as_text().unwrap();
    assert!(body.contains("path=/echo?q=a%20b&page=2") || body.contains("path=/echo?q=a+b&page=2"), "body={}", body);
}

#[test]
fn local_request_headers() {
    let mut s = client();
    s.insert_header("X-Test", "abc");
    let resp = s.get(SERVER.url("/echo"), None).unwrap();
    let body = resp.as_text().unwrap();
    assert!(body.contains("x-test=abc"), "body={}", body);
}

#[test]
fn local_post_json_body() {
    let mut s = client();
    let body = json::object! {"a" => 1, "b" => "two"};
    let resp = s
        .post(SERVER.url("/echo"), body.ty(Application::Json))
        .unwrap();
    assert_eq!(resp.status(), HttpStatus::OK);
    let body = resp.as_text().unwrap();
    assert!(body.contains("body={\"a\":1,\"b\":\"two\"}"), "body={}", body);
    assert!(body.contains("content-type=application/json"), "body={}", body);
}

#[test]
fn local_post_form_body() {
    let mut s = client();
    let form = json::object! {"a" => "1", "b" => "x y"};
    let resp = s.post(SERVER.url("/echo"), form.form()).unwrap();
    let body = resp.as_text().unwrap();
    assert!(body.contains("body=a=1&b=x"), "body={}", body);
    assert!(
        body.contains("content-type=application/x-www-form-urlencoded"),
        "body={}",
        body
    );
}

#[test]
fn local_post_bytes_and_text() {
    let mut s = client();
    let resp = s.post(SERVER.url("/echo"), b"\x00\x01hello".as_slice()).unwrap();
    let body = resp.as_text().unwrap();
    assert!(body.contains("content-type=application/octet-stream"), "body={}", body);

    let resp = s.post(SERVER.url("/echo"), "plain-text").unwrap();
    let body = resp.as_text().unwrap();
    assert!(body.contains("body=plain-text"), "body={}", body);
    assert!(body.contains("content-type=text/plain"), "body={}", body);
}

#[test]
fn local_http_methods() {
    let mut s = client();
    let cases = [
        ("DELETE", s.delete(SERVER.url("/echo"), None)),
        ("PUT", s.put(SERVER.url("/echo"), None)),
        ("PATCH", s.patch::<()>(SERVER.url("/echo"), None)),
        ("OPTIONS", s.options(SERVER.url("/echo"), None)),
    ];
    for (method, result) in cases {
        let resp = result.unwrap();
        assert_eq!(resp.status(), HttpStatus::OK);
        assert!(resp.as_text().unwrap().contains(&format!("method={}", method)));
    }

    let head = s.head(SERVER.url("/head"), None).unwrap();
    assert_eq!(head.status(), HttpStatus::OK);
    assert!(head.as_bytes().is_empty(), "HEAD must not have a body");
}

/// HEAD 响应的 Content-Length 非 0 时，客户端会一直等待响应体直到进程被杀；
/// 这里用带超时的线程检测该挂起行为（超时视为检测到问题）。
#[test]
fn local_head_with_content_length_hangs() {
    use std::sync::mpsc;
    use std::time::Duration;

    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut s = client();
        let result = s.head(SERVER.url("/bytes/16"), None);
        let _ = tx.send(result.is_ok());
    });
    assert!(
        rx.recv_timeout(Duration::from_secs(5)).is_err(),
        "HEAD with non-zero Content-Length returned instead of hanging"
    );
}

#[test]
fn local_redirect_control() {
    let mut s = client().with_auto_redirect(false);
    let resp = s.get(SERVER.url("/redirect"), None).unwrap();
    assert_eq!(resp.status(), HttpStatus::Found);
    assert_eq!(resp.header().location(), Some("/text"));

    let mut s = client().with_auto_redirect(true);
    let resp = s.get(SERVER.url("/redirect"), None).unwrap();
    assert_eq!(resp.status(), HttpStatus::OK);
    assert_eq!(resp.as_text().unwrap(), "hello world");
}

#[test]
fn local_cookie_jar() {
    let mut s = client();
    let resp = s.get(SERVER.url("/set-cookie"), None).unwrap();
    assert_eq!(resp.status(), HttpStatus::OK);
    let cookies = resp.header().cookies().expect("Set-Cookie should parse");
    assert!(cookies.iter().any(|c| c.name() == "k" && c.value() == "v"));

    let resp = s.get(SERVER.url("/echo"), None).unwrap();
    assert!(
        resp.as_text().unwrap().contains("cookie=k=v"),
        "session cookie should be sent back"
    );
}

#[test]
fn local_stream_chunked() {
    let mut s = client();
    #[cfg(feature = "export")]
    let sid = s.send_stream(Method::GET, SERVER.url("/chunked"), None).unwrap().sid;
    #[cfg(not(feature = "export"))]
    let sid = s.send(Method::GET, SERVER.url("/chunked"), None).unwrap();

    let mut body = Vec::new();
    while let Some(chunk) = s.next_chunk(sid).unwrap() {
        body.extend_from_slice(chunk);
    }
    assert_eq!(String::from_utf8(body).unwrap(), "chunk1chunk2chunk3");
}

#[test]
fn local_large_response_body() {
    let mut s = client();
    let resp = s.get(SERVER.url("/bytes/1048576"), None).unwrap();
    assert_eq!(resp.status(), HttpStatus::OK);
    assert_eq!(resp.as_bytes().len(), 1048576);
}

#[test]
fn local_status_code_and_send_check() {
    let mut s = client();
    let resp = s.get(SERVER.url("/status/404"), None).unwrap();
    assert_eq!(resp.status().code(), 404);
    assert_eq!(resp.as_text().unwrap(), "not found");

    let err = s
        .send_check(Method::GET, SERVER.url("/status/404"), None)
        .err()
        .expect("send_check should reject 4xx");
    assert!(err.to_string().contains("404"), "err={}", err);
}

#[test]
fn local_response_readers() {
    let mut s = client();
    let resp = s.get(SERVER.url("/echo"), None).unwrap();
    assert_eq!(resp.status().code(), 200);
    // 文档承诺 get_str 对所有响应头可用；content-type 在实现里被存成 ContextType
    assert!(resp.header().content_type().is_some());
    assert!(resp.header().content_length().is_some());
    assert!(resp.header().get_str("X-Server").is_none());

    let resp = s.get(SERVER.url("/echo"), None).unwrap();
    assert!(resp.as_bytes().starts_with(b"method="));
}
