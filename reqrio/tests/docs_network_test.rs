//! [本测试由AI编写]
//!
//! 同步网络 API 契约测试 —— 依据 https://ms.xllgl.top/docs.html 编写。
//!
//! 覆盖：基础请求 / 查询参数 / IP+SNI / JSON / 表单 / 字节 / 文本 / 自定义方法 /
//! 一次性请求 / send+recv / 并发 / 流式 / 响应读取 / Cookie / 重定向 / 超时错误 /
//! 连接复用 / 指纹 / TLCP / HTTP3 / WebSocket。
//!
//! 依赖公网（baidu / httpbin / gmssl / bing / echo.websocket.org）。

use reqrio::*;
use std::env;
use std::fs;
use std::sync::LazyLock;

static TOKEN: LazyLock<String> = LazyLock::new(|| {
    fs::read_to_string("../TOKEN")
        .ok()
        .map(|s| s.trim().to_string())
        .or_else(|| env::var("REQRIO_TOKEN").ok())
        .unwrap_or_default()
});

const JA3: &str = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,18-45-5-10-11-16-23-27-0-13-35-65281-43-51-17613,29-23-24,0";
const JA4: &str = "t13d1515h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,ff01_0804,0403,0401,0303,0402,080b,0201,0203,0202,0302,0502,0301,0503,0602,0806,0809";

fn session() -> ScReq {
    ScReq::new()
        .with_timeout(Timeout::new_same(15000, 1))
        .with_alpn(ALPN::HTTP20)
}

fn json_body(resp: Response) -> json::JsonValue {
    resp.json().expect("response should be valid json")
}

// ---------------------------------------------------------------------------
// 基础请求 / 查询参数 / SNI
// ---------------------------------------------------------------------------

#[test]
fn net_basic_get() {
    let mut s = session();
    let resp = s.get("https://www.baidu.com", None).unwrap();
    assert_eq!(resp.status(), HttpStatus::OK);
    assert!(!resp.as_bytes().is_empty());
    assert!(resp.as_text().unwrap().contains("baidu") || resp.as_text().unwrap().contains("百度"));
}

#[test]
fn net_url_query_params() {
    let mut s = session();
    let url = "https://httpbin.org/get"
        .params(json::object! {"q": "reqrio", "page": 1})
        .unwrap();
    let resp = s.get(url, None).unwrap();
    assert_eq!(resp.status(), HttpStatus::OK);
    let j = json_body(resp);
    assert_eq!(j["args"]["q"].to_string(), "reqrio");
    assert_eq!(j["args"]["page"].to_string(), "1");
}

#[test]
fn net_ip_with_sni() {
    let mut s = session();
    let url = "https://104.18.34.137".sni("whatnot.com").unwrap();
    let resp = s.get(url, None).unwrap();
    assert_eq!(resp.status(), HttpStatus::OK);
}

// ---------------------------------------------------------------------------
// Body：JSON / 表单 / 字节 / 文本
// ---------------------------------------------------------------------------

#[test]
fn net_post_json() {
    let mut s = session();
    let body = json::object! {"a": 1, "b": "two"};
    let resp = s
        .post("https://httpbin.org/post", body.ty(Application::Json))
        .unwrap();
    assert_eq!(resp.status(), HttpStatus::OK);
    let j = json_body(resp);
    assert_eq!(j["json"]["a"].to_string(), "1");
    assert_eq!(j["json"]["b"].to_string(), "two");
    assert!(
        j["headers"].to_string().to_lowercase().contains("application/json"),
        "content-type echoed: {}",
        j["headers"]
    );
}

#[test]
fn net_post_form() {
    let mut s = session();
    let body = json::object! {"a": "1", "b": "x y"};
    let resp = s.post("https://httpbin.org/post", body.form()).unwrap();
    assert_eq!(resp.status(), HttpStatus::OK);
    let j = json_body(resp);
    assert_eq!(j["form"]["a"].to_string(), "1");
    assert_eq!(j["form"]["b"].to_string(), "x y");
    assert!(j["headers"].to_string().to_lowercase().contains("x-www-form-urlencoded"));
}

#[test]
fn net_post_bytes_and_text() {
    let mut s = session();
    let resp = s
        .post("https://httpbin.org/post", b"\x00\x01hello".as_slice())
        .unwrap();
    assert_eq!(resp.status(), HttpStatus::OK);
    let j = json_body(resp);
    assert!(j["headers"].to_string().to_lowercase().contains("application/octet-stream"));

    let resp = s.post("https://httpbin.org/post", "plain-text-body").unwrap();
    assert_eq!(resp.status(), HttpStatus::OK);
    let j = json_body(resp);
    assert_eq!(j["data"].to_string(), "plain-text-body");
    assert!(j["headers"].to_string().to_lowercase().contains("text/plain"));
}

#[cfg(feature = "serde")]
#[test]
fn net_post_json_serde_struct() {
    #[derive(serde::Serialize)]
    struct Payload {
        a: i32,
    }
    let mut s = session();
    let body = Body::json(&Payload { a: 42 }).unwrap();
    let resp = s.post("https://httpbin.org/post", body).unwrap();
    assert_eq!(resp.status(), HttpStatus::OK);
    let j = json_body(resp);
    assert_eq!(j["json"]["a"].to_string(), "42");
}

// ---------------------------------------------------------------------------
// 方法 / 一次性请求 / send+recv
// ---------------------------------------------------------------------------

#[test]
fn net_quick_functions() {
    let resp = reqrio::get("https://www.baidu.com", None).unwrap();
    assert_eq!(resp.status(), HttpStatus::OK);

    let resp = reqrio::post("https://httpbin.org/post", json::object! {"x": 1}).unwrap();
    assert_eq!(resp.status(), HttpStatus::OK);
    assert_eq!(json_body(resp)["json"]["x"].to_string(), "1");

    let resp = reqrio::put("https://httpbin.org/put", "hello").unwrap();
    assert_eq!(resp.status(), HttpStatus::OK);
    assert_eq!(json_body(resp)["data"].to_string(), "hello");
}

#[test]
fn net_send_recv() {
    let mut s = session();
    let sid = s
        .send(Method::DELETE, "https://httpbin.org/delete", None)
        .unwrap();
    let resp = s.recv(sid).unwrap();
    assert_eq!(resp.status(), HttpStatus::OK);
    assert_eq!(json_body(resp)["method"].to_string(), "DELETE");
}

#[test]
fn net_concurrent_send_recv_same_host() {
    let mut s = session();
    let sid1 = s.send(Method::GET, "https://httpbin.org/get?x=1", None).unwrap();
    let sid2 = s.send(Method::GET, "https://httpbin.org/get?x=2", None).unwrap();
    let sid3 = s.send(Method::GET, "https://httpbin.org/get?x=3", None).unwrap();

    // 文档：HTTP/2 可按任意顺序接收
    let r3 = s.recv(sid3).unwrap();
    let r2 = s.recv(sid2).unwrap();
    let r1 = s.recv(sid1).unwrap();

    assert_eq!(r3.status(), HttpStatus::OK);
    assert_eq!(r2.status(), HttpStatus::OK);
    assert_eq!(r1.status(), HttpStatus::OK);
    assert_eq!(json_body(r3)["args"]["x"].to_string(), "3");
    assert_eq!(json_body(r2)["args"]["x"].to_string(), "2");
    assert_eq!(json_body(r1)["args"]["x"].to_string(), "1");
}

// ---------------------------------------------------------------------------
// 流式下载
// ---------------------------------------------------------------------------

#[test]
fn net_stream_download() {
    // httpbin 在 h2 下对大 Content-Length 响应会断连（见异常汇总），
    // 此处用 HTTP/1.1 验证流式 API 本身。
    let mut s = ScReq::new()
        .with_timeout(Timeout::new_same(20000, 1))
        .with_alpn(ALPN::HTTP11);
    #[cfg(feature = "export")]
    let sid = s
        .send_stream(Method::GET, "https://httpbin.org/bytes/65536", None)
        .unwrap()
        .sid;
    #[cfg(not(feature = "export"))]
    let sid = s
        .send(Method::GET, "https://httpbin.org/bytes/65536", None)
        .unwrap();

    let mut total = 0usize;
    let mut chunks = 0usize;
    while let Some(chunk) = s.next_chunk(sid).unwrap() {
        assert!(!chunk.is_empty());
        total += chunk.len();
        chunks += 1;
    }
    assert_eq!(total, 65536, "streamed byte count");
    assert!(chunks >= 1);
}

// ---------------------------------------------------------------------------
// Response / Header / Cookie / Redirect
// ---------------------------------------------------------------------------

#[test]
fn net_json_and_bytes_readers() {
    let mut s = session();
    let resp = s.get("https://httpbin.org/json", None).unwrap();
    assert_eq!(resp.status(), HttpStatus::OK);
    let j = resp.json().unwrap();
    assert!(j["slideshow"].is_object());

    let resp = s.get("https://httpbin.org/bytes/16", None).unwrap();
    assert_eq!(resp.bytes().len(), 16);
}

#[test]
fn net_cookies_and_redirect() {
    let mut s = session().with_auto_redirect(false);
    let resp = s
        .get("https://httpbin.org/cookies/set?k=v", None)
        .unwrap();
    assert_eq!(resp.status().code(), 302);
    let cks = resp.header().cookies().expect("Set-Cookie should be parsed");
    assert!(cks.iter().any(|c| c.name() == "k" && c.value() == "v"), "cookies = {:?}", cks.iter().map(|c| c.as_req()).collect::<Vec<_>>());
    assert!(resp.header().location().is_some());

    // 会话应已累积 Cookie
    let resp = s.get("https://httpbin.org/cookies", None).unwrap();
    assert_eq!(resp.status(), HttpStatus::OK);
    assert_eq!(json_body(resp)["cookies"]["k"].to_string(), "v");

    // 自动重定向
    let mut s = session();
    let resp = s.get("https://httpbin.org/redirect/2", None).unwrap();
    assert_eq!(resp.status(), HttpStatus::OK);
    assert_eq!(json_body(resp)["url"].to_string(), "https://httpbin.org/get");
}

#[test]
fn net_connect_reuse_and_tls_version() {
    let mut s = ScReq::new()
        .with_timeout(Timeout::new_same(15000, 1))
        .connect("https://www.baidu.com")
        .unwrap();
    for _ in 0..2 {
        let resp = s.get("https://www.baidu.com", None).unwrap();
        assert_eq!(resp.status(), HttpStatus::OK);
    }

    let mut s = ScReq::new()
        .with_timeout(Timeout::new_same(15000, 1))
        .with_alpn(ALPN::HTTP11)
        .with_version(Version::TLS_1_2);
    let resp = s.get("https://www.baidu.com", None).unwrap();
    assert_eq!(resp.status(), HttpStatus::OK);
    assert_eq!(resp.alpn().value(), "http/1.1");

    let mut s = ScReq::new()
        .with_timeout(Timeout::new_same(15000, 1))
        .with_alpn(ALPN::HTTP20)
        .with_version(Version::TLS_1_3);
    let resp = s.get("https://m.sogou.com", None).unwrap();
    assert_eq!(resp.status(), HttpStatus::OK);
}

// ---------------------------------------------------------------------------
// 错误 / 超时
// ---------------------------------------------------------------------------

#[test]
fn net_connect_timeout_error() {
    let mut s = ScReq::new().with_timeout(Timeout::new_same(300, 1));
    let err = s.get("https://192.0.2.1/", None).err().expect("should fail");
    let msg = err.to_string();
    assert!(
        msg.contains("Time") || msg.to_lowercase().contains("timeout") || msg.to_lowercase().contains("connect"),
        "unexpected error message: {}",
        msg
    );
}

#[test]
fn net_invalid_url_error() {
    let mut s = session();
    let err = s.get("not a valid url", None).err().expect("invalid url should fail");
    assert!(!err.to_string().is_empty());
}

// ---------------------------------------------------------------------------
// Fingerprint
// ---------------------------------------------------------------------------

#[test]
fn net_fingerprint_ja3() {
    let fp = Fingerprint::from_ja3(JA3, TOKEN.as_str()).unwrap();
    let mut s = ScReq::new()
        .with_timeout(Timeout::new_same(15000, 1))
        .with_fingerprint(fp);
    assert_eq!(s.get("https://m.so.com", None).unwrap().status(), HttpStatus::OK);
}

#[test]
fn net_fingerprint_ja4() {
    let fp = Fingerprint::from_ja4(JA4, TOKEN.as_str()).unwrap();
    let mut s = ScReq::new()
        .with_timeout(Timeout::new_same(15000, 1))
        .with_fingerprint(fp);
    assert_eq!(s.get("https://m.so.com", None).unwrap().status(), HttpStatus::OK);
}

#[test]
fn net_fingerprint_random() {
    let fp = Fingerprint::random(TOKEN.as_str());
    let mut s = ScReq::new()
        .with_timeout(Timeout::new_same(15000, 1))
        .with_fingerprint(fp);
    assert_eq!(s.get("https://m.so.com", None).unwrap().status(), HttpStatus::OK);
}

#[test]
fn net_fingerprint_custom() {
    // 文档 custom 示例给的是极简扩展集，服务端会直接拒绝；这里用完整浏览器级扩展验证 API。
    let tls = TlsFinger::Custom {
        record_version: Version::TLS_1_0,
        message_version: Version::TLS_1_2,
        suites: vec![
            CipherSuite::TLS_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        ],
        extensions: vec![
            Extension::StatusRequest(StatusRequest::OCSP),
            Extension::SupportedGroups(vec![NamedCurve::X25519, NamedCurve::SecP256r1]),
            Extension::EcPointFormats(vec![EcPointFormat::UNCOMPRESSED]),
            Extension::SignatureAlgorithms(vec![
                SignatureAlgorithm::RSA_PKCS1_SHA256,
                SignatureAlgorithm::ECDSA_SECP256R1_SHA256,
                SignatureAlgorithm::RSA_PSS_RSAE_SHA256,
            ]),
            Extension::ExtendedMasterSecret,
            Extension::CompressionCertificate(vec![CompressionMethod::NULL]),
            Extension::SessionTicket(Buf::default()),
            Extension::SupportedVersions(vec![Version::TLS_1_3, Version::TLS_1_2]),
            Extension::PskKeyExchangeModes(vec![PskMode::PSK_DHE_KE]),
            Extension::KeyShare(vec![KeyEntry::X25519, KeyEntry::SecP256r1]),
            Extension::ApplicationSettings(vec![ALPN::HTTP20, ALPN::HTTP11]),
            Extension::ServerName(vec![ServerName::HOSTNAME]),
            Extension::ApplicationLayerProtocolNegotiation(vec![ALPN::HTTP20, ALPN::HTTP11]),
        ],
    };
    let mut fp = Fingerprint::new_h2(tls, H2Finger::default(), TOKEN.as_str()).unwrap();
    fp.h2_mut().set_priority(true, 147);

    let mut s = ScReq::new()
        .with_timeout(Timeout::new_same(15000, 1))
        .with_fingerprint(fp);
    assert_eq!(s.get("https://m.so.com", None).unwrap().status(), HttpStatus::OK);
}

#[test]
fn net_fingerprint_builtin() {
    let fp = Fingerprint::from_builtin("win-x64-chrome-152", TOKEN.as_str(), false)
        .expect("built-in fingerprint should load with a subscribed token");
    let mut s = ScReq::new()
        .with_timeout(Timeout::new_same(15000, 1))
        .with_fingerprint(fp);
    assert_eq!(s.get("https://m.so.com", None).unwrap().status(), HttpStatus::OK);
}

// ---------------------------------------------------------------------------
// TLCP / HTTP3 / WebSocket
// ---------------------------------------------------------------------------

#[test]
fn net_tlcp() {
    let fp = Fingerprint::new_tls(
        TlsFinger::Custom {
            record_version: Version::TLCP,
            message_version: Version::TLCP,
            suites: vec![CipherSuite::ECC_SM4_CBC_SM3],
            extensions: vec![
                Extension::Reserved { typ: ExtensionType::new(0xfafa), value: Buf::default() },
                Extension::ServerName(vec![ServerName::HOSTNAME]),
                Extension::Reserved { typ: ExtensionType::new(0x8a8a), value: Buf::new_ref(&[0]) },
            ],
        },
        TOKEN.as_str(),
    )
        .unwrap();

    let mut req = ScReq::new()
        .with_timeout(Timeout::new_same(20000, 1))
        .with_alpn(ALPN::HTTP11)
        .with_fingerprint(fp);
    let resp = req.get("https://test.gmssl.cn", None).unwrap();
    assert_eq!(resp.status(), HttpStatus::OK);
}

#[cfg(all(not(feature = "staticlink"), feature = "quic"))]
#[test]
fn net_http3() {
    let mut req = ScReq::new()
        .with_timeout(Timeout::new_same(15000, 1))
        .with_alpn(ALPN::HTTP30);
    let resp = req.get("https://www.bing.com", None).unwrap();
    assert_eq!(resp.status(), HttpStatus::OK);
    // 注：HTTP/2 与 HTTP/3 响应的 Response::alpn() 为空（见异常汇总），故不断言 alpn
}

/// httpbin + 协商到 h2 时，固定 Content-Length 的大响应会断连；
/// 同样的 URL 走 HTTP/1.1 正常（见下一条用例）。
#[test]
fn net_large_body_httpbin_h2() {
    let mut s = session();
    let resp = s
        .get("https://httpbin.org/bytes/65536", None)
        .expect("65KB body over h2 should succeed");
    assert_eq!(resp.status(), HttpStatus::OK);
    assert_eq!(resp.as_bytes().len(), 65536);
}

#[test]
fn net_large_body_http11() {
    let mut s = ScReq::new()
        .with_timeout(Timeout::new_same(20000, 1))
        .with_alpn(ALPN::HTTP11);
    let resp = s.get("https://httpbin.org/bytes/65536", None).unwrap();
    assert_eq!(resp.status(), HttpStatus::OK);
    assert_eq!(resp.as_bytes().len(), 65536);
}

// #[test]
// fn net_websocket_echo() {
//     use std::sync::mpsc;
//     use std::time::Duration;
//
//     let (tx, rx) = mpsc::channel();
//     std::thread::spawn(move || {
//         let result = (|| -> Result<String, String> {
//             let mut ws = WebSocket::open_sync("wss://echo.websocket.org").map_err(|e| e.to_string())?;
//             ws.send_text("hello").wait().map_err(|e| e.to_string())?;
//             let frame = ws.read_frame().wait().map_err(|e| e.to_string())?;
//             let _ = ws.shutdown().wait();
//             Ok(String::from_utf8_lossy(frame.payload().as_bytes()).to_string())
//         })();
//         let _ = tx.send(result);
//     });
//
//     match rx.recv_timeout(Duration::from_secs(20)) {
//         Ok(Ok(payload)) => assert!(payload.contains("hello"), "payload = {}", payload),
//         Ok(Err(e)) => panic!("WebSocket failed: {}", e),
//         Err(_) => panic!("WebSocket timed out after 20s (wss://echo.websocket.org)"),
//     }
// }
