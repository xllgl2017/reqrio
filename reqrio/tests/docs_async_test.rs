//! [本测试由AI编写] 
//!
//! 异步 API（feature = "aync"）契约测试 —— 依据 https://ms.xllgl.top/docs.html 编写。

#![cfg(feature = "aync")]

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

fn session() -> AcReq {
    AcReq::new()
        .with_timeout(Timeout::new_same(15000, 1))
        .with_alpn(ALPN::HTTP20)
}

#[tokio::test]
async fn net_async_basic_get() {
    let mut s = session();
    let resp = s.get("https://www.baidu.com", None).await.unwrap();
    assert_eq!(resp.status(), HttpStatus::OK);
    assert!(!resp.as_bytes().is_empty());
}

#[tokio::test]
async fn net_async_json_and_form() {
    let mut s = session();

    let body = json::object! {"a" => 1};
    let resp = s
        .post("https://httpbin.org/post", body.ty(Application::Json))
        .await
        .unwrap();
    assert_eq!(resp.status(), HttpStatus::OK);
    assert_eq!(resp.json().unwrap()["json"]["a"].to_string(), "1");

    let body = json::object! {"a" => "1"};
    let resp = s.post("https://httpbin.org/post", body.form()).await.unwrap();
    assert_eq!(resp.status(), HttpStatus::OK);
    assert_eq!(resp.json().unwrap()["form"]["a"].to_string(), "1");
}

#[tokio::test]
async fn net_async_send_recv() {
    let mut s = session();
    let sid = s
        .send(Method::GET, "https://httpbin.org/get?async=1", None)
        .await
        .unwrap();
    let resp = s.recv(sid).await.unwrap();
    assert_eq!(resp.status(), HttpStatus::OK);
    assert_eq!(resp.json().unwrap()["args"]["async"].to_string(), "1");
}

#[tokio::test]
async fn net_async_concurrent() {
    let mut s = session();
    let sid1 = s.send(Method::GET, "https://httpbin.org/get?x=1", None).await.unwrap();
    let sid2 = s.send(Method::GET, "https://httpbin.org/get?x=2", None).await.unwrap();
    let r2 = s.recv(sid2).await.unwrap();
    let r1 = s.recv(sid1).await.unwrap();
    assert_eq!(r2.status(), HttpStatus::OK);
    assert_eq!(r1.status(), HttpStatus::OK);
    assert_eq!(r2.json().unwrap()["args"]["x"].to_string(), "2");
    assert_eq!(r1.json().unwrap()["args"]["x"].to_string(), "1");
}

#[tokio::test]
async fn net_async_stream() {
    let mut s = AcReq::new()
        .with_timeout(Timeout::new_same(20000, 1))
        .with_alpn(ALPN::HTTP11);
    #[cfg(feature = "export")]
    let sid = s
        .send_stream(Method::GET, "https://httpbin.org/bytes/65536", None)
        .await
        .unwrap()
        .sid;
    #[cfg(not(feature = "export"))]
    let sid = s
        .send(Method::GET, "https://httpbin.org/bytes/65536", None)
        .await
        .unwrap();

    let mut total = 0usize;
    while let Some(chunk) = s.next_chunk(sid).await.unwrap() {
        total += chunk.len();
    }
    assert_eq!(total, 65536);
}

#[tokio::test]
async fn net_async_connect_and_reuse() {
    let mut s = AcReq::new()
        .with_timeout(Timeout::new_same(15000, 1))
        .connect("https://www.baidu.com")
        .await
        .unwrap();
    for _ in 0..2 {
        let resp = s.get("https://www.baidu.com", None).await.unwrap();
        assert_eq!(resp.status(), HttpStatus::OK);
    }
}

#[tokio::test]
async fn net_async_timeout_error() {
    let mut s = AcReq::new().with_timeout(Timeout::new_same(300, 1));
    let err = s.get("https://192.0.2.1/", None).await.err().expect("should fail");
    let msg = err.to_string();
    assert!(
        msg.contains("Time") || msg.to_lowercase().contains("timeout") || msg.to_lowercase().contains("connect"),
        "unexpected error: {}",
        msg
    );
}

#[tokio::test]
async fn net_async_fingerprint_ja3() {
    let fp = Fingerprint::from_ja3(JA3, TOKEN.as_str()).unwrap();
    let mut s = AcReq::new()
        .with_timeout(Timeout::new_same(15000, 1))
        .with_fingerprint(fp);
    assert_eq!(s.get("https://m.so.com", None).await.unwrap().status(), HttpStatus::OK);
}

#[cfg(all(not(feature = "staticlink"), feature = "quic"))]
#[tokio::test]
async fn net_async_http3() {
    let mut s = AcReq::new()
        .with_timeout(Timeout::new_same(15000, 1))
        .with_alpn(ALPN::HTTP30);
    let resp = s.get("https://www.bing.com", None).await.unwrap();
    assert_eq!(resp.status(), HttpStatus::OK);
}

// #[tokio::test]
// async fn net_async_websocket_echo() {
//     let result = tokio::time::timeout(std::time::Duration::from_secs(20), async {
//         let mut ws = WebSocket::open_async("wss://echo.websocket.org").await?;
//         ws.send_text("hello-async").await?;
//         let frame = ws.read_frame().await?;
//         let _ = ws.shutdown().await;
//         Ok::<String, HlsError>(String::from_utf8_lossy(frame.payload().as_bytes()).to_string())
//     })
//     .await;
//     match result {
//         Ok(Ok(payload)) => assert!(payload.contains("hello-async"), "payload = {}", payload),
//         Ok(Err(e)) => panic!("WebSocket failed: {}", e),
//         Err(_) => panic!("WebSocket timed out after 20s (wss://echo.websocket.org)"),
//     }
// }
