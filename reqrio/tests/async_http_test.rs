#![cfg(feature = "aync")]
mod async_http;

use reqrio::{AcReq, HttpStatus, Method, ReqExt, Timeout};
use reqtls::ALPN;
use std::time::Instant;


#[tokio::test]
async fn test_get() {
    let mut req = AcReq::new().with_alpn(ALPN::HTTP11);
    async_http::http_get_matrix(&mut req, ALPN::HTTP11).await;
    let mut req = AcReq::new().with_alpn(ALPN::HTTP20);
    async_http::http_get_matrix(&mut req, ALPN::HTTP20).await;
}

#[tokio::test]
async fn test_method() {
    let mut req = AcReq::new().with_alpn(ALPN::HTTP11);
    async_http::http_method(&mut req).await;
    let mut req = AcReq::new().with_alpn(ALPN::HTTP20);
    async_http::http_method(&mut req).await;
}

#[tokio::test]
async fn test_status() {
    let mut req = AcReq::new().with_alpn(ALPN::HTTP11);
    async_http::http_status(&mut req).await;
    let mut req = AcReq::new().with_alpn(ALPN::HTTP20);
    async_http::http_status(&mut req).await;
}


#[tokio::test]
async fn test_auth() {
    let mut req = AcReq::new().with_alpn(ALPN::HTTP11);
    async_http::http_auth(&mut req).await;
    let mut req = AcReq::new().with_alpn(ALPN::HTTP20);
    async_http::http_auth(&mut req).await;
}


#[tokio::test]
async fn test_query_param() {
    let mut req = AcReq::new().with_alpn(ALPN::HTTP11);
    async_http::query_param(&mut req).await;
    let mut req = AcReq::new().with_alpn(ALPN::HTTP20);
    async_http::query_param(&mut req).await;
}

#[tokio::test]
async fn test_redirect() {
    let mut req = AcReq::new().with_alpn(ALPN::HTTP11);
    async_http::http_redirect(&mut req).await;
    let mut req = AcReq::new().with_alpn(ALPN::HTTP20);
    async_http::http_redirect(&mut req).await;
}

#[tokio::test]
async fn test_cookie() {
    let mut req = AcReq::new().with_alpn(ALPN::HTTP11);
    async_http::http_cookie(&mut req).await;
    let mut req = AcReq::new().with_alpn(ALPN::HTTP20);
    async_http::http_cookie(&mut req).await;
}

#[tokio::test]
async fn test_headers() {
    let mut req = AcReq::new().with_alpn(ALPN::HTTP11);
    async_http::http_header(&mut req).await;
    let mut req = AcReq::new().with_alpn(ALPN::HTTP20);
    async_http::http_header(&mut req).await;
}

#[tokio::test]
async fn test_stream_req() {
    let mut req = AcReq::new().with_alpn(ALPN::HTTP11);
    async_http::http_stream(&mut req).await;
    let mut req = AcReq::new().with_alpn(ALPN::HTTP20);
    async_http::http_stream(&mut req).await;
}


#[tokio::test]
async fn test_helper() {
    let mut req = AcReq::new().with_alpn(ALPN::HTTP11);
    async_http::http_helper(&mut req).await;
    let mut req = AcReq::new().with_alpn(ALPN::HTTP20);
    async_http::http_helper(&mut req).await;
}

#[tokio::test]
async fn test_body() {
    let mut req = AcReq::new().with_alpn(ALPN::HTTP11);
    async_http::http_body(&mut req).await;
    let mut req = AcReq::new().with_alpn(ALPN::HTTP20);
    async_http::http_body(&mut req).await;
}


#[tokio::test]
async fn test_concurrency() {
    let mut req = AcReq::new().with_alpn(ALPN::HTTP11);
    async_http::http_concurrency(&mut req).await;
    let mut req = AcReq::new().with_alpn(ALPN::HTTP20);
    async_http::http_concurrency(&mut req).await;
}

#[tokio::test]
async fn test_large_body() {
    let mut req = AcReq::new().with_alpn(ALPN::HTTP11);
    let resp = req.get("https://httpbin.reqrio.com/bytes/65536", None).await.unwrap();
    assert_eq!(resp.status(), HttpStatus::OK);
    assert_eq!(resp.as_bytes().len(), 65536);
    let mut req = AcReq::new().with_alpn(ALPN::HTTP20);
    let resp = req.get("https://httpbin.reqrio.com/bytes/65536", None).await.unwrap();
    assert_eq!(resp.status(), HttpStatus::OK);
    assert_eq!(resp.as_bytes().len(), 65536);
}

#[tokio::test]
async fn  test_timeout() {
    let mut req = AcReq::new().with_timeout(Timeout::new_same(3000, 1));
    let start = Instant::now();
    let res = req.get("https://192.0.2.1/", None).await;
    assert!(res.is_err());
    let elapsed = start.elapsed().as_millis();
    assert!((3000..4000).contains(&elapsed), "{}", elapsed);

    let start = Instant::now();
    let sid = req.send(Method::GET, "https://httpbin.reqrio.com/delay/10", None).await.unwrap();
    let res = req.recv(sid).await;
    assert!(res.is_err());
    let elapsed = start.elapsed().as_millis();
    assert!((3000..6000).contains(&elapsed), "{}", elapsed);
}