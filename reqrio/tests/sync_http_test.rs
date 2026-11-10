mod sync_http;

use std::time::Instant;
use reqrio::{json, HttpStatus, ReqExt, ScReq, Timeout, Method};
use reqtls::ALPN;


#[test]
fn test_get() {
    let mut req = ScReq::new().with_alpn(ALPN::HTTP11);
    sync_http::http_get_matrix(&mut req, ALPN::HTTP11);
    let mut req = ScReq::new().with_alpn(ALPN::HTTP20);
    sync_http::http_get_matrix(&mut req, ALPN::HTTP20);
}

#[test]
fn test_method() {
    let mut req = ScReq::new().with_alpn(ALPN::HTTP11);
    sync_http::http_method(&mut req);
    let mut req = ScReq::new().with_alpn(ALPN::HTTP20);
    sync_http::http_method(&mut req);
}

#[test]
fn test_status() {
    let mut req = ScReq::new().with_alpn(ALPN::HTTP11);
    sync_http::http_status(&mut req);
    let mut req = ScReq::new().with_alpn(ALPN::HTTP20);
    sync_http::http_status(&mut req);
}


#[test]
fn test_auth() {
    let mut req = ScReq::new().with_alpn(ALPN::HTTP11);
    sync_http::http_auth(&mut req);
    let mut req = ScReq::new().with_alpn(ALPN::HTTP20);
    sync_http::http_auth(&mut req);
}


#[test]
fn test_query_param() {
    let mut req = ScReq::new().with_alpn(ALPN::HTTP11);
    sync_http::query_param(&mut req);
    let mut req = ScReq::new().with_alpn(ALPN::HTTP20);
    sync_http::query_param(&mut req);
}

#[test]
fn test_redirect() {
    let mut req = ScReq::new().with_alpn(ALPN::HTTP11);
    sync_http::http_redirect(&mut req);
    let mut req = ScReq::new().with_alpn(ALPN::HTTP20);
    sync_http::http_redirect(&mut req);
}

#[test]
fn test_cookie() {
    let mut req = ScReq::new().with_alpn(ALPN::HTTP11);
    sync_http::http_cookie(&mut req);
    let mut req = ScReq::new().with_alpn(ALPN::HTTP20);
    sync_http::http_cookie(&mut req);
}

#[test]
fn test_headers() {
    let mut req = ScReq::new().with_alpn(ALPN::HTTP11);
    sync_http::http_header(&mut req);
    let mut req = ScReq::new().with_alpn(ALPN::HTTP20);
    sync_http::http_header(&mut req);
}

#[test]
fn test_stream_req() {
    let mut req = ScReq::new().with_alpn(ALPN::HTTP11);
    sync_http::http_stream(&mut req);
    let mut req = ScReq::new().with_alpn(ALPN::HTTP20);
    sync_http::http_stream(&mut req);
}


#[test]
fn test_helper() {
    let mut req = ScReq::new().with_alpn(ALPN::HTTP11);
    sync_http::http_helper(&mut req);
    let mut req = ScReq::new().with_alpn(ALPN::HTTP20);
    sync_http::http_helper(&mut req);
}

#[test]
fn test_body() {
    let mut req = ScReq::new().with_alpn(ALPN::HTTP11);
    sync_http::http_body(&mut req);
    let mut req = ScReq::new().with_alpn(ALPN::HTTP20);
    sync_http::http_body(&mut req);
}


#[test]
fn test_concurrency() {
    let mut req = ScReq::new().with_alpn(ALPN::HTTP11);
    sync_http::http_concurrency(&mut req);
    let mut req = ScReq::new().with_alpn(ALPN::HTTP20);
    sync_http::http_concurrency(&mut req);
}

#[test]
fn http_one_shot_api() {
    let res = reqrio::get("https://httpbin.reqrio.com/get", None).unwrap();
    assert_eq!(res.status(), HttpStatus::OK);
    let res = res.json().unwrap();
    assert_eq!(res["method"].to_string(), "GET");

    let res = reqrio::post("https://httpbin.reqrio.com/post", json::object! { "x": 1 }).unwrap();
    assert_eq!(res.status(), HttpStatus::OK);
    let res = res.json().unwrap();
    assert_eq!(res["json"]["x"].to_string(), "1");

    let res = reqrio::put("https://httpbin.reqrio.com/put", "raw").unwrap();
    assert_eq!(res.status(), HttpStatus::OK);
    let res = res.json().unwrap();
    assert_eq!(res["data"].to_string(), "raw");
}

#[test]
fn test_large_body() {
    let mut req = ScReq::new().with_alpn(ALPN::HTTP11);
    let resp = req.get("https://httpbin.reqrio.com/bytes/65536", None).unwrap();
    assert_eq!(resp.status(), HttpStatus::OK);
    assert_eq!(resp.as_bytes().len(), 65536);
    let mut req = ScReq::new().with_alpn(ALPN::HTTP20);
    let resp = req.get("https://httpbin.reqrio.com/bytes/65536", None).unwrap();
    assert_eq!(resp.status(), HttpStatus::OK);
    assert_eq!(resp.as_bytes().len(), 65536);
}


#[test]
fn test_timeout() {
    let mut req = ScReq::new().with_timeout(Timeout::new_same(3000, 1));
    let start = Instant::now();
    let res = req.get("https://192.0.2.1/", None);
    assert!(res.is_err());
    let elapsed = start.elapsed().as_millis();
    assert!((3000..4000).contains(&elapsed), "{}", elapsed);

    let start = Instant::now();
    let sid = req.send(Method::GET, "https://httpbin.reqrio.com/delay/10", None).unwrap();
    let res = req.recv(sid);
    assert!(res.is_err());
    let elapsed = start.elapsed().as_millis();
    assert!(elapsed>=3000, "{}", elapsed);
}
