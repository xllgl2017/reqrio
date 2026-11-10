#![cfg(feature = "aync")]
mod finger;
use reqrio::{Fingerprint, HttpStatus, ReqExt, AcReq};

#[tokio::test]
async fn test_ja3() {
    let fingerprint = Fingerprint::from_ja3(finger::JA3, finger::TOKEN.as_str()).unwrap();
    let mut req = AcReq::new().with_fingerprint(fingerprint);
    let resp = req.get("https://httpbin.reqrio.com", None).await.unwrap();
    assert_eq!(resp.status(), HttpStatus::OK)
}

#[tokio::test]
async fn test_ja4() {
    let fingerprint = Fingerprint::from_ja4(finger::JA4, finger::TOKEN.as_str()).unwrap();
    let mut req = AcReq::new().with_fingerprint(fingerprint);
    let resp = req.get("https://httpbin.reqrio.com", None).await.unwrap();
    assert_eq!(resp.status(), HttpStatus::OK)
}

#[tokio::test]
async fn test_custom() {
    let mut req = AcReq::new().with_fingerprint(finger::build_min_finger());
    let resp = req.get("https://httpbin.reqrio.com", None).await.unwrap();
    assert_eq!(resp.status(), HttpStatus::OK)
}

#[tokio::test]
async fn test_random() {
    let fingerprint = Fingerprint::random(finger::TOKEN.as_str());
    let mut req = AcReq::new().with_fingerprint(fingerprint);
    let resp = req.get("https://httpbin.reqrio.com", None).await.unwrap();
    assert_eq!(resp.status(), HttpStatus::OK)
}

#[tokio::test]
async fn test_builtin() {
    let fp = Fingerprint::from_builtin("win-x64-chrome-152", finger::TOKEN.as_str(), false).unwrap();
    let mut s = AcReq::new().with_fingerprint(fp);
    let res=s.get("https://httpbin.reqrio.com", None).await.unwrap();
    assert_eq!(res.status(), HttpStatus::OK);
}