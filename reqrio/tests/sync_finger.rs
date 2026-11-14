mod finger;
use reqrio::{Fingerprint, HttpStatus, ReqExt, ScReq};

#[test]
fn test_ja3() {
    let fingerprint = Fingerprint::from_ja3(finger::JA3, finger::TOKEN.as_str()).unwrap();
    let mut req = ScReq::new().with_fingerprint(fingerprint);
    let resp = req.get("https://httpbin.reqrio.com", None).unwrap();
    assert_eq!(resp.status(), HttpStatus::OK)
}

#[test]
fn test_ja4() {
    let fingerprint = Fingerprint::from_ja4(finger::JA4, finger::TOKEN.as_str()).unwrap();
    let mut req = ScReq::new().with_fingerprint(fingerprint);
    let resp = req.get("https://httpbin.reqrio.com", None).unwrap();
    assert_eq!(resp.status(), HttpStatus::OK)
}

#[test]
fn test_custom() {
    let mut req = ScReq::new().with_fingerprint(finger::build_min_finger());
    let resp = req.get("https://httpbin.reqrio.com", None).unwrap();
    assert_eq!(resp.status(), HttpStatus::OK)
}

#[test]
fn test_random() {
    let fingerprint = Fingerprint::random(finger::TOKEN.as_str());
    let mut req = ScReq::new().with_fingerprint(fingerprint);
    let resp = req.get("https://httpbin.reqrio.com", None).unwrap();
    assert_eq!(resp.status(), HttpStatus::OK)
}

#[test]
fn test_builtin() {
    // assert!(Fingerprint::from_builtin("win-x64-edge-148", finger::TOKEN.as_str(), false).is_ok());
    assert!(Fingerprint::from_builtin("win-x64-edge-148-h3", finger::TOKEN.as_str(), false).is_ok());
    assert!(Fingerprint::from_builtin("win-x64-edge-156", finger::TOKEN.as_str(), false).is_ok());
    assert!(Fingerprint::from_builtin("win-x64-edge-156-h3", finger::TOKEN.as_str(), false).is_ok());
    assert!(Fingerprint::from_builtin("win-x64-chrome-137", finger::TOKEN.as_str(), false).is_ok());
    assert!(Fingerprint::from_builtin("win-x64-chrome-137-h3", finger::TOKEN.as_str(), false).is_ok());
    assert!(Fingerprint::from_builtin("win-x64-chrome-141", finger::TOKEN.as_str(), false).is_ok());
    assert!(Fingerprint::from_builtin("win-x64-chrome-141-h3", finger::TOKEN.as_str(), false).is_ok());
    assert!(Fingerprint::from_builtin("win-x64-chrome-148", finger::TOKEN.as_str(), false).is_ok());
    assert!(Fingerprint::from_builtin("win-x64-chrome-148-h3", finger::TOKEN.as_str(), false).is_ok());
    assert!(Fingerprint::from_builtin("win-x64-chrome-152", finger::TOKEN.as_str(), false).is_ok());
    assert!(Fingerprint::from_builtin("win-x64-chrome-152-h3", finger::TOKEN.as_str(), false).is_ok());

    let fp = Fingerprint::from_builtin("win-x64-chrome-152", finger::TOKEN.as_str(), false).unwrap();
    let mut s = ScReq::new().with_fingerprint(fp);
    let res = s.get("https://httpbin.reqrio.com", None).unwrap();
    assert_eq!(res.status(), HttpStatus::OK);
}