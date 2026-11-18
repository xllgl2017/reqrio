mod finger;
use reqrio::*;


#[test]
fn tlcp_sync() {
    let mut req = ScReq::new().with_fingerprint(finger::build_tlcp_finger());
    let resp = req.get("https://test.gmssl.cn", None).unwrap();
    assert_eq!(resp.status(), HttpStatus::OK);
}

#[cfg(feature = "aync")]
#[tokio::test]
async fn tlcp_async() {
    let mut req = AcReq::new().with_fingerprint(finger::build_tlcp_finger());
    let resp = req.get("https://test.gmssl.cn", None).await.unwrap();
    assert_eq!(resp.status(), HttpStatus::OK);
}
