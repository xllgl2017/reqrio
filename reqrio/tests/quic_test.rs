#![cfg(all(feature = "quic", not(feature = "staticlink")))]
use std::{env, fs};
use std::sync::LazyLock;
use reqrio::*;

static TOKEN: LazyLock<String> = LazyLock::new(|| fs::read_to_string("../TOKEN").unwrap_or(env::var("REQRIO_TOKEN").unwrap_or("".to_string())));


#[test]
fn test_quic() {
    Fingerprint::check_subscription(TOKEN.as_str());
    let mut req = ScReq::new().with_alpn(ALPN::HTTP30);
    let resp = req.get("https://www.bing.com", None).unwrap();
    assert_eq!(resp.status(), HttpStatus::OK)
}

#[cfg(feature = "aync")]
#[tokio::test]
async fn test_quic_async() {
    Fingerprint::check_subscription(TOKEN.as_str());
    let mut req = AcReq::new().with_alpn(ALPN::HTTP30);
    let resp = req.get("https://www.bing.com", None).await.unwrap();
    assert_eq!(resp.status(), HttpStatus::OK)
}