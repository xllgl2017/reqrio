use std::{env, fs};
use std::sync::LazyLock;
use reqrio::*;

static TOKEN: LazyLock<String> = LazyLock::new(|| fs::read_to_string("../TOKEN").unwrap_or(env::var("REQRIO_TOKEN").unwrap_or("".to_string())));


#[test]
#[cfg(not(feature = "staticlink"))]
fn test_quic() {
    Fingerprint::check_subscription(TOKEN.as_str());
    let mut req = ScReq::new().with_alpn(ALPN::HTTP30);
    let resp = req.get("https://www.bing.com", None).unwrap();
    assert_eq!(resp.status(), HttpStatus::OK)
}

#[cfg(all(feature = "aync", not(feature = "staticlink")))]
#[tokio::test]
async fn test_quic_async() {
    Fingerprint::check_subscription(TOKEN.as_str());
    let mut req = AcReq::new().with_alpn(ALPN::HTTP30);
    let resp = req.get("https://www.bing.com", None).await.unwrap();
    assert_eq!(resp.status(), HttpStatus::OK)
}