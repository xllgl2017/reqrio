mod finger;
use crate::finger::{DEFAULT_SIGNATURE, build_finger};
use reqrio::*;


fn build_sample_finger(suite: CipherSuite, curve: NamedCurve) -> Fingerprint {
    build_finger(
        vec![suite],
        vec![curve],
        DEFAULT_SIGNATURE.to_vec(),
        vec![ALPN::HTTP20, ALPN::HTTP11],
        vec![Version::TLS_1_3],
    )
}
#[tokio::test]
async fn test_tls13() {
    let mut req = AcReq::new().with_version(Version::TLS_1_3);
    req.get("https://httpbin.reqrio.com", None).await.unwrap();
    let conn = req.http_stream_mut().stream_mut().unwrap().tls_conn().unwrap();
    assert_eq!(conn.version(), Version::TLS_1_3);
}


#[tokio::test]
async fn test_tls13_cipher() {
    let fingerprint = build_sample_finger(CipherSuite::TLS_AES_128_GCM_SHA256, NamedCurve::X25519);
    let mut req = AcReq::new().with_fingerprint(fingerprint);
    req.get("https://httpbin.reqrio.com", None).await.unwrap();
    let conn = req.http_stream_mut().stream_mut().unwrap().tls_conn().unwrap();
    assert_eq!(conn.cipher_suite(), &CipherSuite::TLS_AES_128_GCM_SHA256);
    assert_eq!(conn.named_curve(), NamedCurve::X25519);
    assert_eq!(conn.version(), Version::TLS_1_3);

    let fingerprint = build_sample_finger(CipherSuite::TLS_AES_256_GCM_SHA384, NamedCurve::X25519);
    let mut req = AcReq::new().with_fingerprint(fingerprint);
    req.get("https://httpbin.reqrio.com", None).await.unwrap();
    let conn = req.http_stream_mut().stream_mut().unwrap().tls_conn().unwrap();
    assert_eq!(conn.cipher_suite(), &CipherSuite::TLS_AES_256_GCM_SHA384);
    assert_eq!(conn.named_curve(), NamedCurve::X25519);
    assert_eq!(conn.version(), Version::TLS_1_3);

    let fingerprint = build_sample_finger(CipherSuite::TLS_CHACHA20_POLY1305_SHA256, NamedCurve::X25519);
    let mut req = AcReq::new().with_fingerprint(fingerprint);
    req.get("https://httpbin.reqrio.com", None).await.unwrap();
    let conn = req.http_stream_mut().stream_mut().unwrap().tls_conn().unwrap();
    assert_eq!(conn.cipher_suite(), &CipherSuite::TLS_CHACHA20_POLY1305_SHA256);
    assert_eq!(conn.named_curve(), NamedCurve::X25519);
    assert_eq!(conn.version(), Version::TLS_1_3);
}

#[tokio::test]
async fn test_tls13_curve() {
    let fingerprint = build_sample_finger(CipherSuite::TLS_AES_128_GCM_SHA256, NamedCurve::X25519);
    let mut req = AcReq::new().with_fingerprint(fingerprint);
    req.get("https://httpbin.reqrio.com", None).await.unwrap();
    let conn = req.http_stream_mut().stream_mut().unwrap().tls_conn().unwrap();
    assert_eq!(conn.cipher_suite(), &CipherSuite::TLS_AES_128_GCM_SHA256);
    assert_eq!(conn.named_curve(), NamedCurve::X25519);
    assert_eq!(conn.version(), Version::TLS_1_3);

    let fingerprint = build_sample_finger(CipherSuite::TLS_AES_128_GCM_SHA256, NamedCurve::SecP256r1);
    let mut req = AcReq::new().with_fingerprint(fingerprint);
    req.get("https://httpbin.reqrio.com", None).await.unwrap();
    let conn = req.http_stream_mut().stream_mut().unwrap().tls_conn().unwrap();
    assert_eq!(conn.cipher_suite(), &CipherSuite::TLS_AES_128_GCM_SHA256);
    assert_eq!(conn.named_curve(), NamedCurve::SecP256r1);
    assert_eq!(conn.version(), Version::TLS_1_3);

    let fingerprint = build_sample_finger(CipherSuite::TLS_AES_128_GCM_SHA256, NamedCurve::SecP384r1);
    let mut req = AcReq::new().with_fingerprint(fingerprint);
    req.get("https://httpbin.reqrio.com", None).await.unwrap();
    let conn = req.http_stream_mut().stream_mut().unwrap().tls_conn().unwrap();
    assert_eq!(conn.cipher_suite(), &CipherSuite::TLS_AES_128_GCM_SHA256);
    assert_eq!(conn.named_curve(), NamedCurve::SecP384r1);
    assert_eq!(conn.version(), Version::TLS_1_3);

    let fingerprint = build_sample_finger(CipherSuite::TLS_AES_128_GCM_SHA256, NamedCurve::SecP521r1);
    let mut req = AcReq::new().with_fingerprint(fingerprint);
    req.get("https://httpbin.reqrio.com", None).await.unwrap();
    let conn = req.http_stream_mut().stream_mut().unwrap().tls_conn().unwrap();
    assert_eq!(conn.cipher_suite(), &CipherSuite::TLS_AES_128_GCM_SHA256);
    assert_eq!(conn.named_curve(), NamedCurve::SecP521r1);
    assert_eq!(conn.version(), Version::TLS_1_3);
}


#[tokio::test]
async fn test_hello_retry() {
    let mut req = AcReq::new().with_timeout(Timeout::longer()).with_alpn(ALPN::HTTP20).with_auto_redirect(false);
    let res = req.get("https://bing.com/", None).await.unwrap();
    assert_eq!(res.status(), HttpStatus::Move);
}