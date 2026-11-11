mod finger;

use crate::finger::{DEFAULT_SIGNATURE, build_finger};
use reqrio::{AcReq, Fingerprint, ReqExt, ReqStreamExt, Timeout};
use reqtls::{ALPN, CipherSuite, NamedCurve, Version};

fn build_sample_finger(suite: CipherSuite, curve: NamedCurve) -> Fingerprint {
    build_finger(
        vec![suite],
        vec![curve],
        DEFAULT_SIGNATURE.to_vec(),
        vec![ALPN::HTTP20, ALPN::HTTP11],
        vec![Version::TLS_1_2],
    )
}

#[tokio::test]
async fn test_version() {
    let mut req = AcReq::new().with_version(Version::TLS_1_2);
    req.get("https://httpbin.reqrio.com", None).await.unwrap();
    let conn = req.http_stream_mut().stream_mut().unwrap().tls_conn().unwrap();
    assert_eq!(conn.version(), Version::TLS_1_2);
}


#[tokio::test]
async fn test_ecdhe_rsa_gcm() {
    let fingerprint = build_sample_finger(CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, NamedCurve::X25519);
    let mut req = AcReq::new().with_timeout(Timeout::longer()).with_fingerprint(fingerprint);
    req.get("https://httpbin.reqrio.com", None).await.unwrap();
    let conn = req.http_stream_mut().stream_mut().unwrap().tls_conn().unwrap();
    assert_eq!(conn.version(), Version::TLS_1_2);
    assert_eq!(conn.cipher_suite(), CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
    assert_eq!(conn.named_curve(), NamedCurve::X25519);

    let fingerprint = build_sample_finger(CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, NamedCurve::X25519);
    let mut req = AcReq::new().with_timeout(Timeout::longer()).with_fingerprint(fingerprint);
    req.get("https://httpbin.reqrio.com", None).await.unwrap();
    let conn = req.http_stream_mut().stream_mut().unwrap().tls_conn().unwrap();
    assert_eq!(conn.version(), Version::TLS_1_2);
    assert_eq!(conn.cipher_suite(), CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
    assert_eq!(conn.named_curve(), NamedCurve::X25519);

    let fingerprint = build_sample_finger(CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, NamedCurve::X25519);
    let mut req = AcReq::new().with_timeout(Timeout::longer()).with_fingerprint(fingerprint);
    req.get("https://httpbin.reqrio.com", None).await.unwrap();
    let conn = req.http_stream_mut().stream_mut().unwrap().tls_conn().unwrap();
    assert_eq!(conn.version(), Version::TLS_1_2);
    assert_eq!(conn.cipher_suite(), CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
    assert_eq!(conn.named_curve(), NamedCurve::X25519);
}


#[tokio::test]
async fn test_tls12_curve() {
    let fingerprint = build_sample_finger(CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, NamedCurve::X25519);
    let mut req = AcReq::new().with_fingerprint(fingerprint);
    req.get("https://httpbin.reqrio.com", None).await.unwrap();
    let conn = req.http_stream_mut().stream_mut().unwrap().tls_conn().unwrap();
    assert_eq!(conn.cipher_suite(), &CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
    assert_eq!(conn.named_curve(), NamedCurve::X25519);
    assert_eq!(conn.version(), Version::TLS_1_2);

    let fingerprint = build_sample_finger(CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, NamedCurve::SecP256r1);
    let mut req = AcReq::new().with_fingerprint(fingerprint);
    req.get("https://httpbin.reqrio.com", None).await.unwrap();
    let conn = req.http_stream_mut().stream_mut().unwrap().tls_conn().unwrap();
    assert_eq!(conn.cipher_suite(), &CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
    assert_eq!(conn.named_curve(), NamedCurve::SecP256r1);
    assert_eq!(conn.version(), Version::TLS_1_2);

    let fingerprint = build_sample_finger(CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, NamedCurve::SecP384r1);
    let mut req = AcReq::new().with_fingerprint(fingerprint);
    req.get("https://httpbin.reqrio.com", None).await.unwrap();
    let conn = req.http_stream_mut().stream_mut().unwrap().tls_conn().unwrap();
    assert_eq!(conn.cipher_suite(), &CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
    assert_eq!(conn.named_curve(), NamedCurve::SecP384r1);
    assert_eq!(conn.version(), Version::TLS_1_2);

    let fingerprint = build_sample_finger(CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, NamedCurve::SecP521r1);
    let mut req = AcReq::new().with_fingerprint(fingerprint);
    req.get("https://httpbin.reqrio.com", None).await.unwrap();
    let conn = req.http_stream_mut().stream_mut().unwrap().tls_conn().unwrap();
    assert_eq!(conn.cipher_suite(), &CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
    assert_eq!(conn.named_curve(), NamedCurve::SecP521r1);
    assert_eq!(conn.version(), Version::TLS_1_2);
}


#[tokio::test]
async fn test_ecdhe_rsa_cbc() {
    let fingerprint = build_sample_finger(CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, NamedCurve::X25519);
    let mut req = AcReq::new().with_timeout(Timeout::longer()).with_fingerprint(fingerprint);
    req.get("https://httpbin.reqrio.com", None).await.unwrap();
    let conn = req.http_stream_mut().stream_mut().unwrap().tls_conn().unwrap();
    assert_eq!(conn.version(), Version::TLS_1_2);
    assert_eq!(conn.cipher_suite(), CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA);
    assert_eq!(conn.named_curve(), NamedCurve::X25519);

    let fingerprint = build_sample_finger(CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, NamedCurve::X25519);
    let mut req = AcReq::new().with_timeout(Timeout::longer()).with_fingerprint(fingerprint);
    req.get("https://httpbin.reqrio.com", None).await.unwrap();
    let conn = req.http_stream_mut().stream_mut().unwrap().tls_conn().unwrap();
    assert_eq!(conn.version(), Version::TLS_1_2);
    assert_eq!(conn.cipher_suite(), CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA);
    assert_eq!(conn.named_curve(), NamedCurve::X25519);

    let fingerprint = build_sample_finger(CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, NamedCurve::X25519);
    let mut req = AcReq::new().with_timeout(Timeout::longer()).with_fingerprint(fingerprint);
    req.get("https://httpbin.reqrio.com", None).await.unwrap();
    let conn = req.http_stream_mut().stream_mut().unwrap().tls_conn().unwrap();
    assert_eq!(conn.version(), Version::TLS_1_2);
    assert_eq!(conn.cipher_suite(), CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256);
    assert_eq!(conn.named_curve(), NamedCurve::X25519);

    let fingerprint = build_sample_finger(CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, NamedCurve::X25519);
    let mut req = AcReq::new().with_timeout(Timeout::longer()).with_fingerprint(fingerprint);
    req.get("https://httpbin.reqrio.com", None).await.unwrap();
    let conn = req.http_stream_mut().stream_mut().unwrap().tls_conn().unwrap();
    assert_eq!(conn.version(), Version::TLS_1_2);
    assert_eq!(conn.cipher_suite(), CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384);
    assert_eq!(conn.named_curve(), NamedCurve::X25519);
}


#[tokio::test]
async fn test_rsa_cbc() {
    let fingerprint = build_sample_finger(CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA256, NamedCurve::X25519);
    let mut req = AcReq::new().with_timeout(Timeout::longer()).with_fingerprint(fingerprint);
    req.get("https://m.so.com", None).await.unwrap();
    let conn = req.http_stream_mut().stream_mut().unwrap().tls_conn().unwrap();
    assert_eq!(conn.version(), Version::TLS_1_2);
    assert_eq!(conn.cipher_suite(), CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA256);
    assert_eq!(conn.named_curve(), NamedCurve::PreMaster);

    let fingerprint = build_sample_finger(CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA, NamedCurve::X25519);
    let mut req = AcReq::new().with_timeout(Timeout::longer()).with_fingerprint(fingerprint);
    req.get("https://m.baidu.com", None).await.unwrap();
    let conn = req.http_stream_mut().stream_mut().unwrap().tls_conn().unwrap();
    assert_eq!(conn.version(), Version::TLS_1_2);
    assert_eq!(conn.cipher_suite(), CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA);
    assert_eq!(conn.named_curve(), NamedCurve::PreMaster);

    let fingerprint = build_sample_finger(CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA, NamedCurve::X25519);
    let mut req = AcReq::new().with_timeout(Timeout::longer()).with_fingerprint(fingerprint);
    req.get("https://m.baidu.com", None).await.unwrap();
    let conn = req.http_stream_mut().stream_mut().unwrap().tls_conn().unwrap();
    assert_eq!(conn.version(), Version::TLS_1_2);
    assert_eq!(conn.cipher_suite(), CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA);
    assert_eq!(conn.named_curve(), NamedCurve::PreMaster);
}

#[tokio::test]
async fn test_tls_reuse() {
    let mut req = AcReq::new().with_version(Version::TLS_1_2);
    req.get("https://httpbin.reqrio.com", None).await.unwrap();
    req.re_conn(None).await.unwrap();
    req.get("https://httpbin.reqrio.com", None).await.unwrap();
    let conn = req.http_stream_mut().stream_mut().unwrap().tls_conn().unwrap();
    assert!(conn.certs().is_empty())
}