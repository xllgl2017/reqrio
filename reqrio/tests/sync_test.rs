use reqrio::*;
use std::fs;

#[test]
fn test_tls12() {
    //h1
    let mut req = ScReq::new().with_timeout(Timeout::longer());
    req.get("https://www.baidu.com", None).unwrap();
    //h2
    let mut req = ScReq::new().with_timeout(Timeout::longer()).with_alpn(ALPN::HTTP20);
    req.get("https://m.so.com", None).unwrap();
}

#[test]
fn test_tls13() {
    //h1
    let mut req = ScReq::new().with_timeout(Timeout::longer());
    req.get("https://m.sogou.com", None).unwrap();
    //h2
    let mut req = ScReq::new().with_timeout(Timeout::longer()).with_alpn(ALPN::HTTP20);
    req.get("https://m.sogou.com", None).unwrap();
}


#[test]
fn test_auto_redirect() {
    let mut req = ScReq::new().with_timeout(Timeout::longer()).with_alpn(ALPN::HTTP20).with_auto_redirect(false,);
    let res = req.get("https://m.so.com/jump?u=https%3A%2F%2Fmusic.163.com%2Fprogram%3Fid%3D901456263&m=824610&from=m.so.com&monitor=pro%3Dm_so%26pid%3Dresult%26u%3Dhttps%253A%252F%252Fm.so.com%252Fs%252F%26guid%3D14911145.7415413442912131315.1776792324389.8155%26mbp%3D0%26q%3Dewrwe%26pq%3D%26ls%3D%26abv%3D3984-control%252C3759-cpc_m_short_video_vertical_1%26ablist%3D%26sid%3D2548d9cd0087145e8d437af844fa059c%26qid%3D%26src%3Dmsearch_next_input%26srcg%3Dhome_next%26userid%3D%26nid%3D%26version%3D%26category%3D%26nettype%3Dunknown%26nav%3D%26chl%3D%26bv%3D%26adv_t%3D%26end%3D0%26bucketid%3D240001%252C350001%252C530001%252C540001%252C600000%252C750001%252C830001%252C850014%252C920001%252C1230009%252C1330001%252C3030000%252C4130001%252C4260003%252C4700000%252C4770000%252C4810001%252C4970002%252C5010009%252C5120000%252C5150001%252C5560001%252C5790000%252C5810001%252C5910001%252C6000000%252C6330024%252C6480000%252C6490000%252C6570003%252C6620003%252C6920004%252C7170010%252C7190027%252C7970001%252C8060001%252C8080002%252C8100011%252C8190003%252C8220000%252C8310003%252C8480001%252C8570012%252C8640000%252C8720008%252C9000027%252C9110000%252C9240006%252C9270010%252C9560006%252C9630014%252C10820000%252C10950002%252C11090000%252C11140000%252C11180001%252C11460000%252C11500004%252C11750001%26pn%3D1%26bzv%3D584d8cd4518f3435%26mod%3Dog%26pos%3D6%26type%3Dwap%26official%3D0%26pcurl%3Dhttps%253A%252F%252Fmusic.163.com%252Fprogram%253Fid%253D901456263%26data-md-b%3Dtitle%26url_fp%3DCgYIARADGAQ%253D%26screen%3D3%26scrTime%3D3%26af%3D0%26clicktype%3Dlink%26value%3Dhttps%253A%252F%252Fmusic.163.com%252Fprogram%253Fid%253D901456263%26t%3D1776792353084", None).unwrap();
    assert_eq!(res.header().status(), &HttpStatus::Found);

    //TLS_RSA_WITH_AES_128_CBC_SHA
    let mut req = ScReq::new().with_timeout(Timeout::longer());
    let res = req.get("https://m.so.com/jump?u=https%3A%2F%2Fmusic.163.com%2Fprogram%3Fid%3D901456263&m=824610&from=m.so.com&monitor=pro%3Dm_so%26pid%3Dresult%26u%3Dhttps%253A%252F%252Fm.so.com%252Fs%252F%26guid%3D14911145.7415413442912131315.1776792324389.8155%26mbp%3D0%26q%3Dewrwe%26pq%3D%26ls%3D%26abv%3D3984-control%252C3759-cpc_m_short_video_vertical_1%26ablist%3D%26sid%3D2548d9cd0087145e8d437af844fa059c%26qid%3D%26src%3Dmsearch_next_input%26srcg%3Dhome_next%26userid%3D%26nid%3D%26version%3D%26category%3D%26nettype%3Dunknown%26nav%3D%26chl%3D%26bv%3D%26adv_t%3D%26end%3D0%26bucketid%3D240001%252C350001%252C530001%252C540001%252C600000%252C750001%252C830001%252C850014%252C920001%252C1230009%252C1330001%252C3030000%252C4130001%252C4260003%252C4700000%252C4770000%252C4810001%252C4970002%252C5010009%252C5120000%252C5150001%252C5560001%252C5790000%252C5810001%252C5910001%252C6000000%252C6330024%252C6480000%252C6490000%252C6570003%252C6620003%252C6920004%252C7170010%252C7190027%252C7970001%252C8060001%252C8080002%252C8100011%252C8190003%252C8220000%252C8310003%252C8480001%252C8570012%252C8640000%252C8720008%252C9000027%252C9110000%252C9240006%252C9270010%252C9560006%252C9630014%252C10820000%252C10950002%252C11090000%252C11140000%252C11180001%252C11460000%252C11500004%252C11750001%26pn%3D1%26bzv%3D584d8cd4518f3435%26mod%3Dog%26pos%3D6%26type%3Dwap%26official%3D0%26pcurl%3Dhttps%253A%252F%252Fmusic.163.com%252Fprogram%253Fid%253D901456263%26data-md-b%3Dtitle%26url_fp%3DCgYIARADGAQ%253D%26screen%3D3%26scrTime%3D3%26af%3D0%26clicktype%3Dlink%26value%3Dhttps%253A%252F%252Fmusic.163.com%252Fprogram%253Fid%253D901456263%26t%3D1776792353084", None).unwrap();
    assert_eq!(res.header().status(), &HttpStatus::OK);
}

fn build_finger(suites: Vec<CipherSuite>, groups: Vec<NamedCurve>) -> Fingerprint {
    let tls = TlsFinger::Custom {
        record_version: Version::TLS_1_0,
        message_version: Version::TLS_1_2,
        suites,
        extensions: vec![
            Extension::StatusRequest(StatusRequest::new()),
            Extension::SupportedGroups(SupportedGroups::new(groups)),
            Extension::EcPointFormats(EcPointFormats::new(vec![EcPointFormat::UNCOMPRESSED])),
            Extension::SignatureAlgorithms(SignatureAlgorithms::new(vec![
                SignatureAlgorithm::RSA_PKCS1_SHA1.into(),
                SignatureAlgorithm::RSA_PKCS1_SHA256.into(),
                SignatureAlgorithm::RSA_PKCS1_SHA384.into(),
                SignatureAlgorithm::RSA_PKCS1_SHA512.into(),
                SignatureAlgorithm::ECDSA_SECP256R1_SHA256.into(),
                SignatureAlgorithm::ECDSA_SECP384R1_SHA384.into(),
                SignatureAlgorithm::ECDSA_SECP521R1_SHA512.into(),
                SignatureAlgorithm::RSA_PSS_PSS_SHA256.into(),
                SignatureAlgorithm::RSA_PSS_PSS_SHA384.into(),
                SignatureAlgorithm::RSA_PSS_PSS_SHA512.into(),
                SignatureAlgorithm::RSA_PSS_RSAE_SHA256.into(),
                SignatureAlgorithm::RSA_PSS_RSAE_SHA384.into(),
                SignatureAlgorithm::RSA_PSS_RSAE_SHA512.into(),
            ])),
            Extension::SignedCertificateTimestamp,
            Extension::ExtendMasterSecret,
            Extension::CompressionCertificate(CompressCertificate::new(vec![CompressionMethod::NULL])),
            Extension::SessionTicket(Buf::Ref(&[])),
            Extension::SupportedVersions(SupportVersions::new(vec![
                Version::TLS_1_3,
                Version::TLS_1_2,
            ])),
            Extension::PskKeyExchangeMode(vec![PskMode::new(PskMode::PSK_DHE_KE)]),
            Extension::KeyShare(KeyShare::new(vec![
                NamedCurve::X25519.into(),
                NamedCurve::SecP256r1.into(),
            ])),
            Extension::ApplicationSetting(ALPS::new(vec![
                ALPN::HTTP20,
                ALPN::HTTP11
            ])),
            Extension::ServerName(vec![ServerName::new_sni("")]),
            Extension::ApplicationLayerProtocolNegotiation(ALPS::new(vec![
                ALPN::HTTP20,
                ALPN::HTTP11
            ]))
        ],
    };
    Fingerprint::new_tls(tls, fs::read_to_string("../TOKEN").unwrap_or("".to_string())).unwrap()
}


#[test]
fn test_ecdhe_rsa() {
    let fingerprint = build_finger(
        vec![CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
        vec![NamedCurve::X25519.into()], );
    let mut req = ScReq::new().with_timeout(Timeout::longer()).with_fingerprint(fingerprint);
    req.get("https://m.so.com", None).unwrap();
    let fingerprint = build_finger(
        vec![CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384],
        vec![NamedCurve::X25519.into(), NamedCurve::SecP256r1.into()], );
    let mut req = ScReq::new().with_timeout(Timeout::longer()).with_fingerprint(fingerprint);
    req.get("https://m.so.com", None).unwrap();
    let fingerprint = build_finger(
        vec![CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256],
        vec![NamedCurve::X25519.into(), NamedCurve::SecP256r1.into()], );
    let mut req = ScReq::new().with_timeout(Timeout::longer()).with_fingerprint(fingerprint);
    req.get("https://m.so.com", None).unwrap();
    let fingerprint = build_finger(
        vec![CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA],
        vec![NamedCurve::X25519.into(), NamedCurve::SecP256r1.into()], );
    let mut req = ScReq::new().with_timeout(Timeout::longer()).with_fingerprint(fingerprint);
    req.get("https://m.so.com", None).unwrap();
    let fingerprint = build_finger(
        vec![CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA],
        vec![NamedCurve::X25519.into(), NamedCurve::SecP256r1.into()], );
    let mut req = ScReq::new().with_timeout(Timeout::longer()).with_fingerprint(fingerprint);
    req.get("https://m.so.com", None).unwrap();
    let fingerprint = build_finger(
        vec![CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256],
        vec![NamedCurve::X25519.into()]);
    let mut req = ScReq::new().with_timeout(Timeout::longer()).with_fingerprint(fingerprint);
    req.get("https://m.so.com", None).unwrap();
    let fingerprint = build_finger(
        vec![CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA256],
        vec![NamedCurve::X25519.into()], );
    let mut req = ScReq::new().with_timeout(Timeout::longer()).with_fingerprint(fingerprint);
    req.get("https://m.so.com", None).unwrap();

    let fingerprint = build_finger(
        vec![CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384],
        vec![NamedCurve::X25519.into()], );
    let mut req = ScReq::new().with_timeout(Timeout::longer()).with_fingerprint(fingerprint);
    req.get("https://m.so.com", None).unwrap();
}

///RSA
#[test]
fn test_rsa() {
    let fingerprint = build_finger(
        vec![CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA],
        vec![NamedCurve::X25519.into()], );
    let mut req = ScReq::new().with_timeout(Timeout::longer()).with_fingerprint(fingerprint);
    req.get("https://m.baidu.com", None).unwrap();
    let fingerprint = build_finger(
        vec![CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA],
        vec![NamedCurve::X25519.into()], );
    let mut req = ScReq::new().with_timeout(Timeout::longer()).with_fingerprint(fingerprint);
    req.get("https://m.baidu.com", None).unwrap();
}

#[test]
fn test_tls13_cipher() {
    let fingerprint = build_finger(
        vec![CipherSuite::TLS_AES_128_GCM_SHA256],
        vec![NamedCurve::X25519.into(), NamedCurve::SecP256r1.into()], );
    let mut req = ScReq::new().with_timeout(Timeout::longer()).with_fingerprint(fingerprint);
    req.get("https://m.sogou.com", None).unwrap();
    let fingerprint = build_finger(
        vec![CipherSuite::TLS_AES_256_GCM_SHA384],
        vec![NamedCurve::X25519.into(), NamedCurve::SecP256r1.into()], );
    let mut req = ScReq::new().with_timeout(Timeout::longer()).with_fingerprint(fingerprint);
    req.get("https://m.sogou.com", None).unwrap();
    let fingerprint = build_finger(
        vec![CipherSuite::TLS_CHACHA20_POLY1305_SHA256],
        vec![NamedCurve::X25519.into(), NamedCurve::SecP256r1.into()], );
    let mut req = ScReq::new().with_timeout(Timeout::longer()).with_fingerprint(fingerprint);
    req.get("https://m.sogou.com", None).unwrap();
}


#[test]
fn test_hello_retry() {
    let mut req = ScReq::new().with_timeout(Timeout::longer()).with_alpn(ALPN::HTTP20).with_auto_redirect(false);
    let res = req.get("https://bing.com/", None).unwrap();
    assert_eq!(res.header().status(), &HttpStatus::Move);
}