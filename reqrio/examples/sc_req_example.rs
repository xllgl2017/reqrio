use reqrio::*;

fn build_finger() -> Fingerprint {
    let tls = TlsFinger::Custom {
        record_version: Version::TLS_1_0,
        message_version: Version::TLS_1_2,
        suites: vec![
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite::TLS_AES_128_GCM_SHA256,
            CipherSuite::TLS_AES_256_GCM_SHA384,
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
        ],
        extensions: vec![
            Extension::StatusRequest(StatusRequest::new()),
            Extension::SupportedGroups(SupportedGroups::new(vec![
                NamedCurve::X25519.into(),
                NamedCurve::SecP256r1.into(),
                NamedCurve::SecP384r1.into(),
                NamedCurve::SecP521r1.into(),
            ])),
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
            Extension::CompressionCertificate(CompressCertificate::new(vec![CompressionMethod::BROTLI])),
            Extension::SessionTicket(Buf::Ref(&[])),
            Extension::SupportedVersions(SupportVersions::new(vec![
                Version::TLS_1_3,
                Version::TLS_1_2
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
    let h2 = H2Finger {
        setting: vec![
            H2Setting::EnablePush(0),
            H2Setting::HeaderTableSize(4096),
            H2Setting::InitialWindowSize(8192),
            H2Setting::MaxHeaderListSize(242144)
        ],
        window_size: 2147418112,
        weight: 234,
        priority: true,
    };
    Fingerprint::new_h2(tls, h2, "<token>").unwrap()
}

fn custom_fingerprint_example() {
    let mut req = ScReq::new().with_fingerprint(build_finger());
    let resp = req.get("https://www.baidu.com", None).unwrap();
    println!("{}", resp.header());
}

fn form_post_example() {
    let data = json::object! {
        key1: "value1",
        key2: "value2",
        key3: "[{\"id\":44382959111,\"",// non-encode
    };
    let mut req = ScReq::new();
    let url = "https://www.baidu.com/api/test";
    let resp = req.post(url, data.form()).unwrap();
    println!("{}", resp.header());
}

fn json_post_example() {
    let data = json::object! {
        key1: "value1",
        key2: "value2",
        key3: "%5B%7B%22id%22%3A44382959111%2C%22",
    };
    let mut req = ScReq::new();
    let url = "https://www.baidu.com/api/test";
    let resp = req.post(url, data).unwrap();
    println!("{}", resp.header());
}

fn params_get_example() {
    let params = json::object! {
        "p1": "[{\"id\":44382959111,\"",// non-encode
        "p2": 1,
        "p3": null,
    };
    let mut req = ScReq::new();
    let url = "https://www.baidu.com/api/test";
    let resp = req.post(url.params(params), None).unwrap();
    println!("{}", resp.header());
}


fn ip_sni_get_example() {
    let mut req = ScReq::new();
    let url = "https://183.2.172.177/api/test";
    let resp = req.get(url.sni("www.baidu.com"), None).unwrap();
    println!("{}", resp.header());
}

fn bytes_post_example() {
    let mut req = ScReq::new();
    let url = "https://www.baidu.com/api/test";
    let data: Vec<u8> = (0..255).collect();
    let resp = req.post(url, data.ty(Application::OctetStream)).unwrap();
    println!("{}", resp.header());
}

fn file_post_example() {
    let mut req = ScReq::new();
    let url = "https://www.baidu.com/api/test";
    let file = HttpFile::new_path("README.md").unwrap();
    let resp = req.post(url, file).unwrap();
    println!("{}", resp.header());
}


fn file_form_post_example() {
    let mut req = ScReq::new();
    let url = "https://www.baidu.com/api/test";
    let data = json::object! {
        key1: "value1",
        key2: "value2",
        key3: "[{\"id\":44382959111,\"",
    };
    let file = HttpFile::new_path_data(data, "README.md").unwrap();
    let resp = req.post(url, file).unwrap();
    println!("{}", resp.header());
}

fn proxy_get_example() {
    let mut req = ScReq::new()
        .with_proxy(Proxy::new_http_plain("127.0.0.1", 222));
    let url = "https://www.baidu.com/api/test";
    let resp = req.get(url, None).unwrap();
    println!("{}", resp.header());
}

fn socks5_auth_get_example() {
    let mut req = ScReq::new();
    req.set_proxy(Proxy::Socks5(Url::try_from("socks5://username:password@127.0.0.1:1242").unwrap()));
    let url = "https://www.baidu.com/api/test";
    let resp = req.get(url, None).unwrap();
    println!("{}", resp.header());
}

fn main() {
    custom_fingerprint_example();
    form_post_example();
    json_post_example();
    params_get_example();
    ip_sni_get_example();
    bytes_post_example();
    file_post_example();
    file_form_post_example();
    file_form_post_example();
    proxy_get_example();
    socks5_auth_get_example();
}