//! [本测试由AI编写] 
//! 
//! 离线 API 契约测试 —— 依据 https://ms.xllgl.top/docs.html 编写。
//!
//! 覆盖文档中的：Method / Url / Header / Cookie / Body / HttpFile / Timeout /
//! Fingerprint / H2Finger / H3Finger / Sm2Key / HlsError / HTTPStream。
//! 这些用例不访问网络，可在任何环境稳定运行。

#![allow(clippy::redundant_clone)]

use reqrio::*;
use std::env;
use std::fs;
use std::sync::LazyLock;
use std::time::Duration;

static TOKEN: LazyLock<String> = LazyLock::new(|| {
    fs::read_to_string("../TOKEN")
        .ok()
        .map(|s| s.trim().to_string())
        .or_else(|| env::var("REQRIO_TOKEN").ok())
        .unwrap_or_default()
});

static AUTH: LazyLock<String> = LazyLock::new(|| {
    fs::read_to_string("../AUTH")
        .ok()
        .map(|s| s.trim().to_string())
        .or_else(|| env::var("REQRIO_AUTH").ok())
        .unwrap_or_default()
});

const JA3: &str = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,18-45-5-10-11-16-23-27-0-13-35-65281-43-51-17613,29-23-24,0";
const JA4: &str = "t13d1515h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,ff01_0804,0403,0401,0303,0402,080b,0201,0203,0202,0302,0502,0301,0503,0602,0806,0809";

// ---------------------------------------------------------------------------
// Method
// ---------------------------------------------------------------------------

#[test]
fn doc_method_enum_values() {
    assert_eq!(Method::GET as i32, 0);
    assert_eq!(Method::POST as i32, 1);
    assert_eq!(Method::PUT as i32, 2);
    assert_eq!(Method::HEAD as i32, 3);
    assert_eq!(Method::DELETE as i32, 4);
    assert_eq!(Method::OPTIONS as i32, 5);
    assert_eq!(Method::TRACE as i32, 6);
    assert_eq!(Method::CONNECT as i32, 7);
    assert_eq!(Method::PATCH as i32, 8);
    assert_eq!(Method::QUERY as i32, 9);
}

// ---------------------------------------------------------------------------
// Timeout
// ---------------------------------------------------------------------------

#[test]
fn doc_timeout_values() {
    let t = Timeout::new_same(1500, 4);
    assert_eq!(t.connect(), Duration::from_millis(1500));
    assert_eq!(t.read(), Duration::from_millis(1500));
    assert_eq!(t.write(), Duration::from_millis(1500));
    assert_eq!(t.handle(), Duration::from_millis(1500));
    assert_eq!(t.connect_times(), 4);
    assert_eq!(t.handle_times(), 4);

    let mut t = Timeout::default();
    t.set_connect(1234);
    t.set_read(2345);
    t.set_write(3456);
    t.set_handle(4567);
    t.set_connect_times(7);
    t.set_handle_times(8);
    assert_eq!(t.connect(), Duration::from_millis(1234));
    assert_eq!(t.read(), Duration::from_millis(2345));
    assert_eq!(t.write(), Duration::from_millis(3456));
    assert_eq!(t.handle(), Duration::from_millis(4567));
    assert_eq!(t.handle_times(), 8);

    assert!(Timeout::longer().connect() > t.connect());
}

/// `set_handle_times` 不应修改 `connect_times`，但实现里两者被绑定。
#[test]
fn doc_contract_timeout_setters_are_independent() {
    let mut t = Timeout::default();
    t.set_connect_times(7);
    t.set_handle_times(8);
    assert_eq!(t.handle_times(), 8);
    assert_eq!(
        t.connect_times(),
        7,
        "set_handle_times(8) unexpectedly changed connect_times to {}",
        t.connect_times()
    );
}

// ---------------------------------------------------------------------------
// Url / UrlExt / ReqUrl
// ---------------------------------------------------------------------------

#[test]
fn doc_url_params_and_sni() {
    let url = "https://httpbin.org/get"
        .params(json::object! {"q" => "reqrio", "page" => 1})
        .expect("params() should build url");
    let s = url.to_string();
    assert!(s.starts_with("https://httpbin.org/get?"), "url = {}", s);
    assert!(s.contains("q=reqrio"), "url = {}", s);
    assert!(s.contains("page=1"), "url = {}", s);

    let url = "https://104.18.34.137"
        .sni("whatnot.com")
        .expect("sni() should build url");
    assert_eq!(url.sni(), "whatnot.com");
    assert_eq!(url.addr().host(), "104.18.34.137");

    // 特殊字符应被 URL 编码
    let url = "https://example.com/a b"
        .params(json::object! {"q" => "a b&c"})
        .expect("params() should build url");
    let s = url.to_string();
    assert!(!s.contains("q=a b&c"), "query must be encoded, got {}", s);
    assert!(s.contains("q=a%20b%26c") || s.contains("q=a+b%26c"), "got {}", s);
}

#[test]
fn doc_url_invalid_input() {
    assert!("not-a-url".params(json::object! {}).is_err());
    assert!(Url::try_from("also not a url").is_err());
}

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

#[test]
fn doc_header_defaults_and_mutation() {
    let h1 = Header::new_req_h1();
    let h2 = Header::new_req_h2();
    let ua1 = h1.user_agent().unwrap_or_default();
    let ua2 = h2.user_agent().unwrap_or_default();
    assert!(ua1.contains("reqrio"), "h1 UA = {}", ua1);
    assert!(ua2.contains("reqrio"), "h2 UA = {}", ua2);
    assert!(h2.get_str("accept-encoding").is_some());
    assert!(h2.get_str("sec-ch-ua").is_some());

    let mut h = Header::new_req_h2();
    h.insert("X-Test", "1");
    assert_eq!(h.get_str("X-Test"), Some("1"));
    assert_eq!(h.get_str("x-test"), Some("1"), "header names are case-insensitive");
    assert!(h.get("X-TEST").is_some());
    let removed = h.remove("x-test");
    assert!(removed.is_some());
    assert!(h.get_str("x-test").is_none());

    h.set_user_agent("MyAgent/1.0");
    assert_eq!(h.user_agent(), Some("MyAgent/1.0"));

    h.set_cookie("a=1; b=2");
    let cookies = h.cookies().expect("cookie header should be parsed");
    assert_eq!(cookies.len(), 2);
    assert_eq!(cookies[0].name(), "a");
    assert_eq!(cookies[0].value(), "1");

    h.add_cookie(Cookie::new_cookie("c", "3"));
    assert_eq!(h.cookies().unwrap().len(), 3);
}

#[test]
fn doc_reqext_configuration() {
    let mut req = ScReq::new()
        .with_timeout(Timeout::new_same(5000, 3))
        .with_verify(false)
        .with_auto_redirect(false)
        .with_max_redirect_exceeded(5)
        .with_proxy(Proxy::new_socks5("127.0.0.1", 1080))
        .with_alpn(ALPN::HTTP11)
        .with_version(Version::TLS_1_2);

    assert_eq!(req.timeout().connect(), Duration::from_millis(5000));
    assert!(req.proxy().to_string().contains("127.0.0.1:1080"));

    req.insert_header("X-Trace", "1");
    assert_eq!(req.header().get_str("X-Trace"), Some("1"));
    assert!(req.remove_header("X-Trace").is_some());

    req.set_auto_redirect(true);
    req.set_verify(true);
    req.set_max_redirect_exceeds(3);
    req.set_timeout(Timeout::new_same(1000, 1));
    assert_eq!(req.timeout().handle_times(), 1);

    let _ = req.with_env_key_log();
}

// ---------------------------------------------------------------------------
// Cookie
// ---------------------------------------------------------------------------

#[test]
fn doc_cookie_parse_and_manager() {
    let req_cookies = Cookie::from_req("a=1; b=2");
    assert_eq!(req_cookies.len(), 2);
    assert_eq!(req_cookies[0].name(), "a");
    assert_eq!(req_cookies[1].value(), "2");

    let ck = Cookie::from_res("sid=abc; expires=Fri, 19 Dec 2025 03:53:27 GMT; domain=.example.com; path=/; secure; samesite=none");
    assert_eq!(ck.name(), "sid");
    assert_eq!(ck.value(), "abc");
    assert_eq!(ck.domain(), ".example.com");
    assert_eq!(ck.path(), "/");
    assert!(ck.as_res().contains("sid=abc"));
    assert!(ck.as_req().contains("sid=abc"));

    // 文档声称 Rust 暴露 CookieManager，但 crate 根未导出（见异常汇总），
    // 因此这里只验证可访问的 Cookie 行为。
    let mut cookies = Cookie::from_req("a=1; b=2");
    cookies.push(Cookie::new_cookie("c", "3"));
    assert_eq!(cookies.len(), 3);
    assert_eq!(cookies.iter().filter(|c| c.name() == "a").count(), 1);
}

// ---------------------------------------------------------------------------
// Body / BodyExt / BodyData
// ---------------------------------------------------------------------------

#[test]
fn doc_body_conversions() {
    let body = Body::from("hello");
    assert_eq!(body.context_type().spec(), "text/plain");
    assert_eq!(body.to_string().unwrap(), "hello");

    let body = Body::from(String::from("hello"));
    assert_eq!(body.to_vec().unwrap(), b"hello".to_vec());

    let body = Body::from(b"abc".as_slice());
    assert_eq!(body.context_type().spec(), "application/octet-stream");
    assert_eq!(body.to_vec().unwrap(), b"abc".to_vec());

    let body = Body::from(vec![1u8, 2, 3]);
    assert_eq!(body.to_vec().unwrap(), vec![1u8, 2, 3]);

    let body = Body::from(&b"xyz"[..]);
    assert_eq!(body.to_vec().unwrap(), b"xyz".to_vec());

    let json = json::object! {"a" => 1, "b" => "two"};
    let body = Body::from(json.clone());
    assert_eq!(body.context_type().spec(), "application/json");
    let text = body.to_string().unwrap();
    assert!(text.contains("\"a\":1"), "json body = {}", text);

    let json = json::object! {"a" => 1};
    let body = json.ty(Application::Json);
    assert_eq!(body.context_type().spec(), "application/json");

    let form = json::object! {"a" => "1", "b" => "x y"};
    let body = form.form();
    assert_eq!(body.context_type().spec(), "application/x-www-form-urlencoded");
    let text = body.to_string().unwrap();
    assert!(text.contains("a=1"), "form = {}", text);
    assert!(text.contains("b=x"), "form = {}", text);

    assert!(Body::none().to_vec().unwrap().is_empty());
    assert_eq!(Body::none().context_type().spec(), "");
}

#[cfg(feature = "serde")]
#[test]
fn doc_body_json_form_serde() {
    #[derive(serde::Serialize)]
    struct Payload {
        a: i32,
        b: &'static str,
    }

    let body = Body::json(&Payload { a: 7, b: "x" }).unwrap();
    assert_eq!(body.context_type().spec(), "application/json");
    assert_eq!(body.to_string().unwrap(), "{\"a\":7,\"b\":\"x\"}");

    let body = Body::form(&Payload { a: 7, b: "x" }).unwrap();
    assert_eq!(body.context_type().spec(), "application/x-www-form-urlencoded");
    let text = body.to_string().unwrap();
    assert!(text.contains("a=7"), "form = {}", text);
    assert!(text.contains("b=x"), "form = {}", text);
}

// ---------------------------------------------------------------------------
// HttpFile / FileForm (multipart)
// ---------------------------------------------------------------------------

#[test]
fn doc_multipart_file_body() {
    let mut file = HttpFile::new_bytes_data(json::object! {"k" => "v"}, b"file-content".to_vec());
    file.add_form(
        FileForm::new_bytes(b"second-file".to_vec())
            .with_field_name("file2")
            .with_filename("b.txt")
            .with_filetype("text/plain"),
    );
    assert_eq!(file.forms().len(), 2);
    assert_eq!(file.forms()[0].filename(), "1223.txt");

    let body = Body::from(file);
    let ct = body.context_type().spec().to_string();
    assert!(ct.starts_with("multipart/form-data; boundary="), "content-type = {}", ct);
    let data = body.to_vec().unwrap();
    let text = String::from_utf8_lossy(&data);
    assert!(text.contains("name=\"k\""), "multipart = {}", text);
    assert!(text.contains("file-content"), "multipart = {}", text);
    assert!(text.contains("name=\"file2\""), "multipart = {}", text);
    assert!(text.contains("filename=\"b.txt\""), "multipart = {}", text);
    assert!(text.contains("Content-Type: text/plain"), "multipart = {}", text);

    // 路径方式
    let path = env::temp_dir().join("reqrio_docs_upload.txt");
    fs::write(&path, b"path-file-content").unwrap();
    let mut file = HttpFile::new_path(&path).unwrap();
    file.set_data(json::object! {"f" => "1"});
    let body = Body::from(file);
    let data = body.to_vec().unwrap();
    assert!(String::from_utf8_lossy(&data).contains("path-file-content"));
    let _ = fs::remove_file(path);

    // 文件不存在时，构造不报错，真正读取时才失败
    let missing = FileForm::new_path("definitely-not-exists-12345.txt").unwrap();
    assert!(missing.filesize().is_err());
}

// ---------------------------------------------------------------------------
// Proxy
// ---------------------------------------------------------------------------

#[test]
fn doc_proxy_constructors_and_parse() {
    let p = Proxy::new_http_plain("127.0.0.1", 8888);
    assert!(p.to_string().contains("127.0.0.1:8888"));
    let p = Proxy::new_socks5("127.0.0.1", 1080);
    assert!(p.to_string().contains("1080"));

    // 文档示例使用 `"...".parse()?`，但实现只有 TryFrom<&str>，没有 FromStr。
    let p = Proxy::try_from("socks5://user:pass@127.0.0.1:1080").unwrap();
    let s = p.to_string();
    assert!(s.contains("socks5"), "proxy = {}", s);
    assert!(s.contains("127.0.0.1"), "proxy = {}", s);

    let p = Proxy::try_from("http://127.0.0.1:8888").unwrap();
    assert!(p.to_string().contains("8888"));
    assert!(matches!(Proxy::Null.to_string().as_str(), "Null"));
}

// ---------------------------------------------------------------------------
// Fingerprint
// ---------------------------------------------------------------------------

#[test]
fn doc_fingerprint_constructors() {
    let token = TOKEN.as_str();
    assert_eq!(Fingerprint::compute_id().len(), 64);

    let fp = Fingerprint::from_ja3(JA3, token).expect("valid JA3 should parse");
    assert!(matches!(fp.tls(), TlsFinger::Custom { .. }));

    let fp = Fingerprint::from_ja4(JA4, token).expect("valid JA4 should parse");
    assert!(matches!(fp.tls(), TlsFinger::Custom { .. }));

    let fp = Fingerprint::random(token);
    assert!(matches!(fp.tls(), TlsFinger::Custom { .. }));

    let mut fp = Fingerprint::new_custom(Version::TLS_1_2, Version::TLS_1_2, token);
    if let TlsFinger::Custom { suites, extensions, .. } = fp.tls_mut() {
        suites.push(CipherSuite::TLS_AES_128_GCM_SHA256);
        suites.push(CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
        extensions.push(Extension::SupportedGroups(vec![NamedCurve::X25519]));
        extensions.push(Extension::ApplicationLayerProtocolNegotiation(vec![
            ALPN::HTTP20,
            ALPN::HTTP11,
        ]));
    } else {
        panic!("new_custom should produce TlsFinger::Custom");
    }
    fp.h2_mut().set_priority(true, 147);
    assert!(fp.h2().priority);
    assert_eq!(fp.h2().weight, 147);

    let tls = TlsFinger::Custom {
        record_version: Version::TLS_1_0,
        message_version: Version::TLS_1_2,
        suites: vec![CipherSuite::TLS_AES_128_GCM_SHA256],
        extensions: vec![Extension::SupportedGroups(vec![NamedCurve::X25519])],
    };
    let fp = Fingerprint::new_tls(tls, token).expect("new_tls");
    assert!(matches!(fp.tls(), TlsFinger::Custom { .. }));

    let tls = TlsFinger::Custom {
        record_version: Version::TLS_1_0,
        message_version: Version::TLS_1_2,
        suites: vec![CipherSuite::TLS_AES_128_GCM_SHA256],
        extensions: vec![Extension::SupportedGroups(vec![NamedCurve::X25519])],
    };
    let fp = Fingerprint::new_h2(tls, H2Finger::default(), token).expect("new_h2");
    assert!(!fp.h2().frames.is_empty());

    assert!(Fingerprint::from_ja3("not,a,ja3", token).is_err());
    assert!(Fingerprint::from_ja4("bad-ja4", token).is_err());
    assert!(Fingerprint::from_record_hex("zz", token).is_err());
}

#[test]
fn doc_h2finger_frames_and_priority() {
    let mut h2 = H2Finger::default();
    assert!(!h2.frames.is_empty());
    let before = h2.frames.len();
    h2.add_frame(H2Frame::new_setting(vec![H2Setting::HeaderTableSize(65536)]));
    assert_eq!(h2.frames.len(), before + 1);
    h2.set_priority(true, 220);
    assert!(h2.priority);
    assert_eq!(h2.weight, 220);
    let h2 = h2.with_priority(false, 10);
    assert!(!h2.priority);
    assert_eq!(h2.weight, 10);
}

#[cfg(feature = "quic")]
#[test]
fn doc_h3finger() {
    let fp = Fingerprint::default();
    assert!(!fp.h3().frames.is_empty(), "default H3Finger should contain SETTINGS");

    let mut fp = Fingerprint::new_custom(Version::TLS_1_2, Version::TLS_1_2, TOKEN.as_str());
    assert!(fp.h3().frames.is_empty());
    fp.h3_mut().frames.push(H3Frame::new_setting(vec![H3Setting::new(
        H3Setting::MaxTableCapacity,
        65536,
    )]));
    assert_eq!(fp.h3().frames.len(), 1);

    let tls = TlsFinger::Custom {
        record_version: Version::TLS_1_0,
        message_version: Version::TLS_1_2,
        suites: vec![CipherSuite::TLS_AES_128_GCM_SHA256],
        extensions: vec![Extension::SupportedGroups(vec![NamedCurve::X25519])],
    };
    let fp = Fingerprint::new_h3(tls, Default::default(), TOKEN.as_str()).expect("new_h3");
    assert!(!fp.h3().frames.is_empty());
}

#[test]
fn doc_fingerprint_builtin() {
    let r = Fingerprint::from_builtin("win-x64-chrome-152", TOKEN.as_str(), false);
    assert!(
        r.is_ok(),
        "Fingerprint::from_builtin(win-x64-chrome-152) failed: {}",
        r.err().map(|e| e.to_string()).unwrap_or_default()
    );
}

// ---------------------------------------------------------------------------
// SM2 (国密)
// ---------------------------------------------------------------------------

#[test]
fn doc_sm2_sign_verify_encrypt_decrypt() {
    let key = Sm2Key::generate().expect("sm2 generate");
    let sign = key.sign(None::<&[u8]>, b"message").expect("sm2 sign");
    key.verify(None, b"message", &sign).expect("sm2 verify");
    assert!(key.verify(None, b"other-message", &sign).is_err());

    let cipher = key.encrypt(Sm2Model::C1C3C2, false, b"secret").expect("sm2 encrypt");
    let plain = key.decrypt(Sm2Model::C1C3C2, &cipher).expect("sm2 decrypt");
    assert_eq!(plain, b"secret");

    let cipher = key.encrypt(Sm2Model::C1C2C3, false, b"secret2").expect("sm2 encrypt");
    let plain = key.decrypt(Sm2Model::C1C2C3, &cipher).expect("sm2 decrypt");
    assert_eq!(plain, b"secret2");

    let pri = key.pri_key().expect("sm2 pri key");
    let imported = Sm2Key::from_pri_key(pri).expect("sm2 from_pri_key");
    let pub_key = imported.pub_key(false).expect("sm2 pub key");
    assert!(!pub_key.is_empty());
    let _ = Sm2Key::from_pub_key(&pub_key).expect("sm2 from_pub_key");
    // GM/T 0003 的 premaster 前两字节固定为 1,1，其余随机
    let mut pms = [0x5au8; 48];
    pms[0] = 1;
    pms[1] = 1;
    assert!(!key.encrypt_premaster(&pms).unwrap().is_empty());
    assert!(Sm2Key::none().is_null());
}

// ---------------------------------------------------------------------------
// Error / HTTPStream / misc
// ---------------------------------------------------------------------------

#[test]
fn doc_error_display() {
    let e = HlsError::from("boom");
    assert_eq!(e.to_string(), "boom");
    let e = HlsError::from(TimeError::ConnectTimeout);
    assert!(e.to_string().contains("ConnectTimeout"), "display = {}", e);
    let e: HlsError = TimeError::ReadTimeout.into();
    assert!(e.to_string().contains("ReadTimeout"), "display = {}", e);
}

#[test]
fn doc_http_status_and_alpn() {
    assert_eq!(HttpStatus::OK.code(), 200);
    assert_eq!(HttpStatus::Found.code(), 302);
    assert_eq!(HttpStatus::SwitchingProtocols.code(), 101);
    assert_eq!(HttpStatus::new(404).code(), 404);

    assert_eq!(ALPN::HTTP11.value(), "http/1.1");
    assert_eq!(ALPN::HTTP20.value(), "h2");
    #[cfg(feature = "quic")]
    assert_eq!(ALPN::HTTP30.value(), "h3");
    assert_eq!(ALPN::HTTP20.to_string(), "HTTP/2.0");

    let versions = [
        Version::TLS_1_2,
        Version::TLS_1_3,
        Version::TLCP,
    ];
    assert_eq!(versions[0], Version::TLS_1_2);
    assert_eq!(versions[1], Version::TLS_1_3);
    assert_eq!(versions[2], Version::TLCP);
}

#[test]
fn doc_tls_tlcp_fingerprint_shape() {
    let fp = Fingerprint::new_tls(
        TlsFinger::Custom {
            record_version: Version::TLCP,
            message_version: Version::TLCP,
            suites: vec![CipherSuite::ECC_SM4_CBC_SM3],
            extensions: vec![
                Extension::Reserved { typ: ExtensionType::new(0xfafa), value: Buf::default() },
                Extension::ServerName(vec![ServerName::HOSTNAME]),
                Extension::Reserved { typ: ExtensionType::new(0x8a8a), value: Buf::new_ref(&[0]) },
            ],
        },
        TOKEN.as_str(),
    )
    .expect("TLCP fingerprint");
    match fp.tls() {
        TlsFinger::Custom { record_version, message_version, suites, extensions } => {
            assert_eq!(*record_version, Version::TLCP);
            assert_eq!(*message_version, Version::TLCP);
            assert_eq!(*suites, vec![CipherSuite::ECC_SM4_CBC_SM3]);
            assert_eq!(extensions.len(), 3);
        }
        _ => panic!("TLCP fingerprint should be TlsFinger::Custom"),
    }
}
