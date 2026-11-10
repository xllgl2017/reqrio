use reqrio::{Application, BodyData, ContentType, FileForm, HttpFile, HttpStatus, ImageType, Method, ReqExt, AcReq, Text, UrlExt, json, Body};
use reqtls::{ALPN, base64, coder, rand};

///Testing different types of requests
pub async fn http_get_matrix(req: &mut AcReq, alpn: ALPN) {
    let mut sids = vec![
        req.send(Method::GET, "https://httpbin.reqrio.com", None).await.unwrap(),                // 0 首页
        req.send(Method::GET, "https://httpbin.reqrio.com/get", None).await.unwrap(),            // 1 查询串回显
        req.send(Method::GET, "https://httpbin.reqrio.com/headers", None).await.unwrap(),        // 2 请求头回显
        req.send(Method::GET, "https://httpbin.reqrio.com/user-agent", None).await.unwrap(),     // 3 UA 回显
        req.send(Method::GET, "https://httpbin.reqrio.com/ip", None).await.unwrap(),             // 4 出口 IP
        req.send(Method::GET, "https://httpbin.reqrio.com/uuid", None).await.unwrap(),           // 5 uuid
        req.send(Method::GET, "https://httpbin.reqrio.com/json", None).await.unwrap(),           // 6 JSON 文档
        req.send(Method::GET, "https://httpbin.reqrio.com/html", None).await.unwrap(),           // 7 HTML 文档
        req.send(Method::GET, "https://httpbin.reqrio.com/xml", None).await.unwrap(),            // 8 XML 文档
        req.send(Method::GET, "https://httpbin.reqrio.com/robots.txt", None).await.unwrap(),     // 9 纯文本
        req.send(Method::GET, "https://httpbin.reqrio.com/image/png", None).await.unwrap(),      // 10 二进制图片
        req.send(Method::GET, "https://httpbin.reqrio.com/gzip", None).await.unwrap(),           // 11 gzip
        req.send(Method::GET, "https://httpbin.reqrio.com/deflate", None).await.unwrap(),        // 12 deflate
        req.send(Method::GET, "https://httpbin.reqrio.com/brotli", None).await.unwrap(),         // 13 brotli
        req.send(Method::GET, "https://httpbin.reqrio.com/stream/5", None).await.unwrap(),       // 14 chunked JSON 流
        req.send(Method::GET, "https://httpbin.reqrio.com/bytes/2048", None).await.unwrap(),     // 15 定长原始字节
        req.send(Method::GET, "https://httpbin.reqrio.com/etag/reqrio", None).await.unwrap(),    // 16 ETag
    ].into_iter();

    // 0. 首页：状态行 + ALPN + Content-Type + body
    let home = req.recv(sids.next().unwrap()).await.unwrap();
    assert_eq!(home.status(), HttpStatus::OK);
    assert_eq!(home.status().code(), 200);
    assert_eq!(home.alpn(), alpn);
    assert_eq!(home.header().content_type(), Some(&ContentType::Text(Text::Html)));
    assert!(!home.as_bytes().is_empty());
    assert!(home.as_text().unwrap().to_lowercase().contains("httpbin"));

    // /get
    let get = req.recv(sids.next().unwrap()).await.unwrap().json().unwrap();
    assert_eq!(get["url"].to_string(), "https://httpbin.reqrio.com/get");
    assert_eq!(get["method"].to_string(), "GET");
    assert!(get["headers"].is_object());

    // /headers
    let headers = req.recv(sids.next().unwrap()).await.unwrap().json().unwrap();
    let host = headers["headers"].to_string().to_lowercase();
    assert!(host.contains("httpbin.reqrio.com"), "headers = {}", host);

    // /user-agent
    let ua = req.recv(sids.next().unwrap()).await.unwrap().json().unwrap();
    assert!(ua["user-agent"].to_string().to_lowercase().contains("reqrio"));

    // /ip
    let ip = req.recv(sids.next().unwrap()).await.unwrap().json().unwrap();
    assert!(!ip["origin"].to_string().is_empty(), "origin = {}", ip["origin"]);

    // /uuid
    let uuid = req.recv(sids.next().unwrap()).await.unwrap().json().unwrap();
    assert_eq!(uuid["uuid"].to_string().len(), 36);

    // /json
    let doc = req.recv(sids.next().unwrap()).await.unwrap().json().unwrap();
    assert!(doc["slideshow"].is_object(), "slideshow = {}", doc);
    assert!(doc["slideshow"]["slides"].is_array(), "slides = {}", doc);

    // /html
    let html = req.recv(sids.next().unwrap()).await.unwrap();
    assert_eq!(html.header().content_type(), Some(&ContentType::Text(Text::Html)));
    assert!(html.as_text().unwrap().to_lowercase().contains("<html"));

    // /xml
    let xml = req.recv(sids.next().unwrap()).await.unwrap();
    assert_eq!(xml.header().content_type(), Some(&ContentType::Application(Application::Xml)));
    assert!(xml.as_text().unwrap().contains("<slideshow"));

    // /robots.txt
    let robots = req.recv(sids.next().unwrap()).await.unwrap();
    assert_eq!(robots.header().content_type(), Some(&ContentType::Text(Text::Plain)));
    assert!(!robots.as_bytes().is_empty());

    // /image/png：二进制响应
    let png = req.recv(sids.next().unwrap()).await.unwrap();
    assert_eq!(png.header().content_type(), Some(&ContentType::Image(ImageType::Png)));
    assert!(png.bytes().starts_with(&[0x89, b'P', b'N', b'G']), "不是 PNG 数据");

    // gzip
    let gzip = req.recv(sids.next().unwrap()).await.unwrap().json().unwrap();
    assert_eq!(gzip["gzipped"].to_string(), "true");

    // deflate
    let deflate = req.recv(sids.next().unwrap()).await.unwrap().json().unwrap();
    assert_eq!(deflate["deflated"].to_string(), "true");

    // brotli
    let brotli = req.recv(sids.next().unwrap()).await.unwrap().json().unwrap();
    assert_eq!(brotli["brotli"].to_string(), "true");

    // /stream/5：chunked 分块，5 行 JSON
    let stream = req.recv(sids.next().unwrap()).await.unwrap();
    assert_eq!(stream.status(), HttpStatus::OK);
    let text = stream.text().unwrap();
    assert_eq!(text.lines().count(), 5);
    assert!(text.contains("\"id\""));

    // 15. /bytes/2048：原始字节长度精确匹配
    let bytes = req.recv(sids.next().unwrap()).await.unwrap();
    assert_eq!(bytes.status(), HttpStatus::OK);
    assert_eq!(bytes.bytes().len(), 2048);

    // 16. /etag/reqrio：响应头可读
    let etag = req.recv(sids.next().unwrap()).await.unwrap();
    assert_eq!(etag.status(), HttpStatus::OK);
    assert_eq!(etag.header().get_str("etag").unwrap_or_default(), "reqrio");

    let sid = req.send(Method::GET, "https://178.236.41.45/get".sni("httpbin.reqrio.com"), None).await.unwrap();
    let sni = req.recv(sid).await.unwrap();
    assert_eq!(sni.status(), HttpStatus::OK)
}

///Request method testing
pub async fn http_method(req: &mut AcReq) {
    let post_json = json::object! {"name": "reqrio", "num": 7, "ok": true};
    let mut sids = vec![
        req.send(Method::GET, "https://httpbin.reqrio.com/get", None).await.unwrap(),
        req.send(Method::POST, "https://httpbin.reqrio.com/post", &post_json).await.unwrap(),
        req.send(Method::PUT, "https://httpbin.reqrio.com/put", json::object! {"k": "v"}).await.unwrap(),
        req.send(Method::HEAD, "https://httpbin.reqrio.com/get", None).await.unwrap(),
        req.send(Method::DELETE, "https://httpbin.reqrio.com/delete", "bye").await.unwrap(),
        req.send(Method::OPTIONS, "https://httpbin.reqrio.com/anything", None).await.unwrap(),
        req.send(Method::TRACE, "https://httpbin.reqrio.com/get", None).await.unwrap(),
        req.send(Method::CONNECT, "https://httpbin.reqrio.com/connect", None).await.unwrap(),
        req.send(Method::PATCH, "https://httpbin.reqrio.com/patch", "x=1").await.unwrap(),
        req.send(Method::QUERY, "https://httpbin.reqrio.com/query", "x=1").await.unwrap(),
    ].into_iter();

    // GET
    let get = req.recv(sids.next().unwrap()).await.unwrap().json().unwrap();
    assert_eq!(get["method"].dump(), "GET");

    // POST
    let post = req.recv(sids.next().unwrap()).await.unwrap().json().unwrap();
    assert_eq!(post["method"].dump(), "POST");
    assert_eq!(post["data"].dump(), post_json.dump());

    // PUT
    let put = req.recv(sids.next().unwrap()).await.unwrap().json().unwrap();
    assert_eq!(put["method"].dump(), "PUT");
    assert_eq!(put["data"].dump(), json::object! {"k": "v"}.dump());

    //HEAD
    let head = req.recv(sids.next().unwrap()).await.unwrap();
    assert_eq!(head.status(), HttpStatus::OK);
    assert_ne!(head.header().content_length(), None);
    assert_eq!(head.bytes().len(), 0);

    //DELETE
    let delete = req.recv(sids.next().unwrap()).await.unwrap().json().unwrap();
    assert_eq!(delete["method"].dump(), "DELETE");
    assert_eq!(delete["data"].dump(), "bye");

    //OPTIONS
    let options = req.recv(sids.next().unwrap()).await.unwrap();
    assert_eq!(options.status(), HttpStatus::OK);
    assert!(options.header().get_str("Access-Control-Allow-Methods").map(|x| x.contains("GET, POST, PUT, DELETE, PATCH, OPTIONS")).unwrap());

    //TRACE-405
    // let trace = req.recv(sids.next().unwrap()).unwrap();
    // println!("{}", trace);

    //CONNECT-405
    // let connect=req.recv(sids.next().unwrap()).unwrap();
    // println!("{}",connect);

    //PATCH-405
    // let patch=req.recv(sids.next().unwrap()).unwrap();
    // println!("{}",patch);

    //QUERY-不通
    // let query=req.recv(sids.next().unwrap()).unwrap();
    // println!("{}",query);
}

///Request status testing
pub async fn http_status(req: &mut AcReq) {
    let codes = [200u16, 201, 202, 204, 206, 301, 302, 304, 400, 401, 403, 404, 418, 500, 502, 503];
    let status = [
        HttpStatus::OK, HttpStatus::Created, HttpStatus::Accepted, HttpStatus::NoContent,
        HttpStatus::PartialContent,
        HttpStatus::Move,
        HttpStatus::Found,
        HttpStatus::NotModified,
        HttpStatus::BadRequest,
        HttpStatus::Unauthorized,
        HttpStatus::Forbidden,
        HttpStatus::NotFound,
        HttpStatus::Teapot,
        HttpStatus::ServerError,
        HttpStatus::BadGateway,
        HttpStatus::ServiceUnavailable
    ];
    let mut sids = vec![];
    for code in codes {
        sids.push(req.send(Method::GET, format!("https://httpbin.reqrio.com/status/{}", code), None).await.unwrap());
    }
    for (status, sid) in status.into_iter().zip(sids) {
        let res = req.recv(sid).await.unwrap();
        assert_eq!(res.status(), status);
    }
}

///Authentication Request Test
pub async fn http_auth(req: &mut AcReq) {
    let sid = req.send(Method::GET, "https://httpbin.reqrio.com/basic-auth/user/passwd", None).await.unwrap();
    req.insert_header("Authorization", "Basic dXNlcjpwYXNzd2Q=");
    let mut sids = vec![
        sid,
        req.send(Method::GET, "https://httpbin.reqrio.com/basic-auth/user/passwd", None).await.unwrap(),
        req.send(Method::GET, "https://httpbin.reqrio.com/bearer", None).await.unwrap()
    ].into_iter();


    // 未认证
    let auth = req.recv(sids.next().unwrap()).await.unwrap();
    assert_eq!(auth.status(), HttpStatus::Unauthorized);
    // 已认证
    let auth = req.recv(sids.next().unwrap()).await.unwrap();
    assert_eq!(auth.status(), HttpStatus::OK);
    assert!(auth.json().unwrap()["authenticated"].as_bool().unwrap());
    //未认证
    let auth = req.recv(sids.next().unwrap()).await.unwrap();
    assert_eq!(auth.status(), HttpStatus::Unauthorized)
}

///Request parameter testing
pub async fn query_param(req: &mut AcReq) {
    let p1 = json::object! {
        "q": "'reqrio'",
        "v": "\"reqrio\"",
        "n": 42,
        "b": true
    };
    let p2 = json::object! {"added": "2"};
    let p3 = json::object! {
        "cn": "中文",
        "sp": "a b&c=d",
        "empty": ""
    };
    let p4 = json::object! {"f": 1.5, "arr": "x,y"};
    let u1 = "https://httpbin.reqrio.com/get".params(&p1).unwrap();
    let u2 = "https://httpbin.reqrio.com/get?existing=1".params(&p2).unwrap();
    let u3 = "https://httpbin.reqrio.com/get".params(&p3).unwrap();
    let u4 = "https://httpbin.reqrio.com/get".params(&p4).unwrap();

    let mut ids = vec![
        req.send(Method::GET, &u1, None).await.unwrap(),
        req.send(Method::GET, &u2, None).await.unwrap(),
        req.send(Method::GET, &u3, None).await.unwrap(),
        req.send(Method::GET, &u4, None).await.unwrap(),
    ].into_iter();


    // P1
    let j = req.recv(ids.next().unwrap()).await.unwrap().json().unwrap();
    assert_eq!(j["args"]["q"].to_string(), "'reqrio'");
    assert_eq!(j["args"]["v"].to_string(), "\"reqrio\"");
    assert_eq!(j["args"]["n"].to_string(), "42");
    assert_eq!(j["args"]["b"].to_string(), "true");
    assert_eq!(j["url"].to_string(), coder::url_decode(u1.to_string()).unwrap().as_ref());


    // P2
    let j = req.recv(ids.next().unwrap()).await.unwrap().json().unwrap();
    assert_eq!(j["args"]["existing"].to_string(), "1");
    assert_eq!(j["args"]["added"].to_string(), "2");
    assert_eq!(j["url"].to_string(), coder::url_decode(u2.to_string()).unwrap().as_ref());

    // P3
    let j = req.recv(ids.next().unwrap()).await.unwrap().json().unwrap();
    assert_eq!(j["args"]["cn"].to_string(), "中文");
    assert_eq!(j["args"]["sp"].to_string(), "a b&c=d");
    assert_eq!(j["args"]["empty"].to_string(), "");
    //这里不对
    // assert_eq!(j["url"].to_string(), coder::url_decode(u3.to_string()).unwrap().as_ref());

    // P4
    let j = req.recv(ids.next().unwrap()).await.unwrap().json().unwrap();
    assert_eq!(j["args"]["f"].to_string(), "1.5");
    assert_eq!(j["args"]["arr"].to_string(), "x,y");
    assert_eq!(j["url"].to_string(), coder::url_decode(u4.to_string()).unwrap().as_ref());
}

/// Redirection test
/// * Non automatic redirection can be done using send
/// * Automatic redirection cannot use send and recv
pub async fn http_redirect(req: &mut AcReq) {
    req.set_auto_redirect(false);
    let mut ids = vec![
        req.send(Method::GET, "https://httpbin.reqrio.com/redirect/2", None).await.unwrap(),
        req.send(Method::GET, "https://httpbin.reqrio.com/relative-redirect/1", None).await.unwrap(),
        req.send(Method::GET, "https://httpbin.reqrio.com/redirect-to?url=/get&status_code=307", None).await.unwrap(),
        req.send(Method::GET, "https://httpbin.reqrio.com/absolute-redirect/2", None).await.unwrap()
    ].into_iter();
    let r1 = req.recv(ids.next().unwrap()).await.unwrap();
    assert_eq!(r1.status(), HttpStatus::Found);
    assert_eq!(r1.header().location(), Some("/relative-redirect/1"));

    let r2 = req.recv(ids.next().unwrap()).await.unwrap();
    assert_eq!(r2.status(), HttpStatus::Found);
    assert_eq!(r2.header().location(), Some("/get"));

    let r3 = req.recv(ids.next().unwrap()).await.unwrap();
    assert_eq!(r3.status(), HttpStatus::TemporaryRedirect);
    assert_eq!(r3.header().location(), Some("/get"));

    let r4 = req.recv(ids.next().unwrap()).await.unwrap();
    assert_eq!(r4.status(), HttpStatus::Found);
    assert!(r4.header().location().map(|x| x.starts_with("https://")).unwrap());

    req.set_auto_redirect(true);
    let r5 = req.get("https://httpbin.reqrio.com/redirect/2", None).await.unwrap();
    assert_eq!(r5.status(), HttpStatus::OK);

    let r6 = req.get("https://httpbin.reqrio.com/relative-redirect/1", None).await.unwrap();
    assert_eq!(r6.status(), HttpStatus::OK);

    let r7 = req.get("https://httpbin.reqrio.com/redirect-to?url=/get&status_code=307", None).await.unwrap();
    assert_eq!(r7.status(), HttpStatus::OK);

    req.set_max_redirect_exceeds(1);
    let r8 = req.get("https://httpbin.reqrio.com/redirect/5", None).await;
    assert!(r8.is_err())
}


/// Request Cookie Test
pub async fn http_cookie(req: &mut AcReq) {
    req.set_auto_redirect(false);
    let r1 = req.get("https://httpbin.reqrio.com/cookies/set?k=v&k2=v2", None).await.unwrap();
    assert_eq!(r1.status(), HttpStatus::Found);
    assert_eq!(r1.header().location(), Some("/cookies"));
    let cks = r1.header().cookies().unwrap();
    assert!(cks.iter().any(|c| c.name() == "k" && c.value() == "v"));
    assert!(cks.iter().any(|c| c.name() == "k2" && c.value() == "v2"));

    req.header_mut().remove_cookie("k");
    let r2 = req.get("https://httpbin.reqrio.com/cookies/delete?k", None).await.unwrap();
    assert_eq!(r2.status(), HttpStatus::Found);
    let r3 = req.get("https://httpbin.reqrio.com/cookies", None).await.unwrap().json().unwrap();
    assert_eq!(r3["cookies"].dump(), json::object! {"k": "","k2": "v2"}.dump())
}

/// Request Header Test
pub async fn http_header(req: &mut AcReq) {
    req.set_headers_json(json::object! {
        "User-Agent": format!("reqrio/{},reqrio-test",env!("CARGO_PKG_VERSION")),
        "X-Reqrio-Test": "hello",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "X-Multi": "a",
        "X-Int": 1,
        "X-Bool": true,
        "X-Object": {"k":"v"},
        "X-Array": ["1",1,true]
    });
    let mut ids = vec![
        req.send(Method::GET, "https://httpbin.reqrio.com/headers", None).await.unwrap(),
        req.send(Method::GET, "https://httpbin.reqrio.com/user-agent", None).await.unwrap(),
        req.send(Method::POST, "https://httpbin.reqrio.com/post", json::object! { "with": "header" }).await.unwrap(),
    ];
    // Append+Overwrite
    req.insert_header("X-Late-Header", "late");
    req.insert_header("X-Reqrio-Test", "overwritten");
    ids.extend([
        req.send(Method::GET, "https://httpbin.reqrio.com/headers", None).await.unwrap(),
        req.send(Method::GET, "https://httpbin.reqrio.com/anything?phase=late", None).await.unwrap(),
    ]);
    let mut sids = ids.into_iter();

    let mut h1 = req.recv(sids.next().unwrap()).await.unwrap().text().unwrap();
    h1.make_ascii_lowercase();
    let header = json::parse(h1.as_str()).unwrap().into_key("headers");
    assert_eq!(header["user-agent"].dump(), format!("reqrio/{},reqrio-test", env!("CARGO_PKG_VERSION")));
    assert_eq!(header["x-reqrio-test"].dump(), "hello");
    assert_eq!(header["accept-language"].dump(), "zh-cn,zh;q=0.9");
    assert_eq!(header["x-multi"].dump(), "a");
    assert_eq!(header["x-int"].dump(), "1");
    assert_eq!(header["x-bool"].dump(), "true");
    assert_eq!(header["x-object"].dump(), json::object! {"k":"v"}.dump());
    assert_eq!(header["x-array"].dump(), json::array!["1",1,true].dump());


    let h2 = req.recv(sids.next().unwrap()).await.unwrap().json().unwrap();
    assert_eq!(h2["user-agent"].dump(), format!("reqrio/{},reqrio-test", env!("CARGO_PKG_VERSION")));

    let h3 = req.recv(sids.next().unwrap()).await.unwrap().json().unwrap();
    assert_eq!(h3["data"].dump(), json::object! {"with": "header"}.dump());


    for _ in 3..5 {
        let mut res = req.recv(sids.next().unwrap()).await.unwrap().text().unwrap();
        res.make_ascii_lowercase();
        let header = json::parse(res.as_str()).unwrap().into_key("headers");
        assert_eq!(header["user-agent"].dump(), format!("reqrio/{},reqrio-test", env!("CARGO_PKG_VERSION")));
        assert_eq!(header["x-reqrio-test"].dump(), "overwritten");
        assert_eq!(header["accept-language"].dump(), "zh-cn,zh;q=0.9");
        assert_eq!(header["x-multi"].dump(), "a");
        assert_eq!(header["x-int"].dump(), "1");
        assert_eq!(header["x-bool"].dump(), "true");
        assert_eq!(header["x-object"].dump(), json::object! {"k":"v"}.dump());
        assert_eq!(header["x-array"].dump(), json::array!["1",1,true].dump());
        assert_eq!(header["x-late-header"].dump(), "late");
    }
}

pub async fn http_stream(req: &mut AcReq) {
    let sid1 = req.send(Method::GET, "https://httpbin.reqrio.com/bytes/16384", None).await.unwrap();
    let sid2 = req.send(Method::GET, "https://httpbin.reqrio.com/stream/3", None).await.unwrap();
    let mut total = 0usize;
    let mut chunks = 0usize;
    while let Some(chunk) = req.next_chunk(sid1).await.unwrap() {
        assert!(!chunk.is_empty());
        total += chunk.len();
        chunks += 1;
    }
    assert_eq!(total, 16384);
    assert!(chunks >= 1);
    while let Some(chunk) = req.next_chunk(sid2).await.unwrap() {
        assert!(chunk.contains(&b'\n'));
    }
    assert_ne!(sid1, sid2)
}

pub async fn http_helper(req: &mut AcReq) {
    // send_check：non 2xx is considered an error
    let res = req.send_check(Method::GET, "https://httpbin.reqrio.com/status/500", None).await;
    assert!(res.is_err());

    // send_check：2xx is ok
    let res = req.send_check(Method::GET, "https://httpbin.reqrio.com/get", None).await.unwrap();
    assert_eq!(res.status(), HttpStatus::OK);

    // send_check_json：verify key/value and return JSON
    let j = req.send_check_json(
        Method::GET,
        "https://httpbin.reqrio.com/anything",
        None,
        "method",
        "GET",
        vec!["error"]).await
        .unwrap();
    assert_eq!(j["method"].to_string(), "GET");

    // send_check_json：value mismatch ->Error
    let res = req.send_check_json(
        Method::POST,
        "https://httpbin.reqrio.com/anything",
        None,
        "method",
        "GET",
        vec!["method"],
    ).await;
    assert!(res.is_err())
}

/// Form+JSON+File+Text+Bytes
pub async fn http_body(req: &mut AcReq) {
    let d1 = json::object! {
        "str1": "s",
        "str2": "'s'",
        "str3": "\"s\"",
        "int": 0,
        "bool": true,
        "object": {"data":"value"},
        "array": ["2", 0,true,{"k":"v"}],
    };
    let d2 = json::object! {
        "k1":"v1",
        "k2":"v2"
    };
    let text = "sdfhsdjkfsdljhkgs;gfkgsdfhsdasugdsadgsauydgtasdfytsad";
    let bytes = rand::random::<[u8; 4096]>();
    let f1 = HttpFile::new_bytes(bytes);

    let mut f2 = HttpFile::new_bytes(bytes);
    f2.set_data(d2.clone());

    let mut f3 = HttpFile::new_form(FileForm::new_bytes(bytes).with_field_name("file1"));
    f3.add_form(FileForm::new_bytes(&bytes[0..1024]).with_field_name("file2"));
    f3.set_data(d2.clone());

    #[cfg(feature = "serde")]
    #[derive(serde::Serialize)]
    struct DataView {
        str1: String,
        str2: String,
        str3: String,
        int: i32,
        bool: bool,
    }
    #[cfg(feature = "serde")]
    let d3 = DataView {
        str1: "s".to_string(),
        str2: "'s'".to_string(),
        str3: "\"s\"".to_string(),
        int: 0,
        bool: true,
    };

    let mut sids = vec![
        // req.send(Method::GET, "https://httpbin.reqrio.com/get", &d1).await.unwrap(),//这里需要测试GET with body
        req.send(Method::POST, "https://httpbin.reqrio.com/post", d1.form()).await.unwrap(),
        req.send(Method::POST, "https://httpbin.reqrio.com/post", &d1).await.unwrap(),
        req.send(Method::POST, "https://httpbin.reqrio.com/post", &bytes).await.unwrap(),
        req.send(Method::POST, "https://httpbin.reqrio.com/post", text).await.unwrap(),
        req.send(Method::POST, "https://httpbin.reqrio.com/post", f1).await.unwrap(),
        req.send(Method::POST, "https://httpbin.reqrio.com/post", f2).await.unwrap(),
        req.send(Method::POST, "https://httpbin.reqrio.com/post".params(&d2), f3).await.unwrap(),
        #[cfg(feature = "serde")]
        req.send(Method::POST, "https://httpbin.reqrio.com/post", Body::json(&d3).unwrap()).await.unwrap()
    ].into_iter();

    // let r1=req.recv(sids.next().unwrap()).await.unwrap();
    // print!("{}",r1);

    let r2 = req.recv(sids.next().unwrap()).await.unwrap().json().unwrap();
    assert_eq!(r2["form"]["array"].dump(), d1["array"].dump());
    assert_eq!(r2["form"]["bool"].dump(), d1["bool"].dump());
    assert_eq!(r2["form"]["int"].dump(), d1["int"].dump());
    assert_eq!(r2["form"]["object"].dump(), d1["object"].dump());
    assert_eq!(r2["form"]["str1"].dump(), d1["str1"].dump());
    assert_eq!(r2["form"]["str2"].dump(), d1["str2"].dump());
    assert_eq!(r2["form"]["str3"].dump(), d1["str3"].dump());
    match r2["headers"]["Content-Type"].is_null() {
        false => assert_eq!(r2["headers"]["Content-Type"].dump(), "application/x-www-form-urlencoded"),
        true => assert_eq!(r2["headers"]["content-type"].dump(), "application/x-www-form-urlencoded"),
    }

    let r3 = req.recv(sids.next().unwrap()).await.unwrap().json().unwrap();
    assert_eq!(r3["json"]["array"].dump(), d1["array"].dump());
    assert_eq!(r3["json"]["bool"].dump(), d1["bool"].dump());
    assert_eq!(r3["json"]["int"].dump(), d1["int"].dump());
    assert_eq!(r3["json"]["object"].dump(), d1["object"].dump());
    assert_eq!(r3["json"]["str1"].dump(), d1["str1"].dump());
    assert_eq!(r3["json"]["str2"].dump(), d1["str2"].dump());
    assert_eq!(r3["json"]["str3"].dump(), d1["str3"].dump());
    match r3["headers"]["Content-Type"].is_null() {
        false => assert_eq!(r3["headers"]["Content-Type"].dump(), "application/json"),
        true => assert_eq!(r3["headers"]["content-type"].dump(), "application/json"),
    }

    let r4 = req.recv(sids.next().unwrap()).await.unwrap().json().unwrap();
    match r4["headers"]["Content-Type"].is_null() {
        false => assert_eq!(r4["headers"]["Content-Type"].dump(), "application/octet-stream"),
        true => assert_eq!(r4["headers"]["content-type"].dump(), "application/octet-stream"),
    }
    let od = r4["data"].dump().replace("data:application/octet-stream;base64,", "");
    assert_eq!(base64::b64decode(od).unwrap(), bytes);

    let r5 = req.recv(sids.next().unwrap()).await.unwrap().json().unwrap();
    match r5["headers"]["Content-Type"].is_null() {
        false => assert_eq!(r5["headers"]["Content-Type"].dump(), "text/plain"),
        true => assert_eq!(r5["headers"]["content-type"].dump(), "text/plain"),
    }
    assert_eq!(r5["data"].dump(), text);

    let r6 = req.recv(sids.next().unwrap()).await.unwrap().json().unwrap();
    match r6["headers"]["Content-Type"].is_null() {
        false => assert!(r6["headers"]["Content-Type"].dump().starts_with("multipart/form-data; boundary=----WebKitFormBoundary")),
        true => assert!(r6["headers"]["content-type"].dump().starts_with("multipart/form-data; boundary=----WebKitFormBoundary")),
    }
    let od = r6["files"]["file"].dump().replace("data:application/octet-stream;base64,", "");
    assert_eq!(base64::b64decode(od).unwrap(), bytes);


    let r7 = req.recv(sids.next().unwrap()).await.unwrap().json().unwrap();
    match r7["headers"]["Content-Type"].is_null() {
        false => assert!(r7["headers"]["Content-Type"].dump().starts_with("multipart/form-data; boundary=----WebKitFormBoundary")),
        true => assert!(r7["headers"]["content-type"].dump().starts_with("multipart/form-data; boundary=----WebKitFormBoundary")),
    }
    let od = r7["files"]["file"].dump().replace("data:application/octet-stream;base64,", "");
    assert_eq!(base64::b64decode(od).unwrap(), bytes);
    assert_eq!(r7["form"].dump(), d2.dump());

    let r8 = req.recv(sids.next().unwrap()).await.unwrap().json().unwrap();
    match r8["headers"]["Content-Type"].is_null() {
        false => assert!(r8["headers"]["Content-Type"].dump().starts_with("multipart/form-data; boundary=----WebKitFormBoundary")),
        true => assert!(r8["headers"]["content-type"].dump().starts_with("multipart/form-data; boundary=----WebKitFormBoundary")),
    }
    let od = r8["files"]["file1"].dump().replace("data:application/octet-stream;base64,", "");
    assert_eq!(base64::b64decode(od).unwrap(), bytes);
    let od = r8["files"]["file2"].dump().replace("data:application/octet-stream;base64,", "");
    assert_eq!(base64::b64decode(od).unwrap(), &bytes[..1024]);
    assert_eq!(r8["form"].dump(), d2.dump());
    assert_eq!(r8["args"].dump(), d2.dump());

    #[cfg(feature = "serde")]
    {
        let r9 = req.recv(sids.next().unwrap()).await.unwrap().json().unwrap();
        assert_eq!(r9["json"]["bool"].dump(), d1["bool"].dump());
        assert_eq!(r9["json"]["int"].dump(), d1["int"].dump());
        assert_eq!(r9["json"]["str1"].dump(), d1["str1"].dump());
        assert_eq!(r9["json"]["str2"].dump(), d1["str2"].dump());
        assert_eq!(r9["json"]["str3"].dump(), d1["str3"].dump());
        match r9["headers"]["Content-Type"].is_null() {
            false => assert_eq!(r9["headers"]["Content-Type"].dump(), "application/json"),
            true => assert_eq!(r9["headers"]["content-type"].dump(), "application/json"),
        }
    }
}


pub async fn http_concurrency(req: &mut AcReq) {
    let mut sids = vec![];
    for i in 0..6 {
        sids.push(req.send(Method::GET, format!("https://httpbin.reqrio.com/get?i={}", i), None).await.unwrap());
    }
    sids.push(req.send(Method::POST, "https://httpbin.reqrio.com/post", "h2-body").await.unwrap());
    sids.push(req.send(Method::GET, "https://httpbin.reqrio.com/gzip", None).await.unwrap());
    sids.push(req.send(Method::GET, "https://httpbin.reqrio.com/brotli", None).await.unwrap());
    sids.push(req.send(Method::GET, "https://httpbin.reqrio.com/bytes/4096", None).await.unwrap());

    while !sids.is_empty() {
        let pos = rand::random_range(0..sids.len());
        let res = req.recv(sids.remove(pos)).await.unwrap();
        assert_eq!(res.status(), HttpStatus::OK);
    }
}

