use reqrio::{ReqExt, ScReq, ALPN};

fn main() {
    let mut req = ScReq::new().with_alpn(ALPN::Http20).with_url("https://m.so.com").unwrap();
    let headers = json::object! {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "Cookie": "__guid=15015764.1071255116101212729.1764940193317.2156; env_webp=1; _S=pvc5q7leemba50e4kn4qis4b95; QiHooGUID=4C8051464B2D97668E3B21198B9CA207.1766289287750; count=1; so-like-red=2; webp=1; so_huid=114r0SZFiQcJKtA38GZgwZg%2Fdit1cjUGuRcsIL2jTn4%2FE%3D; __huid=114r0SZFiQcJKtA38GZgwZg%2Fdit1cjUGuRcsIL2jTn4%2FE%3D; gtHuid=1",
        "Host": "m.so.com",
        "Pragma": "no-cache",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": 1,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0",
        "sec-ch-ua": r#""Microsoft Edge";v="143", "Chromium";v="143", "Not A(Brand";v="24""#,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": r#""Windows""#
    };
    req.set_headers_json(headers).unwrap();
    // let content = req.gen_h1().unwrap();
    // println!("{:?}", String::from_utf8(content).unwrap());
    // req.send_check_json(Method::GET, "code", "0", vec!["msg", "message"]).unwrap();
    let res = req.get().unwrap();
    println!("{}", res.header());
    println!("{:#?}", req.header().cookies());
    println!("{}", res.to_string().unwrap());
}