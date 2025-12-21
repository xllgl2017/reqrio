use hls::{ScReq, ALPN};

fn main() {
    let mut req = ScReq::new().with_alpn(ALPN::Http11).with_url("https://m.so.com").unwrap();
    // let content = req.gen_h1().unwrap();
    // println!("{:?}", String::from_utf8(content).unwrap());
    // req.send_check_json(Method::GET, "code", "0", vec!["msg", "message"]).unwrap();
    let res = req.get().unwrap();
    println!("{}", res.header());
    println!("{:#?}", res.header().cookies());
    println!("{}", String::from_utf8_lossy(&res.decode_body().unwrap()));
}