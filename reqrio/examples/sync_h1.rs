use reqrio::{ReqExt, ScReq, ALPN};

fn main() {
    let mut req = ScReq::new().with_alpn(ALPN::Http11).with_url("https://qwert.uppuu.com/api/v1/client/s9FkyFPBngt80pFn1?token=a0cedb7c6645280ec2402db62d550a17").unwrap();
    // let content = req.gen_h1().unwrap();
    // println!("{:?}", String::from_utf8(content).unwrap());
    // req.send_check_json(Method::GET, "code", "0", vec!["msg", "message"]).unwrap();
    let mut res = req.get().unwrap();
    println!("{}", res.header());
    println!("{:#?}", req.header().cookies());
    println!("{}", res.to_string().unwrap());
}