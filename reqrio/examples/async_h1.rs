use reqrio::{AcReq, ReqExt, ALPN};

#[tokio::main]
async fn main() {
//     let header = r#"GET /cgi-bin/luci/ HTTP/1.1
// Host: 192.168.15.1
// Connection: keep-alive
// Cache-Control: max-age=0
// Upgrade-Insecure-Requests: 1
// User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0
// Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
// Referer: http://192.168.15.1/
// Accept-Encoding: gzip, deflate
// Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
//
// "#.replace("\n", "\r\n");
//     // let header=Header::try_from(header.to_string()).unwrap();
//     let mut resp = Response::new();
//     let res = resp.extend(&Buffer::new_bytes(header.as_bytes().to_vec())).unwrap();
//     println!("{} {}", header, res);
//     println!("{}", res);
    let mut req = AcReq::new().with_alpn(ALPN::Http20).with_url("https://m.so.com/").await.unwrap();
    let headers = json::object! {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "Cookie": "__guid=15015764.1071255116101212729.1764940193317.2156; env_webp=1; _S=pvc5q7leemba50e4kn4qis4b95; QiHooGUID=4C8051464B2D97668E3B21198B9CA207.1766289287750; count=1; so-like-red=2; webp=1; so_huid=114r0SZFiQcJKtA38GZgwZg%2Fdit1cjUGuRcsIL2jTn4%2FE%3D; __huid=114r0SZFiQcJKtA38GZgwZg%2Fdit1cjUGuRcsIL2jTn4%2FE%3D; gtHuid=1",
        "Host": "s.ssl.qhres2.com",
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
    // req.set_alpn(ALPN::Http11);
    // let content = req.gen_h1().unwrap();
    // println!("{}", String::from_utf8(content).unwrap());
    let mut res = req.get().await.unwrap();
    println!("{}", res.header());
    // println!("{}", res.decode_body().unwrap().as_string().unwrap());
    // println!("{:#?}", req.header().cookies());

    // let jump = "https://e.so.com/jump?u=http%3A%2F%2Fewfbrsqu.wfquanaigou.cn%2F&m=a625dc&from=m.so.com&monitor=pro%3Dm_so%26pid%3Dresult%26u%3Dhttps%253A%252F%252Fm.so.com%252Fs%252F%26guid%3D13928712.2099131224995151211.1766337767018.3141%26mbp%3D2%26q%3Dewfbrsqu.wfquanaigou.cn%26pq%3D%26ls%3D%26abv%3D%26ablist%3D%255B%255D%26sid%3D56e0f68394e00ee73ca2263b502bd982%26qid%3D%26src%3Dmsearch_next_input%26srcg%3Dhome_next%26userid%3D%26nid%3D%26version%3D%26category%3D%26nettype%3Dunknown%26nav%3D%26chl%3D%26bv%3D%26adv_t%3D%26end%3D0%26pn%3D1%26bzv%3D584d8cd4518f3435%26mod%3Dog%26pos%3D1%26type%3Dweb%26official%3D0%26pcurl%3Dhttp%253A%252F%252Fewfbrsqu.wfquanaigou.cn%252F%26data-md-b%3Dtitle%26screen%3D1%26scrTime%3D3%26af%3D%26clicktype%3Dlink%26value%3Dhttp%25253A%25252F%25252Fewfbrsqu.wfquanaigou.cn%25252F%26t%3D1766337768188";
    // req.set_url(jump).await.unwrap();
    // req.insert_header("Sec-Fetch-Site", "same-site").unwrap();
    // let res = req.get().await.unwrap();
    // println!("{}", res.to_string().unwrap());
}