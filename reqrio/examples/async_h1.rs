use std::collections::HashMap;
use reqrio::{AcReq, Addr, Proxy, ReqExt, ALPN};

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
    let mut req = AcReq::new().with_alpn(ALPN::Http20);
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
    // req.set_proxy(Proxy::HttpPlain(Addr::new_addr("125.121.47.165", 13968)));
    // req.set_callback(|body| {
    //     println!("{}", body.len());
    //     Ok(())
    // });
    // req.set_alpn(ALPN::Http11);
    // let content = req.gen_h1().unwrap();
    // println!("{}", String::from_utf8(content).unwrap());
    req.set_url("https://s.360.cn/mso/mso/disp.gif?pro=m_so&pid=result&u=https%3A%2F%2Fm.so.com%2Fs%2F&guid=15015764.1071255116101212729.1764940193317.2156&mbp=0&q=2132&pq=&ls=&abv=&ablist=&sid=f057cafe91decc82f2436391559db2ef&qid=&src=default_src&srcg=default_srcg&userid=&nid=&version=&category=&nettype=unknown&nav=&chl=&bv=&adv_t=&end=0&bucketid=240001%2C350001%2C530001%2C540001%2C750000%2C830003%2C850001%2C920000%2C1230007%2C1330000%2C1550001%2C1900000%2C2260000%2C3030000%2C4130001%2C4260003%2C4700001%2C4770001%2C4810001%2C5010000%2C5070001%2C5120001%2C5150001%2C5400001%2C5510001%2C5740001%2C5790002%2C5810001%2C5910000%2C6000001%2C6310000%2C6480001%2C6490003%2C6620003%2C6660026%2C6920004%2C7170013%2C7190023%2C7660000%2C8020016%2C8060001%2C8190001%2C8310002%2C8330001%2C8480001%2C8530000%2C8570012%2C8640000%2C8720001%2C8890000%2C8980000%2C9000019%2C9060001%2C9110001%2C9130000%2C9260001%2C9270003%2C9330000%2C9390002%2C9560000%2C10720005%2C10820001%2C10950003%2C10990001%2C11010003%2C11120001%2C11140000%2C11180001%2C11270000%2C11460000%2C11500002&pn=1&bzv=584d8cd4518f3435&mod=new-rel&eci=&nlpv=&t=1767332302636").await.unwrap();
    let mut res = req.get().await.unwrap();
    println!("{} {}", res.header(), res.raw_body().len());
    req.set_url("https://s.360.cn/mso/disp.gif?pro=m_so&pid=result&u=https%3A%2F%2Fm.so.com%2Fs%2F&guid=15015764.1071255116101212729.1764940193317.2156&mbp=0&q=2132&pq=&ls=&abv=&ablist=&sid=f057cafe91decc82f2436391559db2ef&qid=&src=default_src&srcg=default_srcg&userid=&nid=&version=&category=&nettype=unknown&nav=&chl=&bv=&adv_t=&end=0&bucketid=240001%2C350001%2C530001%2C540001%2C750000%2C830003%2C850001%2C920000%2C1230007%2C1330000%2C1550001%2C1900000%2C2260000%2C3030000%2C4130001%2C4260003%2C4700001%2C4770001%2C4810001%2C5010000%2C5070001%2C5120001%2C5150001%2C5400001%2C5510001%2C5740001%2C5790002%2C5810001%2C5910000%2C6000001%2C6310000%2C6480001%2C6490003%2C6620003%2C6660026%2C6920004%2C7170013%2C7190023%2C7660000%2C8020016%2C8060001%2C8190001%2C8310002%2C8330001%2C8480001%2C8530000%2C8570012%2C8640000%2C8720001%2C8890000%2C8980000%2C9000019%2C9060001%2C9110001%2C9130000%2C9260001%2C9270003%2C9330000%2C9390002%2C9560000%2C10720005%2C10820001%2C10950003%2C10990001%2C11010003%2C11120001%2C11140000%2C11180001%2C11270000%2C11460000%2C11500002&pn=1&bzv=584d8cd4518f3435&screen=1&mod=ccb&cat=time-filter&t=1767332302637").await.unwrap();
    let mut res = req.get().await.unwrap();
    println!("{}", res.header());
    req.set_url("https://s.360.cn/mso/disp_srp.gif?pro=m_so&pid=result&u=https%3A%2F%2Fm.so.com%2Fs%2F&guid=15015764.1071255116101212729.1764940193317.2156&mbp=0&q=2132&pq=&ls=&abv=&ablist=&sid=f057cafe91decc82f2436391559db2ef&qid=&src=default_src&srcg=default_srcg&nettype=unknown&nav=&end=0&pn=1&psid=&af=0&dpi=1920_1200&dpr=1&dr=&ssl=1&p1=0&p3=&p2=1&t=1767332302636").await.unwrap();
    let mut res = req.get().await.unwrap();
    println!("{}", res.header());
    req.set_url("https://s.360.cn/mso/srp.gif?pro=m_so&pid=result&u=https%3A%2F%2Fm.so.com%2Fs%2F&guid=15015764.1071255116101212729.1764940193317.2156&mbp=0&q=2132&pq=&ls=&abv=&ablist=&sid=f057cafe91decc82f2436391559db2ef&qid=&src=default_src&srcg=default_srcg&userid=&nid=&version=&category=&nettype=unknown&nav=&chl=&bv=&adv_t=&end=0&bucketid=240001%2C350001%2C530001%2C540001%2C750000%2C830003%2C850001%2C920000%2C1230007%2C1330000%2C1550001%2C1900000%2C2260000%2C3030000%2C4130001%2C4260003%2C4700001%2C4770001%2C4810001%2C5010000%2C5070001%2C5120001%2C5150001%2C5400001%2C5510001%2C5740001%2C5790002%2C5810001%2C5910000%2C6000001%2C6310000%2C6480001%2C6490003%2C6620003%2C6660026%2C6920004%2C7170013%2C7190023%2C7660000%2C8020016%2C8060001%2C8190001%2C8310002%2C8330001%2C8480001%2C8530000%2C8570012%2C8640000%2C8720001%2C8890000%2C8980000%2C9000019%2C9060001%2C9110001%2C9130000%2C9260001%2C9270003%2C9330000%2C9390002%2C9560000%2C10720005%2C10820001%2C10950003%2C10990001%2C11010003%2C11120001%2C11140000%2C11180001%2C11270000%2C11460000%2C11500002&pn=1&bzv=584d8cd4518f3435&ob=0&box_list=&ob_map=&om=5&om_list=0%3Amso-og-goods-list%2C1%3Amso-app-download%2C5%3Amso-app-download%2C8%3Amso-baike%2C11%3Amso-app-download&en=0&en_list=&mb=5&mb_list=top-rec%2C3%3Amso-recommend-normal-rel-1_top%2C4%3Aown_guide_recommend%2C7%3Amso-recommend-normal-rel-1_bottom%2Cnew-rel&mods=rec_top%2Crec_nlp%2Crec_guide%2Crec_nlp%2Cnew-rel&toptype=wap%2Cwap%2Cweb&psid=&af=0&tg=&dpi=1920_1200&dpr=1&dr=&ssl=1&unionid=&p1=0&p3=&wap=5&web=5&t=1767332302635").await.unwrap();
    let mut res = req.get().await.unwrap();
    println!("{}", res.header());
    req.set_url("https://s.360.cn/mso/disp.gif?pro=m_so&pid=result&u=https%3A%2F%2Fm.so.com%2Fs%2F&guid=15015764.1071255116101212729.1764940193317.2156&mbp=0&q=2132&pq=&ls=&abv=&ablist=&sid=f057cafe91decc82f2436391559db2ef&qid=&src=default_src&srcg=default_srcg&userid=&nid=&version=&category=&nettype=unknown&nav=&chl=&bv=&adv_t=&end=0&bucketid=240001%2C350001%2C530001%2C540001%2C750000%2C830003%2C850001%2C920000%2C1230007%2C1330000%2C1550001%2C1900000%2C2260000%2C3030000%2C4130001%2C4260003%2C4700001%2C4770001%2C4810001%2C5010000%2C5070001%2C5120001%2C5150001%2C5400001%2C5510001%2C5740001%2C5790002%2C5810001%2C5910000%2C6000001%2C6310000%2C6480001%2C6490003%2C6620003%2C6660026%2C6920004%2C7170013%2C7190023%2C7660000%2C8020016%2C8060001%2C8190001%2C8310002%2C8330001%2C8480001%2C8530000%2C8570012%2C8640000%2C8720001%2C8890000%2C8980000%2C9000019%2C9060001%2C9110001%2C9130000%2C9260001%2C9270003%2C9330000%2C9390002%2C9560000%2C10720005%2C10820001%2C10950003%2C10990001%2C11010003%2C11120001%2C11140000%2C11180001%2C11270000%2C11460000%2C11500002&pn=1&bzv=584d8cd4518f3435&mod=recb&screen=1&p_list=0%2C1%2C2%2C3%2C4%2C5%2C6%2C7%2C8%2C9&logid=1&cat=toprecommend&eci=&nlpv=&t=1767332302638").await.unwrap();
    let mut res = req.get().await.unwrap();
    println!("{}", res.header());
    // let mut res = req.get().await.unwrap();
    // println!("{}", res.header());
    // println!("{}", res.decode_body().unwrap().as_bytes().unwrap().len());
    // println!("{:#?}", req.header().cookies());

    // let jump = "https://e.so.com/jump?u=http%3A%2F%2Fewfbrsqu.wfquanaigou.cn%2F&m=a625dc&from=m.so.com&monitor=pro%3Dm_so%26pid%3Dresult%26u%3Dhttps%253A%252F%252Fm.so.com%252Fs%252F%26guid%3D13928712.2099131224995151211.1766337767018.3141%26mbp%3D2%26q%3Dewfbrsqu.wfquanaigou.cn%26pq%3D%26ls%3D%26abv%3D%26ablist%3D%255B%255D%26sid%3D56e0f68394e00ee73ca2263b502bd982%26qid%3D%26src%3Dmsearch_next_input%26srcg%3Dhome_next%26userid%3D%26nid%3D%26version%3D%26category%3D%26nettype%3Dunknown%26nav%3D%26chl%3D%26bv%3D%26adv_t%3D%26end%3D0%26pn%3D1%26bzv%3D584d8cd4518f3435%26mod%3Dog%26pos%3D1%26type%3Dweb%26official%3D0%26pcurl%3Dhttp%253A%252F%252Fewfbrsqu.wfquanaigou.cn%252F%26data-md-b%3Dtitle%26screen%3D1%26scrTime%3D3%26af%3D%26clicktype%3Dlink%26value%3Dhttp%25253A%25252F%25252Fewfbrsqu.wfquanaigou.cn%25252F%26t%3D1766337768188";
    // req.set_url(jump).await.unwrap();
    // req.insert_header("Sec-Fetch-Site", "same-site").unwrap();
    // let res = req.get().await.unwrap();
    // println!("{}", res.to_string().unwrap());
}