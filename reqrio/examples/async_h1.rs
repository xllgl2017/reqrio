use reqrio::*;

#[cfg(feature = "log")]
const LOGER: Logger = Logger {
    module: &[],
    debug_file: None,
    info_file: None,
    warn_file: None,
    error_file: None,
    out_file: None,
};

#[cfg(feature = "log")]
fn test_log() {
    set_logger(&LOGER).unwrap();
    set_max_level(LevelFilter::Debug);
}

#[tokio::main]
async fn main() {
    #[cfg(feature = "log")]
    test_log();
    let mut timeout = Timeout::longer();
    timeout.set_handle_times(1);

    let mut req = AcReq::new()
        // .with_fingerprint(fingerprint)
        .with_timeout(timeout)
        .with_verify(true)
        .with_key_log("2.log")
        .with_auto_redirect(false)
        // .with_proxy(Proxy::Null)
        .with_verify(false)
        .with_alpn(ALPN::Http11)
        // .with_proxy(Proxy::try_from("http: //222.186.129.68:15265").unwrap())
        // .with_mtls(certs, key)
        // .with_proxy(Proxy::new_socks5("127.0.0.1",10279))
        // .with_proxy(Proxy::new_http_plain("127.0.0.1", 10279))
        // .connect("https://104.18.34.137".sni("whatnot.com")).await.unwrap()
        ;
    let headers = json::object! {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        "Accept": "*/*",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Dest": "document",
        "sec-fetch-user":"?1",
        "upgrade-insecure-requests":"1",
        "sec-ch-ua": "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Microsoft Edge\";v=\"120\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\"",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Accept-Encoding": "gzip,deflate,br,zstd",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        // "cookie":"_EDGE_V=1; MUIDB=184C10AD397866DF1A1607B038566708; MUID=184C10AD397866DF1A1607B038566708; _UR=QS=0&TQS=0&Pn=0; BFBUSR=BFBHP=0; MUIDB=184C10AD397866DF1A1607B038566708; SRCHD=AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF&AF=NOFORM; SRCHUID=V=2&GUID=EB7B9E5DE58F4D5690F6904732C24C7B&dmnchg=1; USRLOC=HS&ELOC=LAT=23.384721755981445|LON=113.44195556640625|N=%E7%99%BD%E4%BA%91%E5%8C%BA%EF%BC%8C%E5%B9%BF%E4%B8%9C%E7%9C%81|ELT=4|&HS=1; _RwBf=r&r&r&r&r=0&ilt=10&ihpd=5&ispd=3&rc=12&rb=0&rg=200&pc=12&mtu=0&rbb=0&clo=0&v=8&l=2026-03-15T07:00:00.0000000Z&lft=0001-01-01T00:00:00.0000000&aof=0&ard=0001-01-01T00:00:00.0000000&rwdbt=0&rwflt=0&rwaul2=0&g=&o=2&p=&c=&t=0&s=0001-01-01T00:00:00.0000000+00:00&ts=2026-03-15T14:03:35.7211444+00:00&rwred=0&wls=&wlb=&wle=&ccp=&cpt=&lka=0&lkt=0&aad=0&TH=&cid=0&gb=; SRCHUSR=DOB&DS&DS&DS&DS&DS=1&DOB=20260315; _EDGE_S=SID=357AA105805E678827ACB618817066E6; _SS=SID=357AA105805E678827ACB618817066E6; _HPVN=CS=eyJQbiI6eyJDbiI6MSwiU3QiOjAsIlFzIjowLCJQcm9kIjoiUCJ9LCJTYyI6eyJDbiI6MSwiU3QiOjAsIlFzIjowLCJQcm9kIjoiSCJ9LCJReiI6eyJDbiI6MSwiU3QiOjAsIlFzIjowLCJQcm9kIjoiVCJ9LCJBcCI6dHJ1ZSwiTXV0ZSI6dHJ1ZSwiTGFkIjoiMjAyNi0wMy0xNVQwMDowMDowMFoiLCJJb3RkIjowLCJHd2IiOjAsIlRucyI6MCwiRGZ0IjpudWxsLCJNdnMiOjAsIkZsdCI6MCwiSW1wIjozMCwiVG9ibiI6MH0=; SRCHHPGUSR=SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&V&SRCHLANG&SRCHLANG&SRCHLANG&V&SRCHLANG&SRCHLANG=zh-Hans&PREFCOL=0&BRW=NOTP&BRH=M&CW=150&CH=769&SCW=150&SCH=769&DPR=1.0&UTC=480&HV=1773588648&HVE=CfDJ8HAK7eZCYw5BifHFeUHnkJGC6_lT8f9GeruXx8zjPXuk-5GHkofYMoFErMkT8CTKKKsSt5O2HyGmjLyCEXbEREUmwCd8ZBlYMLSDZu1wZ-EI1LDuyIiI1tkP6Usyicm601qX3aJVYqVWUBn-t6h0ZWLiftm4aS627xFj1fE5PD-85i7BWTkhqG0uvaYzuSgB2A&BZA=0&PRVCW=150&PRVCH=769&B=0&EXLTT=7&V=CfDJ8HAK7eZCYw5BifHFeUHnkJGijeRjCoaCMaAnmznMvdEg2GXY8647Wb-7wnHNpePKXRO6KRQ_0cQc-onivd35uV-p-4g0MB0V_Z1ZpW-QSJe9zbPUG-Ks-kQMjzEl6GlLo6N0ciP51vkQdR-P-lCUH58&PR=1"
    };
    req.set_headers_json(headers).unwrap();
    // let data = json::object! {
    //     "body":"spLabel=false&clueLabel=false&id=24055967626&spTitle=pre_data6&productNameSupplement=&description=&picContent=&spPicContentSwitch=1&shippingTimeX=-&skus=%5B%7B%22id%22%3A44382959111%2C%22spec%22%3A%22455%22%2C%22price%22%3A10%2C%22unit%22%3A%22%E4%BB%BD%22%2C%22stock%22%3A1%2C%22weight%22%3A0%2C%22weightUnit%22%3A%22%E5%85%8B%28g%29%22%2C%22ladderPrice%22%3A0%2C%22ladderNum%22%3A1%2C%22upcCode%22%3A%22211102884294%22%2C%22upc%22%3A%22211102884294%22%2C%22sourceFoodCode%22%3A%22a2640479882013848866%22%2C%22skuCode%22%3A%22a2640479882013848866%22%2C%22shelfNum%22%3A%22%22%2C%22minOrderCount%22%3A1%2C%22skuAttrs%22%3A%5B%5D%2C%22oriPrice%22%3A0%2C%22skipUpcImg%22%3A%22%22%2C%22commonProperty%22%3Anull%7D%5D&attrList=%5B%5D&picture=http%3A%2F%2Fp0.meituan.net%2Fscproduct%2F18a930e5f9b95f8fcedd9ee4ff220cd3148954.jpg&labels=%5B%7B%22group_id%22%3A43%2C%22sub_attr%22%3A0%7D%5D&isSp=0&categoryId=400000364&categoryPath=200001013%2C200001014%2C400000364&releaseType=0&tagList=%5B%7B%22tagId%22%3A1377205822%2C%22tagName%22%3A%22%E6%9C%AA%E5%88%86%E7%B1%BB%22%7D%5D&limitSale=%7B%22limitSale%22%3Afalse%2C%22begin%22%3A%22%22%2C%22end%22%3A%22%22%2C%22type%22%3A1%2C%22frequency%22%3A1%2C%22count%22%3A0%7D&categoryAttrMap=%7B%221200000003%22%3A%7B%22attrId%22%3A1200000003%2C%22attrName%22%3A%22%E5%89%82%E5%9E%8B%22%2C%22attrType%22%3A3%2C%22inputType%22%3A1%2C%22sequence%22%3A9%2C%22isRequired%22%3A0%2C%22valueList%22%3A%5B%5D%7D%2C%221200000005%22%3A%7B%22attrId%22%3A1200000005%2C%22attrName%22%3A%22%E6%B3%A8%E6%84%8F%E4%BA%8B%E9%A1%B9%22%2C%22attrType%22%3A3%2C%22inputType%22%3A3%2C%22sequence%22%3A16%2C%22isRequired%22%3A0%2C%22valueList%22%3A%5B%7B%22value%22%3A%22%22%2C%22valueIdPath%22%3A%22%22%2C%22valuePath%22%3A%22%22%2C%22selected%22%3A1%7D%5D%7D%2C%221200000011%22%3A%7B%22attrId%22%3A1200000011%2C%22attrName%22%3A%22%E9%80%82%E5%AE%9C%E4%BA%BA%E7%BE%A4%22%2C%22attrType%22%3A3%2C%22inputType%22%3A3%2C%22sequence%22%3A12%2C%22isRequired%22%3A0%2C%22valueList%22%3A%5B%7B%22value%22%3A%22%22%2C%22valueIdPath%22%3A%22%22%2C%22valuePath%22%3A%22%22%2C%22selected%22%3A1%7D%5D%7D%2C%221200000012%22%3A%7B%22attrId%22%3A1200000012%2C%22attrName%22%3A%22%E6%88%90%E5%88%86%22%2C%22attrType%22%3A3%2C%22inputType%22%3A3%2C%22sequence%22%3A7%2C%22isRequired%22%3A0%2C%22valueList%22%3A%5B%7B%22value%22%3A%22%22%2C%22valueIdPath%22%3A%22%22%2C%22valuePath%22%3A%22%22%2C%22selected%22%3A1%7D%5D%7D%2C%221200000014%22%3A%7B%22attrId%22%3A1200000014%2C%22attrName%22%3A%22%E8%B4%AE%E8%97%8F%22%2C%22attrType%22%3A3%2C%22inputType%22%3A3%2C%22sequence%22%3A14%2C%22isRequired%22%3A1%2C%22valueList%22%3A%5B%7B%22value%22%3A%22%E5%B7%B2%22%2C%22valueIdPath%22%3A%22%22%2C%22valuePath%22%3A%22%22%2C%22selected%22%3A1%7D%5D%7D%2C%221200000015%22%3A%7B%22attrId%22%3A1200000015%2C%22attrName%22%3A%22%E6%B8%A9%E9%A6%A8%E6%8F%90%E7%A4%BA%22%2C%22attrType%22%3A3%2C%22inputType%22%3A3%2C%22sequence%22%3A19%2C%22isRequired%22%3A0%2C%22valueList%22%3A%5B%7B%22value%22%3A%221.%E2%80%9C%E5%9B%BD%E5%AE%B6%E8%8D%AF%E7%9B%91%E5%B1%80%E6%8F%90%E7%A4%BA%E6%82%A8%EF%BC%9A%E8%AF%B7%E6%AD%A3%E7%A1%AE%E8%AE%A4%E8%AF%86%E5%8C%96%E5%A6%86%E5%93%81%E5%8A%9F%E6%95%88%EF%BC%8C%E5%8C%96%E5%A6%86%E5%93%81%E4%B8%8D%E8%83%BD%E6%9B%BF%E4%BB%A3%E8%8D%AF%E5%93%81%EF%BC%8C%E4%B8%8D%E8%83%BD%E6%B2%BB%E7%96%97%E7%9A%AE%E8%82%A4%E7%97%85%E7%AD%89%E7%96%BE%E7%97%85%E2%80%9D%EF%BC%8C%E6%8F%90%E9%86%92%E5%B9%BF%E5%A4%A7%E6%B6%88%E8%B4%B9%E8%80%85%E9%98%B2%E8%8C%83%E5%8C%96%E5%A6%86%E5%93%81%E6%B6%88%E8%B4%B9%E9%A3%8E%E9%99%A9%EF%BC%9B2.%E7%94%B1%E4%BA%8E%E5%8E%82%E5%AE%B6%E4%B8%8D%E5%AE%9A%E6%9C%9F%E6%9B%B4%E6%8D%A2%E4%BA%A7%E5%93%81%E5%8C%85%E8%A3%85%EF%BC%8C%E5%A6%82%E9%81%87%E6%96%B0%E5%8C%85%E8%A3%85%E4%B8%8A%E5%B8%82%E5%8F%AF%E8%83%BD%E5%AD%98%E5%9C%A8%E6%9B%B4%E6%96%B0%E6%BB%9E%E5%90%8E%EF%BC%8C%E8%AF%B7%E4%BB%A5%E6%94%B6%E5%88%B0%E7%9A%84%E5%AE%9E%E8%B4%A7%E5%8C%85%E8%A3%85%E4%B8%BA%E5%87%86%EF%BC%81%22%2C%22valueIdPath%22%3A%22%22%2C%22valuePath%22%3A%22%22%2C%22selected%22%3A1%7D%5D%7D%2C%221200000017%22%3A%7B%22attrId%22%3A1200000017%2C%22attrName%22%3A%22%E7%94%A8%E6%B3%95%E7%94%A8%E9%87%8F%22%2C%22attrType%22%3A3%2C%22inputType%22%3A3%2C%22sequence%22%3A13%2C%22isRequired%22%3A1%2C%22valueList%22%3A%5B%7B%22value%22%3A%22%E5%B7%B2%22%2C%22valueIdPath%22%3A%22%22%2C%22valuePath%22%3A%22%22%2C%22selected%22%3A1%7D%5D%7D%2C%221200000018%22%3A%7B%22attrId%22%3A1200000018%2C%22attrName%22%3A%22%E7%94%9F%E4%BA%A7%E4%BC%81%E4%B8%9A%22%2C%22attrType%22%3A3%2C%22inputType%22%3A3%2C%22sequence%22%3A5%2C%22isRequired%22%3A1%2C%22valueList%22%3A%5B%7B%22value%22%3A%22%E5%B7%B2%22%2C%22valueIdPath%22%3A%22%22%2C%22valuePath%22%3A%22%22%2C%22selected%22%3A1%7D%5D%7D%2C%221200000073%22%3A%7B%22attrId%22%3A1200000073%2C%22attrName%22%3A%22%E9%80%82%E7%94%A8%E8%8C%83%E5%9B%B4%22%2C%22attrType%22%3A3%2C%22inputType%22%3A3%2C%22sequence%22%3A11%2C%22isRequired%22%3A0%2C%22valueList%22%3A%5B%7B%22value%22%3A%22%22%2C%22valueIdPath%22%3A%22%22%2C%22valuePath%22%3A%22%22%2C%22selected%22%3A1%7D%5D%7D%2C%221200000080%22%3A%7B%22attrId%22%3A1200000080%2C%22attrName%22%3A%22%E6%9C%89%E6%95%88%E6%9C%9F%22%2C%22attrType%22%3A3%2C%22inputType%22%3A3%2C%22sequence%22%3A15%2C%22isRequired%22%3A1%2C%22valueList%22%3A%5B%7B%22value%22%3A%22%E5%B7%B2%22%2C%22valueIdPath%22%3A%22%22%2C%22valuePath%22%3A%22%22%2C%22selected%22%3A1%7D%5D%7D%2C%221200000085%22%3A%7B%22attrId%22%3A1200000085%2C%22attrName%22%3A%22%E4%BA%A7%E5%9C%B0%E7%B1%BB%E5%9E%8B%22%2C%22attrType%22%3A3%2C%22inputType%22%3A1%2C%22sequence%22%3A6%2C%22isRequired%22%3A1%2C%22valueList%22%3A%5B%7B%22valueId%22%3A1300000003%2C%22value%22%3A%22%E5%9B%BD%E4%BA%A7%22%2C%22valueIdPath%22%3A%221300000003%22%2C%22valuePath%22%3A%221%22%2C%22sequence%22%3A1%2C%22selected%22%3A1%7D%5D%7D%2C%221200000086%22%3A%7B%22attrId%22%3A1200000086%2C%22attrName%22%3A%22%E6%89%B9%E5%87%86%E6%96%87%E5%8F%B7%22%2C%22attrType%22%3A1%2C%22inputType%22%3A3%2C%22sequence%22%3A4%2C%22isRequired%22%3A1%2C%22valueList%22%3A%5B%7B%22value%22%3A%22%E5%B7%B2%22%2C%22valueIdPath%22%3A%22%22%2C%22valuePath%22%3A%22%22%2C%22selected%22%3A1%7D%5D%7D%2C%221200000088%22%3A%7B%22attrId%22%3A1200000088%2C%22attrName%22%3A%22%E5%93%81%E7%89%8C%22%2C%22attrType%22%3A1%2C%22inputType%22%3A1%2C%22sequence%22%3A2%2C%22isRequired%22%3A0%2C%22valueList%22%3A%5B%5D%7D%2C%221200000159%22%3A%7B%22attrId%22%3A1200000159%2C%22attrName%22%3A%22%E4%BA%A7%E5%93%81%E5%90%8D%E7%A7%B0%22%2C%22attrType%22%3A1%2C%22inputType%22%3A3%2C%22sequence%22%3A1%2C%22isRequired%22%3A1%2C%22valueList%22%3A%5B%7B%22value%22%3A%22%E5%B7%B2%22%2C%22valueIdPath%22%3A%22%22%2C%22valuePath%22%3A%22%22%2C%22selected%22%3A1%7D%5D%7D%2C%221200000251%22%3A%7B%22attrId%22%3A1200000251%2C%22attrName%22%3A%22%E4%BA%A7%E5%93%81%E5%8A%9F%E6%95%88%22%2C%22attrType%22%3A3%2C%22inputType%22%3A3%2C%22sequence%22%3A10%2C%22isRequired%22%3A0%2C%22valueList%22%3A%5B%7B%22value%22%3A%22%22%2C%22valueIdPath%22%3A%22%22%2C%22valuePath%22%3A%22%22%2C%22selected%22%3A1%7D%5D%7D%2C%221200004423%22%3A%7B%22attrId%22%3A1200004423%2C%22attrName%22%3A%22%E5%95%86%E6%A0%87%22%2C%22attrType%22%3A1%2C%22inputType%22%3A1%2C%22sequence%22%3A3%2C%22isRequired%22%3A0%2C%22valueList%22%3A%5B%5D%7D%2C%221200004527%22%3A%7B%22attrId%22%3A1200004527%2C%22attrName%22%3A%22%E5%84%BF%E7%AB%A5%E5%8C%96%E5%A6%86%E5%93%81%22%2C%22attrType%22%3A3%2C%22inputType%22%3A1%2C%22sequence%22%3A18%2C%22isRequired%22%3A0%2C%22valueList%22%3A%5B%5D%7D%2C%221200189598%22%3A%7B%22attrId%22%3A1200189598%2C%22attrName%22%3A%22%E6%89%A7%E8%A1%8C%E6%A0%87%E5%87%86%E6%96%87%E5%8F%B7%22%2C%22attrType%22%3A3%2C%22inputType%22%3A3%2C%22sequence%22%3A18%2C%22isRequired%22%3A0%2C%22valueList%22%3A%5B%7B%22value%22%3A%22%22%2C%22valueIdPath%22%3A%22%22%2C%22valuePath%22%3A%22%22%2C%22selected%22%3A1%7D%5D%7D%7D&spuSaleAttrMap=%7B%7D&upcImage=&sellStatus=1&marketingPicture=&marketingPicList=&industryPics=%5B%7B%22type%22%3A1%2C%22quoteSwitch%22%3A0%7D%2C%7B%22type%22%3A2%2C%22quoteSwitch%22%3A0%7D%5D&wmPoiId=31309015&skipAudit=false&validType=0&missingRequiredInfo=false&auditStatus=0&useSuggestCategory=false&auditScene=0&saveType=1&auditSource=1&spVideoStatus=0&checkActivitySkuModify=true&hsCodeId=",
    //     "method":"POST",
    //     "cookie":r#"_lxsdk_cuid=1999098642bc8-03c78c52e8aedd-76574611-384000-1999098642c4; _lxsdk=1999098642bc8-03c78c52e8aedd-76574611-384000-1999098642c4; e_b_id_352126=4b43997da8f5f5aa8082a019a6cdf04e; uuid_update=true; acctId=267433045; token=0cpJblTnhR5bQFB_39b9g2SSwbXnyTWLAniQgW--LYfs*; brandId=-1; wmPoiId=31309015; isOfflineSelfOpen=2; city_id=0; isChain=0; existBrandPoi=true; ignore_set_router_proxy=false; region_id=0; region_version=0; newCategory=true; bsid=EyePQTksNOTzBax0Jj0WXN7afqoa0oHmoMBZsTRn1yHXGkItD0ShP6FUcrSeokuN3CQGi7ftajaZxvQ9Vmoqdw; device_uuid=!b0cfb761-8530-4aad-9d72-7f85b01606ed; _gw_ab_call_37616_150=TRUE; _gw_ab_37616_150=851; logistics_support=1; cityId=440100; provinceId=440000; city_location_id=610100; location_id=610103; account_businesstype=1; single_poi_businesstype=1; accountAllPoiBusinessType=1; acct_id=267433045; acct_name=mt838377du; poi_id=31309015; account_second_type=200; poi_first_category_id=22; poi_second_category_id=4012; pushToken=0cpJblTnhR5bQFB_39b9g2SSwbXnyTWLAniQgW--LYfs*; isNewCome=1; set_info={"wmPoiId":31309015,"region_id":"1000610100","region_version":1766133001}; pharmacistAccount=0; wpush_server_url=wss://wpush.meituan.com; shopCategory=medicine; com.sankuai.yiyao.shangjia.main_strategy=; cacheTimeMark=2026-01-18; WEBDFPID=z8yy33552xwy586vz4x1x5xw0y1832z98000901270247958w8y12yy6-1768794670395-1759067529980SMCUUEKa12a6b8169ee7736639f3ec62dbf984b1665; utm_source_rg=AM%2566AyTyT%25284; yy-epassport-accessToken=EyePQTksNOTzBax0Jj0WXN7afqoa0oHmoMBZsTRn1yHXGkItD0ShP6FUcrSeokuN3CQGi7ftajaZxvQ9Vmoqdw; com.sankuai.yiyao.eproduct.manager_strategy=; logan_session_token=zjnxg3h69dimc8jf1c59; _lxsdk_s=19bcf3a66bb-504-7a4-cd5%7C%7C201"#,
    //     "url":"https://yiyao.meituan.com/reuse/health/product/retail/w/uniSave?yodaReady=h5&csecplatform=4&csecversion=4.2.0",
    //     "type":"hs1.6"
    // };
    // req.header_mut().set_authorization("Upy9fDyueOXiEbON0vRXimw/tlHO5QHs+IV75wUbSzZngY0oLn1wJpQ00TnW1Cihu1UUnDUvVg4y9FggZe9nlMYfUxbwWBKP27EmkCEmyrxnrlc5inWEeK3OXKwUhhfc").unwrap();
    // let url = "https://testapi.xllgl.top:3453/v1/api/mtgsig";
    // req.set_url(url).await.unwrap();
    // req.set_json(data);
    // let res = req.post().await.unwrap().text().unwrap();
    // println!("{}",res);
    // let data = json::object! {
    //   "alpn": "http/1.1",
    //   "body": "",
    //   "headers": {
    //     "Accept": "*/*",
    //     "Accept-Encoding": "gzip, deflate, br, zstd",
    //     "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
    //     "Cache-Control": "no-cache",
    //     "Connection": "keep-alive",
    //     // "Content-Type": "application/x-www-form-urlencoded",
    //     "Pragma": "no-cache",
    //     // "Referer": "http://xxxxxx",
    //     "Sec-Fetch-Dest": "empty",
    //     "Sec-Fetch-Mode": "cors",
    //     "Sec-Fetch-Site": "same-origin",
    //   },
    //   "method": "GET",
    //   "tls": "Chrome-linux-135",
    //   "url": "https://m.baidu.com"
    // };
    // req.set_url("https://shopee.tw/").await.unwrap();
    // req.set_url("https://127.0.0.1:3453/v1/api/tlsReq").await.unwrap();
    // req.set_json(data);
    // req.set_auto_redirect(false);
    // req.set_url("http://zwfw.hubei.gov.cn/web/user/uias_login.do?appCode=hbzwfw&gotoUrl=http%3A%2F%2Fzwfw.hubei.gov.cn%2Fwebview%2Fgrkj%2Fwelcome.html&p01=").await.unwrap();
    // req.set_url("https://127.0.0.1:7878").await.unwrap();
    // req.set_url("https://www.jetstar.com").await.unwrap();
    // req.set_url("https://m1.pxb7.com/api/search/h5/product/selectSearchPageList").await.unwrap();
    // req.set_url("https://www.link114.cn/").await.unwrap();
    //
    // req.set_url("https://accounts.pcid.ca/login").await.unwrap();
    // req.set_url("https://xxbg.snssdk.com/fdsf/dsfsdfkdsjfk").await.unwrap();
    // req.set_url("https://www.toutiao.com/article/7600224020776239658/?log_from=99ab1fa2b852c_1769590891442&wid=1769590984039").await.unwrap();
    // req.set_url("https://www.sogou.com").await.unwrap();
    // req.set_url("https://cn.bing.com/search?q=site%EF%BC%9Asite：wLLyn.com&first=0&FORM=PERE2").await.unwrap();
    // req.set_proxy(Proxy::new_socks5("127.0.0.1", 10279));
    // req.set_url("https://m.baidu.com").await.unwrap();
    // req.set_url("https://www.sephora.com/").await.unwrap();
    // req.set_url("https://doc.rust-lang.org/").await.unwrap();
    // req.set_url("https://tls.123408.xyz/api/clean").await.unwrap();
    // req.set_url("https://mcs-mimp-web.sf-express.com/mcs-mimp/sendValidCode").await.unwrap()
    // req.set_url("https://jetstar.com").await.unwrap();
    // req.set_url("https://127.0.0.1:8000").await.unwrap();
    // req.set_auto_redirect(false);
    // req.set_url("https://oauth.hubei.gov.cn:8443/").await.unwrap();
    req.set_auto_redirect(false);
    // let res = req.get("https://dns.alidns.com/resolve?name=crypto.cloudflare.com&type=HTTPS", None).await.unwrap();
    // let res=req.get("https://www.link114.cn/",None).await.unwrap();
    // let res = req.get("https://www.bing.com".params(json::object! {}), vec![0u8; 0].ty(Application::Json)).await.unwrap();
    // let res = req.get("https://117.89.181.21".sni("m.sogou.com"), None).await.unwrap();
    // let url = Url::try_from("https://cn.bing.com/").unwrap();
    // let url = "https://113.108.215.122/xhr/front/trade/priority/rushPurchase/hot/branch/one".sni("h5.moutai519.com.cn").unwrap(); //
    // let url = "https://www.baidu.com".try_into().unwrap();
    req.set_verify(false);
    let t = Time::now();
    // let resp = req.get("https://m.so.com/", None).await.unwrap();
    let resp = req.get("https://www.baidu.com", None).await.unwrap();
    println!("{} {}", resp.header(), resp.as_bytes().len());
    println!("{}", Time::now().as_mills() - t.as_mills());
}