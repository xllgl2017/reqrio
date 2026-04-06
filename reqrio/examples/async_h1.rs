use reqrio::*;

#[tokio::main]
async fn main() {
    let mut timeout = Timeout::longer();
    timeout.set_handle_times(1);

    // let fingerprint = Fingerprint::from_ja3("771,4866-4867-4865-49196-49200-49195-49199-52393-52392-49188-49192-49187-49191-159-158-107-103-255,0-11-10-16-22-23-49-13-43-45-51-21,29-23-30-25-24-256-257-258-259-260,0-1-2", "691j799n9c-j3g2d251k799n9c-j3l11961k").unwrap();
    // let fingerprint = Fingerprint::from_ja4("t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601", "4b107bbnbc-01o-3781k7bbnbc-01v25461k").unwrap();
    // let fingerprint = Fingerprint::from_hex_all("160301072401000720030347c8885be57c7b5ef724505f486efff05173d7ac332ff5764b7509f845f2f4cd20ea5e1d057803dd84d88a0e0d0ba7578e38bfb307cd60808f710d100c13bda4110020dada130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010006b71a1a0000002d00020101000b00020100000500050100000000003304ef04edfafa00010011ec04c0c399b44b802ea789831e2625ebd68a136b713e80a50233a22dbc8002a6aab07ba3afd935e2f315ddb72dfa4a94f75a7494da759b03780f558a3d0a0608a38d8af2122d1ccca3a9121b5387e9da46d913b539b0c9d6b4a68a9a15f825892b26ce70815b159a7dee77ab7ea5b4fd30b9f202818ba6c7551a65f011654307b334716e667651c4e7a2a5e14ff43b271fe627273246268628157b641a62751e30b263657f160868d8d7b8095439d97941759874943c6a12da92b7d146e4e870a4e90541a23b7c5ab1c6448f7188563a097c5f78a349073737d7a37cdb08bcb09ca6dc31b4229260d88a93c7a948411e7da3b309c41987771bf8c71151aa9bc4369f1515463587c42387bb48c52846491b1d9227c0686fa1549246f44424aa258e443b431096ec2ccd377a88e24c98229236fa016bab815466c40eeae134ca77704348a2b6627cbed551d1ea0daf635206d425f600c73edc4b98c02bdf0b5efc7b73ce75a2924043e2436c944771630259f0516b30b529a64062b3098dc8343852e598887c88dbaa0b2c709b1a58941916ba4edb9caec90eb6f930f9da5cb58bb855862b59263eeda31d2a06a89763b838d10f6a0c3199c1b10bcc9d1549b0e860a1f0901698c350b7eb5e86104ff631361fd6beec2c77806362833c2efa3063810c86faa7b5ab92389eab258320265fb23f0d7a2b3a9aad03c94604cb43d532376314b2e8d4cfedda36b578b590e6146ea18c6847a0569c8318a68620f294e9d9875d014549695bd3ca68c430577092a375ac3a37203a0336c1e134b45af2548bccc8ce075e4e74a370f16d4bcbc90c8cb42ed09b5dd05c620528d9dac66833bc02e7734967c6a7cc4bebe95b85d7275b976c9ac0997eb264a0a684d4279512054a3258a39e604f1ec148ca2130d29a1ab92b53c1b0ab4ee3805f339201e968847b78739175fd695181b7a7ce500bd31a0685926e04d5ce6d2b612845ba68d39f617c21afa75f26bca95c17507698af280c0c5f21890ab78a8e56b1e94509b226066624a7c6701c3ae461c54161e7d5760279acc167cc01908b7d4a19576459e9b6276ce2c791990851fb9f8b197cf0c96de1fb61cd1c13c222c5194182edc4695e295d54a506fa09b0881169a6f32a8afc0acd5644876b5e698105f36a56a16aaf49041ea34a92619969b983025d585ee6f1bcfa131e995431b2b3a68b514534a599af1c13ad095d38cb458a1a8ac7f51524503166a63cf6d8963aa89a20c37013984672f79a9be13f93719d89e765a82a4775d531b3ebcb8b4c2935510ba6a770bc10a8a4ec60f01a9a20250050d96c535454f5b69b8cf8c00c44790f3964a1f4b2fabc5a85f061348c89e3ba1797c0c26bf3bbcad70d93822f932a18ca7ca0cf866c6b1b4de2571606f01eb2e5ab3be719c91370f29363a218aacf40284dc6c3c59671df4b62d5e44e81039c3498248a7659f0074996533e8097a0aee389a6d9ae9364b3a64bcf4e576f67802b89943ae03a24d2772726887f5fc803933111d4aa35da30a78b560bb4ec2dc918a3998281f046093f897919078ebdf05ec7f7ce03311a79bc49cb537322e8c6a6abbe56a55f6e1555e384ba6fa9c4f8e0189d3650c26aee67cbe704d7465022c259b6534361651c9b6d71fc98e18f84ff8aa1f3e880bcdbd8eddd440e3d7e99580bd9bc7f83f444daa761442c1a625dc5d44da361001d0020afa0c21e9ab34f115732ecb8e6b5d83379c4660811738d8be560cafde446fd0b00000020001e00001b6d63732d6d696d702d7765622e73662d657870726573732e636f6d002b0007064a4a03030303000a000c000afafa11ec001d0017001800230000001b000302000244690005000302683100170000fe0d011a0000010001960020cb3de92f31efcfcd5a53c79fbe3200c1f481e37199aa290649f1abad6ed5031e00f0dcb724c041356d77ecf7cf213696ee291b549ee48b028251d6ddde9865586ea997acd0a5210799395fd9682738cf609dd99a9c829efbc5ba83ffc2d8932b551886b5c1ebc1ac1233273e5ccfe8fa1e50fb0812f05f0fcb607672a934c778acc998173d746e8672f2aa6b60efa66369ffd7c03b9d7dcf3fc3f0cdb255347d8394dae22615b14c5ff626fa8e65b5d93278da980f307f21af1a124cab78db6d41d1cfe69d7f1ab90038f7d209f85e7d7d5ad045a2ca484569320dcae3f33b163992f0e68268899d3dabdb83f3177f115f97d165ba545ef9c193a16abc8ad3b24d458af544fb553218136e8dfa1230aa000c0010000e000c02683108687474702f312e3100120000000d0012001004030804040105030805050108060601ff01000100eaea00010016030300251000002120db295d27307243c8688dc4c8136ad6241713f787a2a6554d616e27965b789a41140303000101", "691j799n9c-j3g2d251k799n9c-j3l11961k").unwrap();
    // let fingerprint = Fingerprint::random("516k711n1c-j592g6.1k711n1c-j5d6a561k").unwrap();
    // let certs = Certificate::from_pem_file("/home/xl/1/client.crt").unwrap();
    // let key = RsaKey::from_pri_pem_file("/home/xl/1/client.key").unwrap();
    let mut req = AcReq::new()
        .with_fingerprint(Fingerprint::random("-").unwrap())
        .with_alpn(ALPN::Http20)
        .with_timeout(timeout)
        .with_verify(false)
        // .with_mtls(certs, key)
        // .with_proxy(Proxy::try_from("http://127.0.0.1:10240").unwrap())
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
    // let params = json::object! {
    //     tRef:"fullpage",
    //     tLc:2,
    //     text28777:"",
    //     tLabels:"92001903143160000052257347",
    //     tABt:false,
    // };
    // req.set_auto_redirect(false);
    let res=req.get("https://m.so.com",None).await.unwrap();
    // let res = req.get("https://tools.usps.com/go/TrackConfirmAction".params(params.clone()), None).await.unwrap();
    // let res = req.get("https://tools.usps.com/go/TrackConfirmAction".params(params), None).await.unwrap();
    println!("{}", res.header());
    // println!("{}", res.text().unwrap());
    // req.set_url("https://m.so.com").await.unwrap();
    // req.set_url("https://im.jinritemai.com/").await.unwrap();
    // req.set_auto_redirect(false);
    // req.set_url("https://cn.bing.com/AS/Suggestions?pt=page.home&qry=&csr=1&pths=1&zis=1&pf=1&cvid=AFEA02EAF9E449A99970476597AE6CED").await.unwrap();
    // req.set_text("sfssdfsfsdfdf");
    // println!("{:?}",String::from_utf8(fs::read("/home/xl/1/ca.crt").unwrap()).unwrap());
    // let data = json::object! {"test_key":"test_value"};
    // let file = HttpFile::new_bytes_data(data, fs::read("/home/xl/1/ca.crt").unwrap());
    // req.set_files(file).unwrap();
    // req.set_data(data);
    // println!("{}", req.h1_raw_string().unwrap());
    // let res = req.get().await.unwrap();
    // println!("{} {:#?}", res.header().status(), req.header().cookies());
    // let params = json::object! {
    //     format:"{\\json",
    //     ecount:20,
    //     efirst:0
    // };
    // let url = "https://cn.bing.com/hp/api/v1/carousel".to_string();
    // // println!("{}", url);
    // let res = req.get(url.params(params), None).await.unwrap();
    // req.set_url("https://cn.bing.com/notifications/render?bnptrigger=%7B%22PartnerId%22%3A%22HomePage%22%2C%22IID%22%3A%22Bnp%22%2C%22Attributes%22%3A%7B%22RawRequestURL%22%3A%22%2F%22%7D%7D&IG=AFEA02EAF9E449A99970476597AE6CED&IID=Bnp").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/web/xlsc.aspx?dl=1&f=8").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/hp/api/model").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/sa/simg/favicon-trans-bg-blue-mg-png.png").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/web/xlsc.aspx?dl=1&f=8").await.unwrap();
    // let res = req.get().await.unwrap();
    // let res = req.get().await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/AS/Suggestions?pt=page.home&qry=&csr=1&pths=1&zis=1&pf=1&cvid=AFEA02EAF9E449A99970476597AE6CED").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/hp/api/v1/carousel?&format=json&ecount=20&efirst=0&&").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/notifications/render?bnptrigger=%7B%22PartnerId%22%3A%22HomePage%22%2C%22IID%22%3A%22Bnp%22%2C%22Attributes%22%3A%7B%22RawRequestURL%22%3A%22%2F%22%7D%7D&IG=AFEA02EAF9E449A99970476597AE6CED&IID=Bnp").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/web/xlsc.aspx?dl=1&f=8").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/hp/api/model").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/sa/simg/favicon-trans-bg-blue-mg-png.png").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/web/xlsc.aspx?dl=1&f=8").await.unwrap();
    // let res = req.get().await.unwrap();
    // let res = req.get().await.unwrap();
    // let res = req.get().await.unwrap();
    // println!("{}", res.header());
}