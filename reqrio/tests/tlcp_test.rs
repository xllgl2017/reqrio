use std::{env, fs};
use reqrio::*;

fn build_finger() -> Result<Fingerprint, HlsError> {
    let token = fs::read_to_string("../TOKEN").unwrap_or_else(|_| {
        env::var("REQRIO_TOKEN").unwrap_or("".to_string())
    });
    Fingerprint::new_tls(TlsFinger::Custom {
        record_version: Version::TLCP,
        message_version: Version::TLCP,
        suites: vec![
            CipherSuite::ECC_SM4_CBC_SM3,
        ],
        extensions: vec![
            Extension::Reserved { typ: 0xfafa, value: Buf::Ref(&[]) },
            Extension::ServerName(vec![ServerName::new_sni("")]),
            Extension::Reserved { typ: 0x8a8a, value: Buf::Ref(&[0]) },
        ],
    }, token)
}

#[test]
fn tlcp_sync() {
    let mut req = ScReq::new()
        .with_fingerprint(build_finger().unwrap());
    let resp = req.get("https://test.gmssl.cn", None).unwrap();
    assert_eq!(resp.header().status(), HttpStatus::OK);
}

#[cfg(feature = "aync")]
#[tokio::test]
async fn tlcp_async() {
    let mut req = AcReq::new()
        .with_fingerprint(build_finger().unwrap());
    let resp = req.get("https://test.gmssl.cn", None).await.unwrap();
    assert_eq!(resp.header().status(), HttpStatus::OK);
}
