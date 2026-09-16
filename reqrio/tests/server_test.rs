use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::Duration;
#[cfg(feature = "aync")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use reqrio::*;

fn gen_ca() -> (Vec<u8>, Vec<u8>) {
    let mut ca_signer = CertSigner::root_siger(2048).unwrap();
    ca_signer.set_expire(10).unwrap();
    //Country code, only two characters
    ca_signer.add_subject(DnType::Country, "US").unwrap();
    ca_signer.add_subject(DnType::StateOrProvince, "Reqrio").unwrap();
    ca_signer.add_subject(DnType::Locality, "XXX").unwrap();
    ca_signer.add_subject(DnType::Organization, "XXX").unwrap();
    ca_signer.add_subject(DnType::OrganizationalUnit, "XXX").unwrap();
    ca_signer.add_subject(DnType::Common, "XXX").unwrap();
    //Certificate Purpose
    ca_signer.add_extension(CertExtend::KeyUsage(vec![KeyUsage::Critical, KeyUsage::KeyCertSign, KeyUsage::CrlSign])).unwrap();
    ca_signer.add_extension(CertExtend::KeyIdentifier(vec![KeyIdentifier::Hash])).unwrap();
    ca_signer.add_extension(CertExtend::BasicConstraints(vec![BasicConstraint::Critical, BasicConstraint::Ca(true)])).unwrap();
    ca_signer.sign_by_self().unwrap();
    (ca_signer.cert_mut().as_der().unwrap().as_slice().to_vec(), ca_signer.key().to_pri_der().unwrap().as_slice().to_vec())
}

fn gen_server_cert(ca: &[u8], key: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let ca = Certificate::from_der(ca).unwrap();
    let key = RsaKey::from_pri_der(key).unwrap();
    let mut signer = CertSigner::server_signer(2048, ca).unwrap();
    signer.set_expire(1).unwrap();
    signer.add_subject(DnType::Country, "CN").unwrap();
    signer.add_subject(DnType::StateOrProvince, "xxxx").unwrap();
    signer.add_subject(DnType::Locality, "xxxx").unwrap();
    signer.add_subject(DnType::Organization, "xx").unwrap();
    signer.add_subject(DnType::OrganizationalUnit, "xxx").unwrap();
    signer.add_subject(DnType::Common, "test.reqrio.org").unwrap();
    signer.add_extension(CertExtend::SubjectAltName(vec![SubjectAltName::dns("test.reqrio.org")])).unwrap();
    signer.add_extension(CertExtend::KeyIdentifier(vec![KeyIdentifier::Hash])).unwrap();
    signer.add_extension(CertExtend::BasicConstraints(vec![BasicConstraint::Critical, BasicConstraint::Ca(false)])).unwrap();
    signer.add_extension(CertExtend::KeyUsage(vec![KeyUsage::Critical, KeyUsage::DigitalSignature, KeyUsage::KeyEncipherment, KeyUsage::NonRepudiation])).unwrap();
    signer.add_extension(CertExtend::ExtKeyUsage(vec![KeyUsage::ServerAuth])).unwrap();
    signer.sign_by(&key).unwrap();
    (signer.cert_mut().as_der().unwrap().as_slice().to_vec(), signer.key().to_pri_der().unwrap().as_slice().to_vec())
}


#[cfg(all(feature = "aync", test))]
fn aync_server(ca: &[u8], cert: &[u8], key: &[u8]) {
    let mut cert = vec![Certificate::from_der(cert).unwrap()];
    let key = RsaKey::from_pri_der(key).unwrap();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().thread_stack_size(16 * 1024 * 1024).build().unwrap();
    let _ = rt.enter();
    rt.spawn(async move {
        let listen = tokio::net::TcpListener::bind("0.0.0.0:7877").await.unwrap();
        let (stream, _) = listen.accept().await.unwrap();
        let mut tls_stream = TlsStream::accept(stream, ServerConfig {
            alpn: &ALPN::HTTP11,
            ca: &mut Certificate::none(),
            server_cert: &mut cert,
            cert_key: &key,
            verify: false,
            ca_certs: &vec![],
            key_log: None,
        }).await.unwrap();
        let mut buffer = [0; 1024];
        let _ = tls_stream.read(&mut buffer).await.unwrap();
        if buffer.starts_with(b"GET") || buffer.starts_with(b"POST") {
            tls_stream.write_all("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".as_bytes()).await.unwrap();
        }
    });
    rt.block_on(async move {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let cas = Certificate::from_der(ca).unwrap();
        let mut req = AcReq::new().with_verify(false);
        req.set_mtls(vec![], RsaKey::none(), Some(vec![cas]));
        let resp = req.get("https://127.0.0.1:7877".sni("test.reqrio.org"), None).await.unwrap();
        assert_eq!(resp.header().status(), &HttpStatus::OK);
    });
}


fn sync_server(ca: &[u8], cert: &[u8], key: &[u8]) {
    let mut cert = vec![Certificate::from_der(cert).unwrap()];
    let key = RsaKey::from_pri_der(key).unwrap();
    std::thread::spawn(move || {
        let listen = TcpListener::bind("0.0.0.0:7878").unwrap();
        let (stream, _) = listen.accept().unwrap();
        let mut tls_stream = TlsStream::accept(stream, ServerConfig {
            alpn: &ALPN::HTTP11,
            ca: &mut Certificate::none(),
            server_cert: &mut cert,
            cert_key: &key,
            verify: false,
            ca_certs: &vec![],
            key_log: None,
        }).wait().unwrap();
        let mut buffer = [0; 1024];
        let _ = tls_stream.read(&mut buffer).unwrap();
        if buffer.starts_with(b"GET") || buffer.starts_with(b"POST") {
            tls_stream.write_all("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".as_bytes()).unwrap();
        }
    });
    std::thread::sleep(Duration::from_secs(1));
    let cas = Certificate::from_der(ca).unwrap();
    let mut req = ScReq::new();
    req.set_mtls(vec![], RsaKey::none(), Some(vec![cas]));
    let resp = req.get("https://127.0.0.1:7878".sni("test.reqrio.org"), None).unwrap();
    assert_eq!(resp.header().status(), &HttpStatus::OK);
}

#[test]
fn test_server() {
    let (ca_cert, ca_key) = gen_ca();
    let (server_cert, server_key) = gen_server_cert(ca_cert.as_slice(), ca_key.as_slice());
    sync_server(ca_cert.as_slice(), server_cert.as_slice(), server_key.as_slice());
    #[cfg(feature = "aync")]
    aync_server(ca_cert.as_slice(), server_cert.as_slice(), server_key.as_slice());
}