use crate::boring::rsa::bindings::*;
use crate::boring::BoringResExt;
use crate::error::RlsResult;
use crate::{Certificate, RlsError, Url};
use std::ffi::CStr;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::LazyLock;
#[cfg(feature = "log")]
use log::{debug, error};
use crate::ffi::CPointer;

pub static ROOT_STORES: LazyLock<CertStore> = LazyLock::new(|| {
    let certs = Certificate::from_pem(include_bytes!("../../../../roots")).unwrap();
    let mut store = CertStore::empty().unwrap();
    store.extend_certs(certs).unwrap();
    store
});


pub struct CertStore {
    store_ptr: CPointer<X509_STORE>,
    //保存指针
    stores: Vec<Certificate>,
}

impl CertStore {
    pub fn empty() -> RlsResult<CertStore> {
        let store_ptr = CPointer::new_checked(unsafe { X509_STORE_new() }, RlsError::X509StoreNewError)?;
        Ok(CertStore {
            store_ptr,
            stores: vec![],
        })
    }

    pub fn add_cert(&self, cert: &Certificate) -> RlsResult<()> {
        unsafe { X509_STORE_add_cert(self.store_ptr.as_mut_ptr(), cert.x509().as_mut_ptr()) }.ok(RlsError::X509StoreAddError)?;
        Ok(())
    }

    pub fn extend_certs(&mut self, certs: Vec<Certificate>) -> RlsResult<()> {
        for cert in certs {
            self.add_cert(&cert)?;
            self.stores.push(cert);
        }
        Ok(())
    }

    pub fn pointer(&self) -> &CPointer<X509_STORE> { &self.store_ptr }

    pub fn verify_cert(&self, certs: &mut Vec<Certificate>, ext_cas: &[Certificate], sni: &str) -> RlsResult<()> {
        #[cfg(feature = "log")]
        debug!("[Verify] chain_certs={}; ext_cas={}; sni={}", certs.len(), ext_cas.len(), sni);
        let stack = CPointer::new_checked(unsafe { sk_new_null() }, RlsError::SkNewError)?;
        for ext_ca in ext_cas {
            self.add_cert(ext_ca)?;
        }
        for cert in &certs[1..] {
            let len = unsafe { sk_push(stack.as_mut_ptr(), cert.x509().as_mut_ptr() as _) };
            if len == 0 { return Err(RlsError::SkPushError); }
        }
        let ctx = CPointer::new_checked(unsafe { X509_STORE_CTX_new() }, RlsError::X509StoreCtxNewError)?;
        unsafe {
            X509_STORE_CTX_init(
                ctx.as_mut_ptr(),
                self.store_ptr.as_mut_ptr(),
                certs[0].x509().as_mut_ptr(),
                stack.as_mut_ptr() as _,
            )
        }.ok(RlsError::X509StoreCtxInitError)?;
        let ret = unsafe { X509_verify_cert(ctx.as_mut_ptr()) };
        if ret != 1 {
            let err = unsafe { X509_STORE_CTX_get_error(ctx.as_ptr()) };
            if err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT || err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY {
                let aia = certs.last().ok_or("cert empty")?.get_aia().or(Err(RlsError::IssuerUnknown))?;
                if aia.is_empty() { return Err(RlsError::IssuerUnknown); }
                for uri in aia {
                    let cert = download_cert(uri)?;
                    certs.push(cert);
                }
                return self.verify_cert(certs, ext_cas, sni);
            }
            let msg_prt = unsafe { X509_verify_cert_error_string(err as _) };
            #[cfg(feature = "log")]
            error!("[Verify] Verify failed: {}",unsafe{CStr::from_ptr(msg_prt).to_str()?});
            return Err(RlsError::from(unsafe { CStr::from_ptr(msg_prt) }.to_bytes()));
        };
        certs[0].verify_sni(sni)
    }
}


pub fn download_cert(url: impl AsRef<str>) -> RlsResult<Certificate> {
    let url = Url::try_from(url.as_ref())?;
    let mut tcp = TcpStream::connect(url.addr().to_string())?;
    let context = format!("GET {} HTTP/1.1\r\nHost: {}\r\nAccept: */*\r\n\r\n", url.uri(), url.addr().host());
    tcp.write_all(context.into_bytes().as_ref())?;
    let mut res = vec![];
    let mut context_len = 0;
    loop {
        let mut buf = [0; 1024];
        let len = tcp.read(&mut buf)?;
        res.extend_from_slice(&buf[..len]);
        if context_len == 0 {
            if let Some(pos) = res.windows(4).position(|w| w == b"\r\n\r\n") {
                let header = String::from_utf8_lossy(&res[..pos]).to_string();
                for line in header.split("\r\n") {
                    if line.to_lowercase().starts_with("content-length") {
                        context_len = line.split(": ").last().ok_or("context-length empty")?.parse()?;
                        res.drain(0..pos + 4);
                        break;
                    }
                }
            }
        } else if res.len() >= context_len { break; }
    }
    Certificate::from_der(&res)
}