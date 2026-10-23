mod key_usage;
mod subject;
mod extend;
mod key_identifier;
mod basic_constraints;
mod alt_name;

use crate::boring::bindings::EVP_sha256;
use crate::boring::rsa::bindings::*;
use crate::boring::BoringResExt;
use crate::error::RlsResult;
use crate::ffi::CPointer;
use crate::{rand, Certificate, RlsError, RsaKey};
use std::ffi::CString;
use std::os::raw::c_long;
use std::ptr::null_mut;
pub use subject::DnType;
pub use extend::CertExtend;
pub use key_identifier::KeyIdentifier;
pub use key_usage::KeyUsage;
pub use basic_constraints::BasicConstraint;
pub use alt_name::SubjectAltName;

pub struct CertSigner {
    pkey: RsaKey,
    cert: Certificate,
    name: CPointer<X509_NAME>,
    ctx: X509V3_CTX,
    root: Certificate,
}

impl CertSigner {
    fn new(key_size: i32, root: Certificate) -> RlsResult<CertSigner> {
        let pkey = RsaKey::gen_new_key(key_size)?;
        let x509 = CPointer::new_checked(unsafe { X509_new() }, RlsError::X509NewError)?;
        unsafe { X509_set_version(x509.as_mut_ptr(), 2) }.ok(RlsError::X509SetVersionFail)?;
        //serial
        let mut serial_bytes = rand::random::<[u8; 20]>();
        serial_bytes[0] &= 0x7F;
        let bn = CPointer::new_checked(unsafe { BN_bin2bn(serial_bytes.as_ptr(), 20, null_mut()) }, RlsError::BnNewError)?;

        let serial = CPointer::new_checked(unsafe { ASN1_INTEGER_new() }, RlsError::NewAsn1IntegerError)?;
        unsafe { BN_to_ASN1_INTEGER(bn.as_ptr(), serial.as_mut_ptr()) };
        unsafe { X509_set_serialNumber(x509.as_mut_ptr(), serial.as_ptr()); }
        //pubkey
        unsafe { X509_set_pubkey(x509.as_mut_ptr(), pkey.pkey().as_mut_ptr()); }
        let name = CPointer::new_checked(unsafe { X509_NAME_new() }, RlsError::NewX509NameError)?;
        Ok(CertSigner {
            pkey,
            name,
            ctx: X509V3_CTX {
                flags: 0,
                issuer_cert: if root.is_none() { x509.as_ptr() } else { root.x509().as_ptr() },
                subject_cert: x509.as_ptr(),
                subject_req: null_mut(),
                crl: null_mut(),
                db: null_mut(),
            },
            cert: Certificate::new(x509),
            root,
        })
    }
    pub fn root_siger(key_size: i32) -> RlsResult<CertSigner> {
        CertSigner::new(key_size, Certificate::none())
    }

    pub fn server_signer(key_size: i32, ca_cert: Certificate) -> RlsResult<CertSigner> {
        CertSigner::new(key_size, ca_cert)
    }


    pub fn set_expire(&mut self, years: c_long) -> RlsResult<()> {
        unsafe { X509_gmtime_adj(X509_get_notBefore(self.cert.x509().as_ptr()), 0); }
        unsafe { X509_gmtime_adj(X509_get_notAfter(self.cert.x509().as_ptr()), 60 * 60 * 24 * 365 * years); }
        Ok(())
    }

    pub fn add_subject(&self, dn: DnType, value: impl AsRef<str>) -> RlsResult<()> {
        let field = CString::new(dn.filed_value())?;
        let value = CString::new(value.as_ref())?;
        unsafe {
            X509_NAME_add_entry_by_txt(
                self.name.as_mut_ptr(),
                field.as_ptr(),
                MBSTRING_ASC,
                value.as_ptr() as *const u8,
                -1,
                -1,
                0,
            ).ok(RlsError::X509AddNameError)
        }
    }

    pub fn add_extension(&mut self, extension: CertExtend) -> RlsResult<()> {
        let value = CString::new(extension.value())?;
        let ext = unsafe {
            X509V3_EXT_nconf_nid(
                null_mut(),
                &self.ctx,
                extension.nid(),
                value.as_ptr(),
            )
        };
        let ext = CPointer::new_checked(ext, RlsError::NewX509ExtError)?;
        unsafe { X509_add_ext(self.cert.x509().as_mut_ptr(), ext.as_ptr(), -1) }.ok(RlsError::X509AddExtFail)
    }

    pub fn sign_by_self(&mut self) -> RlsResult<()> {
        unsafe { X509_set_subject_name(self.cert.x509().as_mut_ptr(), self.name.as_ptr()) }.ok(RlsError::X509SetSubjectError)?;
        unsafe { X509_set_issuer_name(self.cert.x509().as_mut_ptr(), self.name.as_ptr()) }.ok(RlsError::X509SetIssuerError)?;
        //sign
        let ret = unsafe { X509_sign(self.cert.x509().as_mut_ptr(), self.pkey.pkey().as_mut_ptr(), EVP_sha256()) };
        if ret <= 0 { return Err(RlsError::X509SignError); }
        Ok(())
    }

    pub fn sign_by(&mut self, ca_key: &RsaKey) -> RlsResult<()> {
        unsafe { X509_set_subject_name(self.cert.x509().as_mut_ptr(), self.name.as_ptr()) }.ok(RlsError::X509SetSubjectError)?;
        let ca_subject = unsafe { X509_get_subject_name(self.root.x509().as_ptr()) };
        unsafe { X509_set_issuer_name(self.cert.x509().as_mut_ptr(), ca_subject) }.ok(RlsError::X509SetIssuerError)?;
        //sign
        let ret = unsafe { X509_sign(self.cert.x509().as_mut_ptr(), ca_key.pkey().as_mut_ptr(), EVP_sha256()) };
        if ret <= 0 { return Err(RlsError::X509SignError); }
        Ok(())
    }

    pub fn verify(&mut self) -> RlsResult<()> {
        unsafe {
            X509_verify(self.cert.x509.as_ptr(), self.root.pub_key()?.as_mut_ptr())
        }.ok("invalid cert".into())
    }

    pub fn key(&self) -> &RsaKey {
        &self.pkey
    }

    pub fn cert_mut(&mut self) -> &mut Certificate { &mut self.cert }
}

#[cfg(test)]
mod tests {
    use crate::boring::certificate::siger::basic_constraints::BasicConstraint;
    use crate::boring::certificate::siger::extend::CertExtend;
    use crate::boring::certificate::siger::key_identifier::KeyIdentifier;
    use crate::boring::certificate::siger::key_usage::KeyUsage;
    use crate::boring::certificate::siger::subject::DnType;
    use crate::boring::certificate::siger::CertSigner;
    use std::fs;
    use crate::boring::certificate::siger::alt_name::SubjectAltName;

    #[test]
    fn test_generate_root_ca() {
        let mut ca_signer = CertSigner::root_siger(2048).unwrap();
        ca_signer.set_expire(10).unwrap();
        ca_signer.add_subject(DnType::Country, "CN").unwrap();
        ca_signer.add_subject(DnType::StateOrProvince, "Guangdong").unwrap();
        ca_signer.add_subject(DnType::Locality, "Guangzhou").unwrap();
        ca_signer.add_subject(DnType::Organization, "XLX").unwrap();
        ca_signer.add_subject(DnType::OrganizationalUnit, "XLX").unwrap();
        ca_signer.add_subject(DnType::Common, "XLX CA").unwrap();
        ca_signer.add_extension(CertExtend::KeyUsage(vec![KeyUsage::Critical, KeyUsage::KeyCertSign, KeyUsage::CrlSign])).unwrap();
        ca_signer.add_extension(CertExtend::KeyIdentifier(vec![KeyIdentifier::Hash])).unwrap();
        ca_signer.add_extension(CertExtend::BasicConstraints(vec![BasicConstraint::Critical, BasicConstraint::Ca(true)])).unwrap();
        ca_signer.sign_by_self().unwrap();
        fs::write("ca.der", ca_signer.cert.as_der().unwrap().as_slice()).unwrap();

        let mut signer = CertSigner::server_signer(2048, ca_signer.cert).unwrap();
        signer.set_expire(1).unwrap();
        signer.add_subject(DnType::Country, "CN").unwrap();
        signer.add_subject(DnType::StateOrProvince, "Guangdong").unwrap();
        signer.add_subject(DnType::Locality, "Guangzhou").unwrap();
        signer.add_subject(DnType::Organization, "XLX").unwrap();
        signer.add_subject(DnType::OrganizationalUnit, "XLX").unwrap();
        signer.add_subject(DnType::Common, "baidu.com").unwrap();
        signer.add_extension(CertExtend::SubjectAltName(vec![SubjectAltName::dns("baidu.com"), SubjectAltName::dns("debug.baidu.com")])).unwrap();
        signer.add_extension(CertExtend::KeyIdentifier(vec![KeyIdentifier::Hash])).unwrap();
        signer.add_extension(CertExtend::BasicConstraints(vec![BasicConstraint::Critical, BasicConstraint::Ca(false)])).unwrap();
        signer.add_extension(CertExtend::KeyUsage(vec![KeyUsage::Critical, KeyUsage::DigitalSignature, KeyUsage::KeyEncipherment, KeyUsage::NonRepudiation])).unwrap();
        signer.add_extension(CertExtend::ExtKeyUsage(vec![KeyUsage::ServerAuth])).unwrap();
        signer.sign_by(&ca_signer.pkey).unwrap();
        fs::write("s.der", signer.cert.as_der().unwrap().as_slice()).unwrap();

        let mut signer = CertSigner::server_signer(2048, signer.root).unwrap();
        signer.set_expire(1).unwrap();
        signer.add_subject(DnType::Country, "CN").unwrap();
        signer.add_subject(DnType::StateOrProvince, "Guangdong").unwrap();
        signer.add_subject(DnType::Locality, "Guangzhou").unwrap();
        signer.add_subject(DnType::Organization, "XLX").unwrap();
        signer.add_subject(DnType::OrganizationalUnit, "XLX").unwrap();
        signer.add_subject(DnType::Common, "baidu.com").unwrap();
        signer.add_extension(CertExtend::BasicConstraints(vec![BasicConstraint::Critical, BasicConstraint::Ca(false)])).unwrap();
        signer.add_extension(CertExtend::KeyUsage(vec![KeyUsage::Critical, KeyUsage::DigitalSignature, KeyUsage::NonRepudiation])).unwrap();
        signer.add_extension(CertExtend::ExtKeyUsage(vec![KeyUsage::ClientAuth])).unwrap();
        signer.sign_by(&ca_signer.pkey).unwrap();
        fs::write("c.der", signer.cert.as_der().unwrap().as_slice()).unwrap();
        assert!(signer.cert.as_pem().unwrap().starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(signer.cert.as_pem().unwrap().trim().ends_with("-----END CERTIFICATE-----"))
    }
}