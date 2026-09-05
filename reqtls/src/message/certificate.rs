use super::HandshakeType;
use crate::buffer::Buf;
use crate::error::RlsResult;
use crate::{u24, BufferError, CertType, CompressionMethod, Reader, SignatureAlgorithm, Version, Writer};
use std::fmt::Debug;

#[derive(Debug)]
pub struct Certificates<'a> {
    handshake_type: HandshakeType,
    certificates: Vec<Buf<'a>>,
}

impl<'a> Default for Certificates<'a> {
    fn default() -> Self {
        Certificates {
            handshake_type: HandshakeType::Certificate,
            certificates: vec![],
        }
    }
}

impl<'a> Certificates<'a> {
    pub fn from_reader(version: &Version, reader: &mut Reader<'a>, compressed: bool) -> RlsResult<Certificates<'a>> {
        if !compressed { reader.read_u24()?; }
        if let &Version::TLS_1_3 = version {
            reader.read_u8()?; //req ctx len
        }
        let len = reader.read_u24()?;
        let mut reader = reader.read_reader(len as usize)?;
        let mut certificates = Vec::with_capacity(len as usize);
        while reader.unread_len() > 0 {
            let len = reader.read_u24()? as usize;
            certificates.push(Buf::Ref(reader.read_slice(len)?));
            if let &Version::TLS_1_3 = version {
                let ext_len = reader.read_u16()?; //ext len
                if ext_len > 0 {
                    let _exts = reader.read_slice(ext_len as usize)?;
                    // println!("cert ext: {:?}", _exts)
                }
            }
        }
        Ok(Certificates {
            handshake_type: HandshakeType::Certificate,
            certificates,
        })
    }

    pub fn len(&self) -> usize {
        7 + self.certificates.iter().map(|x| 3 + x.len()).sum::<usize>()
    }

    pub fn write_to(self, writer: &mut Writer) -> Result<(), BufferError> {
        writer.write_u8(self.handshake_type as u8)?;
        writer.write_u24(self.len() as u24 - 4)?;
        writer.write_u24(self.len() as u24 - 7)?;
        for certificate in self.certificates {
            writer.write_u24(certificate.len() as u24)?;
            writer.write_slice(certificate.as_ref())?;
        }
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn add_certificate(&mut self, cert: &'a [u8]) {
        self.certificates.push(Buf::Ref(cert));
    }

    pub fn certificates(&self) -> &Vec<Buf<'_>> {
        &self.certificates
    }
}

#[derive(Debug)]
pub struct CertificateStatus<'a> {
    handshake_type: HandshakeType,
    bytes: Buf<'a>,
}

impl<'a> CertificateStatus<'a> {
    pub fn from_reader(ht: HandshakeType, reader: &mut Reader<'a>) -> RlsResult<CertificateStatus<'a>> {
        let len = reader.read_u24()?;
        Ok(CertificateStatus {
            handshake_type: ht,
            bytes: Buf::Ref(reader.read_slice(len as usize)?),
        })
    }

    pub fn len(&self) -> usize { self.bytes.len() }

    pub fn write_to(self, writer: &mut Writer) -> Result<(), BufferError> {
        writer.write_u8(self.handshake_type as u8)?;
        writer.write_u24(self.bytes.len() as u24)?;
        writer.write_slice(self.bytes.as_ref())
    }
}


#[derive(Debug)]
pub struct CertificateRequest<'a> {
    handshake_type: HandshakeType,
    cert_type: Vec<CertType>,
    hashes: Vec<SignatureAlgorithm>,
    distinguished_name: Buf<'a>,
}

impl<'a> Default for CertificateRequest<'a> {
    fn default() -> Self {
        CertificateRequest {
            handshake_type: HandshakeType::CertificateRequest,
            cert_type: vec![],
            hashes: vec![],
            distinguished_name: Buf::Ref(&[]),
        }
    }
}

impl<'a> CertificateRequest<'a> {
    pub fn random() -> CertificateRequest<'a> {
        let mut res = CertificateRequest {
            cert_type: vec![CertType::RSA, CertType::ECDSA],
            hashes: vec![
                SignatureAlgorithm::RSA_PSS_PSS_SHA256.into(),
                SignatureAlgorithm::RSA_PSS_PSS_SHA384.into(),
                SignatureAlgorithm::RSA_PSS_PSS_SHA512.into(),
            ],
            ..CertificateRequest::default()
        };
        for hash in SignatureAlgorithm::ALL {
            if res.hashes.len() >= 10 { break; }
            if res.hashes.iter().any(|x| x.as_u16() == hash) { continue; }
            res.hashes.push(SignatureAlgorithm::new(hash));
        }
        res
    }

    pub fn from_reader(ht: HandshakeType, reader: &mut Reader<'a>) -> RlsResult<CertificateRequest<'a>> {
        let mut res = CertificateRequest {
            handshake_type: ht,
            ..Default::default()
        };
        reader.read_u24()?;
        for _ in 0..reader.read_u8()? {
            res.cert_type.push(CertType::new(reader.read_u8()?));
        }
        let len = reader.read_u16()?;
        for _ in (0..len).step_by(2) {
            res.hashes.push(SignatureAlgorithm::new(reader.read_u16()?));
        }
        let len = reader.read_u16()?;
        res.distinguished_name = Buf::Ref(reader.read_slice(len as usize)?);
        Ok(res)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn len(&self) -> usize {
        9 + self.cert_type.len() + self.hashes.len() * 2 + self.distinguished_name.len()
    }

    pub fn write_to(self, writer: &mut Writer) -> Result<(), BufferError> {
        writer.write_u8(self.handshake_type as u8)?;
        writer.write_u24(self.len() as u24 - 4)?;
        writer.write_u8(self.cert_type.len() as u8)?;
        writer.write_u16(self.hashes.len() as u16 * 2)?;
        for hash in self.hashes {
            writer.write_u16(hash.into_inner())?;
        }
        writer.write_u16(self.distinguished_name.len() as u16)?;
        writer.write_slice(self.distinguished_name.as_ref())
    }

    pub fn hashes(&self) -> &Vec<SignatureAlgorithm> {
        &self.hashes
    }

    pub fn into_hashes(self) -> Vec<SignatureAlgorithm> {
        self.hashes
    }
}

#[derive(Debug)]
pub struct CertificateVerify<'a> {
    handshake_type: HandshakeType,
    sign_hash: SignatureAlgorithm,
    sign: Buf<'a>,
}

impl<'a> Default for CertificateVerify<'a> {
    fn default() -> Self {
        CertificateVerify {
            handshake_type: HandshakeType::CertificateVerify,
            sign_hash: SignatureAlgorithm::RSA_PSS_RSAE_SHA256.into(),
            sign: Buf::Ref(&[]),
        }
    }
}

impl<'a> CertificateVerify<'a> {
    pub fn from_reader(ht: HandshakeType, reader: &mut Reader<'a>) -> RlsResult<CertificateVerify<'a>> {
        reader.read_u24()?;
        let sign_hash = SignatureAlgorithm::new(reader.read_u16()?);
        let sign_len = reader.read_u16()?;
        Ok(CertificateVerify {
            handshake_type: ht,
            sign_hash,
            sign: Buf::Ref(reader.read_slice(sign_len as usize)?),
        })
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn len(&self) -> usize {
        8 + self.sign.len()
    }

    pub fn write_to(self, writer: &mut Writer) -> Result<(), BufferError> {
        writer.write_u8(self.handshake_type as u8)?;
        writer.write_u24(self.len() as u24 - 4)?;
        writer.write_u16(self.sign_hash.into_inner())?;
        writer.write_u16(self.sign.len() as u16)?;
        writer.write_slice(self.sign.as_ref())
    }

    pub fn set_hash(&mut self, hash: SignatureAlgorithm) {
        self.sign_hash = hash;
    }

    pub fn set_sign(&mut self, sign: &'a [u8]) {
        self.sign = Buf::Ref(sign);
    }

    pub fn hash(&self) -> SignatureAlgorithm {
        self.sign_hash
    }

    pub fn sign(&self) -> &Buf<'_> {
        &self.sign
    }
}


#[derive(Debug)]
pub struct CompressedCertificate<'a> {
    handshake_type: HandshakeType,
    algorithm: CompressionMethod,
    uncompressed_len: u24,
    data: Buf<'a>,
}


impl<'a> CompressedCertificate<'a> {
    pub fn len(&self) -> usize {
        1 + 3 + 2 + 3 + 3 + self.data.len()
    }
    pub fn from_reader(ht: HandshakeType, reader: &mut Reader<'a>) -> RlsResult<CompressedCertificate<'a>> {
        reader.read_u24()?;
        let algorithm = reader.read_u16()?.into();
        let uncompressed_len = reader.read_u24()?;
        let len = reader.read_u24()? as usize;
        Ok(CompressedCertificate {
            handshake_type: ht,
            algorithm,
            uncompressed_len,
            data: Buf::Ref(reader.read_slice(len)?),
        })
    }

    pub fn write_to(self, writer: &mut Writer) -> Result<(), BufferError> {
        writer.write_u8(self.handshake_type as u8)?;
        writer.write_u16(self.algorithm.into_inner())?;
        writer.write_u24(self.uncompressed_len)?;
        writer.write_u24(self.data.len() as u24)?;
        writer.write_slice(self.data.as_ref())
    }

    pub fn algorithm(&self) -> CompressionMethod {
        self.algorithm
    }

    pub fn compressed_data(&self) -> &Buf<'_> {
        &self.data
    }
}