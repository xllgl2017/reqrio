use crate::error::RlsResult;

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy)]
pub enum SignatureAlgorithm {
    RSA_PKCS1_SHA1 = 0x0201,
    RSA_PKCS1_SHA256 = 0x0401,
    RSA_PKCS1_SHA384 = 0x0501,
    RSA_PKCS1_SHA512 = 0x0601,
    RSA_PSS_RSAE_SHA256 = 0x0804,
    RSA_PSS_RSAE_SHA384 = 0x0805,
    RSA_PSS_RSAE_SHA512 = 0x0806,
    RSA_PSS_PSS_SHA256 = 0x0807,
    RSA_PSS_PSS_SHA384 = 0x0808,
    RSA_PSS_PSS_SHA512 = 0x0809,

    ED25519 = 0x080A,
    ED448 = 0x080B,

    ECDSA_SHA1 = 0x0203,
    ECDSA_SECP256R1_SHA256 = 0x0403,
    ECDSA_SECP384R1_SHA384 = 0x0503,
    ECDSA_SECP521R1_SHA512 = 0x0603,
    SHA1_DSA = 0x0202,
    SHA224_RSA = 0x0301,
    SHA224_DSA = 0x0302,
    SHA224_ECDSA = 0x0303,
    SHA256_DSA = 0x0402,
    SHA384_DSA = 0x0502,
    SHA512_DSA = 0x0602,
}

impl SignatureAlgorithm {
    pub fn from_u16(value: u16) -> Option<SignatureAlgorithm> {
        match value {
            0x0201 => Some(SignatureAlgorithm::RSA_PKCS1_SHA1),
            0x0401 => Some(SignatureAlgorithm::RSA_PKCS1_SHA256),
            0x0501 => Some(SignatureAlgorithm::RSA_PKCS1_SHA384),
            0x0601 => Some(SignatureAlgorithm::RSA_PKCS1_SHA512),
            0x0804 => Some(SignatureAlgorithm::RSA_PSS_RSAE_SHA256),
            0x0805 => Some(SignatureAlgorithm::RSA_PSS_RSAE_SHA384),
            0x0806 => Some(SignatureAlgorithm::RSA_PSS_RSAE_SHA512),
            0x0807 => Some(SignatureAlgorithm::RSA_PSS_PSS_SHA256),
            0x0808 => Some(SignatureAlgorithm::RSA_PSS_PSS_SHA384),
            0x0809 => Some(SignatureAlgorithm::RSA_PSS_PSS_SHA512),
            0x080A => Some(SignatureAlgorithm::ED25519),
            0x080B => Some(SignatureAlgorithm::ED448),
            0x0203 => Some(SignatureAlgorithm::ECDSA_SHA1),
            0x0403 => Some(SignatureAlgorithm::ECDSA_SECP256R1_SHA256),
            0x0503 => Some(SignatureAlgorithm::ECDSA_SECP384R1_SHA384),
            0x0603 => Some(SignatureAlgorithm::ECDSA_SECP521R1_SHA512),
            0x0202 => Some(SignatureAlgorithm::SHA1_DSA),
            0x0301 => Some(SignatureAlgorithm::SHA224_RSA),
            0x0302 => Some(SignatureAlgorithm::SHA224_DSA),
            0x0303 => Some(SignatureAlgorithm::SHA224_ECDSA),
            0x0402 => Some(SignatureAlgorithm::SHA256_DSA),
            0x0502 => Some(SignatureAlgorithm::SHA384_DSA),
            0x0602 => Some(SignatureAlgorithm::SHA512_DSA),
            _ => None
        }
    }

    pub fn as_bytes(&self) -> [u8; 2] {
        (*self as u16).to_be_bytes()
    }
}

#[derive(Debug)]
pub struct SignatureAlgorithms {
    hash_len: u16,
    hash: Vec<SignatureAlgorithm>,
}

impl SignatureAlgorithms {
    pub fn new() -> SignatureAlgorithms {
        SignatureAlgorithms {
            hash_len: 0,
            hash: vec![],
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> RlsResult<SignatureAlgorithms> {
        let mut res = SignatureAlgorithms::new();
        res.hash_len = u16::from_be_bytes([bytes[0], bytes[1]].try_into()?);
        for chunk in bytes[2..].chunks(2) {
            let v = u16::from_be_bytes(chunk.try_into()?);
            res.hash.push(SignatureAlgorithm::from_u16(v).ok_or(format!("SignatureAlgorithm Unknown-{}", v))?);
        }
        Ok(res)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = vec![0, 0];
        for hash in &self.hash {
            res.extend(hash.as_bytes());
        }
        let len = (res.len() - 2) as u16;
        res[0..2].copy_from_slice(len.to_be_bytes().as_ref());
        res
    }
}

