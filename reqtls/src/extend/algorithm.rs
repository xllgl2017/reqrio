use crate::boring::SignatureAlgorithm;
use crate::error::RlsResult;
use crate::{rand, BufferError, Reader, WriteExt};


#[derive(Debug, Clone)]
pub struct SignatureAlgorithms {
    hash: Vec<SignatureAlgorithm>,
}

impl SignatureAlgorithms {
    pub fn new(sig_alg: Vec<SignatureAlgorithm>) -> SignatureAlgorithms {
        SignatureAlgorithms {
            hash: sig_alg,
        }
    }

    pub fn len(&self) -> usize {
        self.hash.len() * 2 + 2
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) -> Result<(), BufferError> {
        writer.write_u16(self.len() as u16 - 2)?;
        for hash in self.hash {
            writer.write_u16(hash.into_inner())?;
        }
        Ok(())
    }

    pub fn from_reader(mut reader: Reader<'_>) -> RlsResult<SignatureAlgorithms> {
        let len = reader.read_u16()?;
        let mut hashes = Vec::with_capacity(reader.unread_len());
        for _ in (0..len).step_by(2) {
            hashes.push(SignatureAlgorithm::new(reader.read_u16()?))
        }
        Ok(SignatureAlgorithms {
            hash: hashes,
        })
    }

    pub fn hashes(&self) -> &Vec<SignatureAlgorithm> {
        &self.hash
    }

    pub fn set_hashes(&mut self, hashes: Vec<SignatureAlgorithm>) {
        self.hash = hashes;
    }

    pub fn push_hash(&mut self, hash: SignatureAlgorithm) {
        self.hash.push(hash);
    }

    pub fn clear(&mut self) {
        self.hash.clear();
    }

    pub fn random() -> SignatureAlgorithms {
        let mut res = SignatureAlgorithms::new(vec![]);
        let all_sign = SignatureAlgorithm::ALL;
        res.hash = vec![
            SignatureAlgorithm::RSA_PSS_RSAE_SHA256.into(),
            SignatureAlgorithm::ECDSA_SECP256R1_SHA256.into(),
            SignatureAlgorithm::RSA_PKCS1_SHA256.into(),
        ];
        while res.hash.len() < 10 {
            let index = rand::random::<usize>() % all_sign.len();
            if res.hash.iter().any(|x| x.as_u16() == all_sign[index]) { continue; }
            res.hash.push(SignatureAlgorithm::new(all_sign[index]));
        }
        res
    }
}

