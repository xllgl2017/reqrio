use super::cipher::suite::Hasher;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Sha256, Sha384};
use crate::error::RlsResult;

enum PrfKind {
    Sha256,
    Sha384,
}

impl PrfKind {
    fn hmac_sha(&self, secret: &[u8], data: &[&[u8]]) -> RlsResult<Vec<u8>> {
        match self {
            PrfKind::Sha256 => {
                let mut a_i: Hmac<Sha256> = Hmac::new_from_slice(secret)?;
                for datum in data {
                    a_i.update(datum);
                }
                Ok(a_i.finalize().as_bytes().to_vec())
            }
            PrfKind::Sha384 => {
                let mut a_i: Hmac<Sha384> = Hmac::new_from_slice(secret)?;
                for datum in data {
                    a_i.update(datum);
                }
                Ok(a_i.finalize().as_bytes().to_vec())
            }
        }
    }

    fn hash_size(&self) -> usize {
        match self {
            PrfKind::Sha256 => 32,
            PrfKind::Sha384 => 48,
        }
    }
}

pub struct Prf(PrfKind);


impl Prf {
    pub fn from_hasher(hasher: &Hasher) -> Prf {
        match hasher {
            Hasher::None => Prf(PrfKind::Sha256),
            Hasher::Sha256(_) => Prf(PrfKind::Sha256),
            Hasher::Sha384(_) => Prf(PrfKind::Sha384),
        }
    }

    pub fn prf(&mut self, secret: &[u8], label: &str, seed: &[u8], out: &mut [u8]) -> RlsResult<()> {
        // A(0) = HMAC_hash(secret, label + seed)
        let mut a_i = self.0.hmac_sha(secret, &[label.as_bytes(), seed])?;
        let chunk_size = self.0.hash_size();
        for chunk in out.chunks_mut(chunk_size) {
            // P_hash[i] = HMAC_hash(secret, A(i) + label + seed)
            let p_hash = self.0.hmac_sha(secret, &[&a_i, label.as_bytes(), seed])?;
            chunk.copy_from_slice(&p_hash[..chunk.len()]);
            // A(i) = HMAC_hash(secret, A(i - 1))
            a_i = self.0.hmac_sha(secret, &[&a_i])?;
        }
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use sha2::Sha384;
    use crate::tls::cipher::suite::Hasher;
    use crate::tls::prf::Prf;

    #[test]
    fn test_prf() {
        let share_secret = [169, 119, 121, 220, 226, 211, 115, 229, 118, 182, 165, 43, 9, 136, 95, 237, 216, 241, 71, 247, 72, 223, 183, 53, 243, 149, 13, 126, 86, 226, 73, 95];
        let session_hash = [47, 194, 65, 138, 4, 178, 140, 144, 105, 216, 222, 186, 55, 208, 73, 132, 233, 163, 32, 184, 75, 137, 96, 106, 244, 67, 10, 4, 37, 134, 240, 9, 92, 7, 59, 8, 159, 230, 44, 28, 212, 227, 128, 20, 130, 244, 73, 60];
        let mut out = [0; 48];
        let mut prf = Prf::from_hasher(&Hasher::Sha384(Sha384::default()));
        prf.prf(&share_secret, "extended master secret", &session_hash, &mut out).unwrap();
        println!("{:?}", out);
    }
}