use super::cipher::suite::Hasher;
use crate::error::RlsResult;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Sha256, Sha384};

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
    pub fn default() -> Prf {
        Prf(PrfKind::Sha256)
    }

    pub fn from_hasher(hasher: &Hasher) -> Prf {
        match hasher {
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
    use crate::cipher::suite::Hasher;
    use crate::prf::Prf;
    use sha2::Sha256;

    #[test]
    fn test_prf() {
        println!("{:?}", 1u64.to_be_bytes());
        let share_secret = [189, 131, 30, 96, 115, 185, 113, 187, 225, 41, 170, 137, 172, 238, 155, 134, 67, 209, 193, 147, 14, 95, 123, 199, 218, 123, 24, 132, 246, 107, 134, 13];
        let session_hash = [203, 88, 253, 224, 105, 246, 231, 82, 172, 215, 174, 32, 168, 62, 147, 60, 219, 189, 233, 197, 149, 10, 0, 47, 84, 235, 172, 168, 140, 212, 108, 127];
        let mut master_secret = [0; 48];
        let mut prf = Prf::from_hasher(&Hasher::Sha256(Sha256::default()));
        prf.prf(&share_secret, "extended master secret", &session_hash, &mut master_secret).unwrap();
        println!("{:?}", master_secret);
        let client_random = [168, 102, 144, 116, 168, 105, 73, 53, 141, 158, 97, 68, 2, 18, 204, 19, 248, 142, 178, 215, 223, 48, 197, 110, 19, 11, 72, 208, 168, 74, 129, 61];
        let server_random = [164, 16, 246, 211, 195, 19, 199, 151, 186, 4, 30, 216, 157, 252, 162, 77, 8, 173, 21, 113, 194, 5, 185, 227, 68, 79, 87, 78, 71, 82, 68, 1];
        let seed = [server_random, client_random].concat();
        let mut key_block = [0; 32 + 32 + 12 + 12];
        prf.prf(&master_secret, "key expansion", &seed, key_block.as_mut_slice()).unwrap();
        println!("{:?}", key_block);
        let (wk, remain) = key_block.split_at(32);
        let (rk, remain) = remain.split_at(32);
        let (wi, remain) = remain.split_at(12);
        let (ri, remain) = remain.split_at(12);
        let (explicit, _) = remain.split_at(0);
        println!("{:?}", wk);
        println!("{:?}", rk);
        println!("{:?}", wi);
        println!("{:?}", ri);
        println!("{:?}", explicit);
    }
}