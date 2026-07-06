use crate::boring;
use crate::boring::HashType;
use crate::error::RlsResult;

struct PrfBuf<'a> {
    bufs: Vec<&'a mut [u8]>,
    pos: usize,
    index: usize,
}

impl<'a> PrfBuf<'a> {
    pub fn write_slice(&mut self, bi: &[u8]) -> bool {
        if self.pos >= self.bufs.len() { return true; }
        let buf = &mut self.bufs[self.pos];
        if bi.len() >= buf.len() - self.index {
            let index = buf.len() - self.index;
            buf[self.index..].copy_from_slice(&bi[..index]);
            self.index = 0;
            self.pos += 1;
            self.write_slice(&bi[index..])
        } else {
            buf[self.index..self.index + bi.len()].copy_from_slice(bi);
            self.index += bi.len();
            false
        }
    }
}

pub struct Prf(HashType);


impl Prf {
    pub fn default() -> Prf {
        Prf(HashType::Sha256)
    }

    pub fn from_hasher(hash: HashType) -> Prf {
        Prf(hash)
    }

    pub fn hmac_sha(&self, secret: &[u8], data: &[&[u8]]) -> RlsResult<Vec<u8>> {
        let mut hmac = boring::Hmac::new(secret, self.0)?;
        for datum in data {
            hmac.update(datum)?;
        }
        Ok(hmac.finalize()?.to_vec())
    }

    pub fn prfs(&self, secret: &[u8], label: &str, seed: &[u8], bufs: Vec<&mut [u8]>) -> RlsResult<()> {
        let mut buf = PrfBuf { bufs, pos: 0, index: 0 };
        // A(0) = HMAC_hash(secret, label + seed)
        let mut a_i = self.hmac_sha(secret, &[label.as_bytes(), seed])?;
        loop {
            // P_hash[i] = HMAC_hash(secret, A(i) + label + seed)
            let p_hash = self.hmac_sha(secret, &[&a_i, label.as_bytes(), seed])?;
            let finish = buf.write_slice(p_hash.as_slice());
            if finish { break; }
            // A(i) = HMAC_hash(secret, A(i - 1))
            a_i = self.hmac_sha(secret, &[&a_i])?;
        }
        Ok(())
    }

    pub fn prf(&self, secret: &[u8], label: &str, seed: &[u8], bufs: &mut [u8]) -> RlsResult<()> {
        self.prfs(secret, label, seed, vec![bufs])
    }
}


#[cfg(test)]
mod tests {
    use crate::boring::HashType;
    use crate::prf::Prf;

    #[test]
    fn test_prf() {
        let share_secret = [189, 131, 30, 96, 115, 185, 113, 187, 225, 41, 170, 137, 172, 238, 155, 134, 67, 209, 193, 147, 14, 95, 123, 199, 218, 123, 24, 132, 246, 107, 134, 13];
        let session_hash = [203, 88, 253, 224, 105, 246, 231, 82, 172, 215, 174, 32, 168, 62, 147, 60, 219, 189, 233, 197, 149, 10, 0, 47, 84, 235, 172, 168, 140, 212, 108, 127];
        let mut master_secret = [0; 48];
        let prf = Prf::from_hasher(HashType::Sha256);
        prf.prf(&share_secret, "extended master secret", &session_hash, &mut master_secret).unwrap();
        assert_eq!(master_secret, [54, 29, 236, 142, 207, 233, 234, 120, 87, 164, 114, 115, 240, 89, 116, 235, 66, 75, 243, 36, 113, 58, 255, 221, 104, 179, 245, 252, 202, 46, 209, 186, 2, 15, 187, 115, 171, 182, 124, 136, 65, 74, 43, 255, 111, 246, 100, 128]);
        let client_random = [168, 102, 144, 116, 168, 105, 73, 53, 141, 158, 97, 68, 2, 18, 204, 19, 248, 142, 178, 215, 223, 48, 197, 110, 19, 11, 72, 208, 168, 74, 129, 61];
        let server_random = [164, 16, 246, 211, 195, 19, 199, 151, 186, 4, 30, 216, 157, 252, 162, 77, 8, 173, 21, 113, 194, 5, 185, 227, 68, 79, 87, 78, 71, 82, 68, 1];
        let seed = [server_random, client_random].concat();
        let mut wk = [0; 32];
        let mut rk = [0; 32];
        let mut wi = [0; 12];
        let mut ri = [0; 12];
        let mut explicit = [0; 0];
        prf.prfs(&master_secret, "key expansion", &seed, vec![
            &mut wk,
            &mut rk,
            &mut wi,
            &mut ri,
            &mut explicit
        ]).unwrap();
        assert_eq!(wk, [160, 232, 46, 123, 17, 199, 214, 127, 79, 55, 210, 3, 178, 54, 214, 91, 134, 248, 228, 182, 149, 151, 217, 154, 147, 117, 242, 110, 212, 99, 213, 13]);
        assert_eq!(rk, [164, 198, 66, 228, 237, 141, 213, 234, 16, 10, 31, 43, 251, 150, 0, 90, 179, 86, 160, 39, 123, 36, 130, 196, 143, 91, 102, 229, 31, 43, 19, 165]);
        assert_eq!(wi, [63, 246, 130, 48, 155, 103, 72, 13, 37, 238, 1, 94]);
        assert_eq!(ri, [233, 23, 102, 163, 242, 77, 144, 20, 53, 23, 212, 164]);
        assert_eq!(explicit, []);
    }
}