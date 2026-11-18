mod suite;

use crate::boring::{BoringResExt, HashError};
use crate::error::RlsResult;
use crate::key::EchKey;
use crate::Hkdf;
use std::os::raw::c_int;
pub use suite::HpkeSuite;

unsafe extern "C" {
    fn X25519_keypair(pri_key: *mut u8, pub_key: *mut u8);
    fn X25519(shared_key: *mut u8, pri_key: *const u8, peer_pub: *const u8) -> c_int;
}




#[repr(u8)]
#[derive(Copy, Clone, PartialEq)]
pub enum HpkeMode {
    Base = 0,
    Psk = 1,
    Auth = 2,
    AuthPsk = 3,
}

pub struct Hpke {
    mode: HpkeMode,
    suite: &'static HpkeSuite,
}
impl Hpke {
    pub const fn new(mode: HpkeMode, suite: &'static HpkeSuite) -> Hpke {
        Hpke { mode, suite }
    }

    fn extract_and_expand(&self, pk_em: &[u8], pk_rm: &[u8], pk_sm: &[u8], secret: &mut [u8], secret2: &[u8]) -> Result<(), HashError> {
        let mut hmac = Hkdf::new_extracting(&[], self.suite.hash)?;
        hmac.update(b"HPKE-v1")?;
        hmac.update(b"KEM")?;
        hmac.update(self.suite.kem_id.to_be_bytes())?;
        hmac.update(b"eae_prk")?;
        hmac.update(secret.as_ref())?;
        hmac.update(secret2)?;
        let mut hkdf = Hkdf::from_prk(hmac.finalize()?, self.suite.hash);
        hkdf.extend_multi(&[
            &(secret.len() as u16).to_be_bytes(),
            b"HPKE-v1",
            b"KEM",
            &self.suite.kem_id.to_be_bytes(),
            b"shared_secret",
            pk_em,
            pk_rm,
            pk_sm
        ], secret.as_mut())
    }

    /// [rfc9180](https://datatracker.ietf.org/doc/html/rfc9180#name-dh-based-kem-dhkem): Encap
    pub fn encap(&self, pk_rm: &[u8]) -> RlsResult<([u8; 32], [u8; 32])> {
        let mut pk_em = [0; 32];
        let mut sk_em = [0; 32];
        unsafe { X25519_keypair(sk_em.as_mut_ptr(), pk_em.as_mut_ptr()) }
        let mut secret = [0; 32];
        unsafe { X25519(secret.as_mut_ptr(), sk_em.as_ptr(), pk_rm.as_ptr()) }
            .ok("derive share key error")?;
        self.extract_and_expand(&pk_em, pk_rm, &[], &mut secret, &[])?;
        Ok((secret, pk_em))
    }

    /// [rfc9180](https://datatracker.ietf.org/doc/html/rfc9180#name-dh-based-kem-dhkem): AuthEncap
    pub fn auth_encap(&self, pk_rm: &[u8], sk_sm: &[u8], pk_sm: &[u8]) -> RlsResult<([u8; 32], [u8; 32])> {
        let mut pk_em = [0; 32];
        let mut sk_em = [0; 32];
        unsafe { X25519_keypair(sk_em.as_mut_ptr(), pk_em.as_mut_ptr()) }

        let mut dh1 = [0; 32];
        let mut dh2 = [0; 32];
        unsafe { X25519(dh1.as_mut_ptr(), sk_em.as_ptr(), pk_rm.as_ptr()) }
            .ok("derive share key error")?;
        unsafe { X25519(dh2.as_mut_ptr(), sk_sm.as_ptr(), pk_rm.as_ptr()) }
            .ok("derive share key error")?;
        self.extract_and_expand(&pk_em, pk_rm, pk_sm, &mut dh1, &dh2)?;
        Ok((dh1, pk_em))
    }

    /// [rfc9180](https://datatracker.ietf.org/doc/html/rfc9180#name-dh-based-kem-dhkem): Decap
    pub fn decap(&self, pk_em: &[u8], sk_rm: &[u8], pk_rm: &[u8]) -> RlsResult<[u8; 32]> {
        let mut secret = [0; 32];
        unsafe { X25519(secret.as_mut_ptr(), sk_rm.as_ptr(), pk_em.as_ptr()) }
            .ok("decap share key error")?;
        self.extract_and_expand(pk_em, pk_rm, &[], &mut secret, &[])?;
        Ok(secret)
    }

    /// [rfc9180](https://datatracker.ietf.org/doc/html/rfc9180#name-dh-based-kem-dhkem): AuthDecap
    pub fn auth_decap(&self, pk_em: &[u8], sk_rm: &[u8], pk_rm: &[u8], pk_sm: &[u8]) -> RlsResult<[u8; 32]> {
        let mut dh1 = [0; 32];
        let mut dh2 = [0; 32];
        unsafe { X25519(dh1.as_mut_ptr(), sk_rm.as_ptr(), pk_em.as_ptr()) }
            .ok("derive share key error")?;
        unsafe { X25519(dh2.as_mut_ptr(), sk_rm.as_ptr(), pk_sm.as_ptr()) }
            .ok("derive share key error")?;
        self.extract_and_expand(pk_em, pk_rm, pk_sm, &mut dh1, &dh2)?;
        Ok(dh1)
    }

    const DEFAULT_PSK: &[u8] = &[];
    const DEFAULT_PSK_ID: &[u8] = &[];

    /// [rfc9180](https://datatracker.ietf.org/doc/html/rfc9180#name-dh-based-kem-dhkem): VerifyPSKInputs
    fn verify_psk_input(&self, psk: &[u8], psk_id: &[u8]) -> RlsResult<()> {
        let got_psk = psk != Self::DEFAULT_PSK;
        let got_psk_id = psk_id != Self::DEFAULT_PSK_ID;
        if got_psk != got_psk_id { return Err("Inconsistent PSK inputs".into()); }
        if got_psk && matches!(self.mode, HpkeMode::Base|HpkeMode::Auth) {
            return Err("PSK input provided when not needed".into());
        }
        if !got_psk && matches!(self.mode, HpkeMode::Psk|HpkeMode::AuthPsk) {
            return Err("Missing required PSK input".into());
        }
        Ok(())
    }


    fn build_prk(&self, salt: &[u8], label: &str, info: &[u8]) -> Result<Vec<u8>, HashError> {
        let mut hmac = Hkdf::new_extracting(salt, self.suite.hash)?;
        hmac.update(b"HPKE-v1")?;
        hmac.update(b"HPKE")?;
        hmac.update(self.suite.kem_id.to_be_bytes())?;
        hmac.update(self.suite.kdf_id.to_be_bytes())?;
        hmac.update(self.suite.aead_id.to_be_bytes())?;
        hmac.update(label.as_bytes())?;
        hmac.update(info)?;
        hmac.finalize()
    }

    fn derive_expand(&self, hkdf: &mut Hkdf<'_>, label: &str, out: &mut [u8], psk_id_hash: &[u8], info_psk_hash: &[u8]) -> Result<(), HashError> {
        hkdf.extend_multi(&[
            &(out.len() as u16).to_be_bytes(),
            b"HPKE-v1",
            b"HPKE",
            &self.suite.kem_id.to_be_bytes(),
            &self.suite.kdf_id.to_be_bytes(),
            &self.suite.aead_id.to_be_bytes(),
            label.as_bytes(),
            &[self.mode as u8],
            psk_id_hash,
            info_psk_hash
        ], out)
    }

    /// [rfc9180](https://datatracker.ietf.org/doc/html/rfc9180#name-dh-based-kem-dhkem): KeySchedule
    fn key_schedule(&self, shared_secret: &[u8], info: &[u8], psk: &[u8], psk_id: &[u8]) -> RlsResult<EchKey> {
        self.verify_psk_input(psk_id, psk_id)?;
        let psk_id_hash = self.build_prk(&[], "psk_id_hash", psk_id)?;
        let info_psk_hash = self.build_prk(&[], "info_hash", info)?;
        let prk = self.build_prk(shared_secret, "secret", psk)?;
        let mut secret_hkdf = Hkdf::from_prk(prk, self.suite.hash);
        let mut key = EchKey::new(self.suite);
        self.derive_expand(&mut secret_hkdf, "key", key.key_mut(), &psk_id_hash, &info_psk_hash)?;
        self.derive_expand(&mut secret_hkdf, "base_nonce", key.iv_mut(), &psk_id_hash, &info_psk_hash)?;
        self.derive_expand(&mut secret_hkdf, "exp", key.exp_mut(), &psk_id_hash, &info_psk_hash)?;
        Ok(key)
    }
}


#[cfg(test)]
mod test {
    use super::{Hpke, HpkeMode, HpkeSuite, X25519};
    use crate::boring::BoringResExt;

    pub fn encap(hpke: &Hpke, pk_em: &[u8], sk_em: &[u8], pk_rm: &[u8]) -> [u8; 32] {
        let mut secret = [0; 32];
        unsafe { X25519(secret.as_mut_ptr(), sk_em.as_ptr(), pk_rm.as_ptr()) }
            .ok("derive share key error").unwrap();
        hpke.extract_and_expand(pk_em, pk_rm, &[], &mut secret, &[]).unwrap();
        secret
    }

    fn auth_encap(hpke: &Hpke, pk_em: &[u8], sk_em: &[u8], pk_rm: &[u8], sk_sm: &[u8], pk_sm: &[u8]) -> [u8; 32] {
        let mut dh1 = [0; 32];
        let mut dh2 = [0; 32];
        unsafe { X25519(dh1.as_mut_ptr(), sk_em.as_ptr(), pk_rm.as_ptr()) }
            .ok("derive share key error").unwrap();
        unsafe { X25519(dh2.as_mut_ptr(), sk_sm.as_ptr(), pk_rm.as_ptr()) }
            .ok("derive share key error").unwrap();
        hpke.extract_and_expand(pk_em, pk_rm, pk_sm, &mut dh1, &dh2).unwrap();
        dh1
    }

    #[test]
    fn test_x25519_kem() {
        let pk_em = hex::decode("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431").unwrap();
        let sk_em = hex::decode("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736").unwrap();
        let pk_rm = hex::decode("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d").unwrap();
        let sk_rm = hex::decode("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8").unwrap();

        let hpke = Hpke::new(HpkeMode::Base, &HpkeSuite::X25519_AES_128_GCM_SHA256);
        let encap = encap(&hpke, &pk_em, &sk_em, &pk_rm);
        let decap = hpke.decap(&pk_em, &sk_rm, &pk_rm).unwrap();
        assert_eq!(encap, decap);
        assert_eq!(encap.as_slice(), [254, 14, 24, 201, 240, 36, 206, 67, 121, 154, 227, 147, 199, 232, 254, 143, 206, 157, 33, 136, 117, 232, 34, 123, 1, 135, 192, 78, 125, 46, 161, 252]);
        let info = hex::decode("4f6465206f6e2061204772656369616e2055726e").unwrap();
        let key = hpke.key_schedule(&encap, &info, Hpke::DEFAULT_PSK, Hpke::DEFAULT_PSK_ID).unwrap();
        assert_eq!(key.key(), hex::decode("4531685d41d65f03dc48f6b8302c05b0").unwrap());
        assert_eq!(key.iv(), hex::decode("56d890e5accaaf011cff4b7d").unwrap());
        assert_eq!(key.exp(), hex::decode("45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8").unwrap());
    }


    #[test]
    fn test_x25519_kem_psk() {
        let pk_em = hex::decode("0ad0950d9fb9588e59690b74f1237ecdf1d775cd60be2eca57af5a4b0471c91b").unwrap();
        let sk_em = hex::decode("463426a9ffb42bb17dbe6044b9abd1d4e4d95f9041cef0e99d7824eef2b6f588").unwrap();
        let pk_rm = hex::decode("9fed7e8c17387560e92cc6462a68049657246a09bfa8ade7aefe589672016366").unwrap();
        let sk_rm = hex::decode("c5eb01eb457fe6c6f57577c5413b931550a162c71a03ac8d196babbd4e5ce0fd").unwrap();
        let psk = hex::decode("0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82").unwrap();
        let psk_id = hex::decode("456e6e796e20447572696e206172616e204d6f726961").unwrap();
        let hpke = Hpke::new(HpkeMode::Psk, &HpkeSuite::X25519_AES_128_GCM_SHA256);
        let encap = encap(&hpke, &pk_em, &sk_em, &pk_rm);
        let decap = hpke.decap(&pk_em, &sk_rm, &pk_rm).unwrap();
        assert_eq!(encap, decap);
        assert_eq!(encap.as_slice(), hex::decode("727699f009ffe3c076315019c69648366b69171439bd7dd0807743bde76986cd").unwrap());
        let info = hex::decode("4f6465206f6e2061204772656369616e2055726e").unwrap();
        let key = hpke.key_schedule(&encap, &info, &psk, &psk_id).unwrap();
        assert_eq!(key.key(), hex::decode("15026dba546e3ae05836fc7de5a7bb26").unwrap());
        assert_eq!(key.iv(), hex::decode("9518635eba129d5ce0914555").unwrap());
        assert_eq!(key.exp(), hex::decode("3d76025dbbedc49448ec3f9080a1abab6b06e91c0b11ad23c912f043a0ee7655").unwrap());
    }

    #[test]
    fn test_x25519_kem_auth() {
        let pk_em = hex::decode("23fb952571a14a25e3d678140cd0e5eb47a0961bb18afcf85896e5453c312e76").unwrap();
        let sk_em = hex::decode("ff4442ef24fbc3c1ff86375b0be1e77e88a0de1e79b30896d73411c5ff4c3518").unwrap();
        let pk_rm = hex::decode("1632d5c2f71c2b38d0a8fcc359355200caa8b1ffdf28618080466c909cb69b2e").unwrap();
        let sk_rm = hex::decode("fdea67cf831f1ca98d8e27b1f6abeb5b7745e9d35348b80fa407ff6958f9137e").unwrap();
        let pk_sm = hex::decode("8b0c70873dc5aecb7f9ee4e62406a397b350e57012be45cf53b7105ae731790b").unwrap();
        let sk_sm = hex::decode("dc4a146313cce60a278a5323d321f051c5707e9c45ba21a3479fecdf76fc69dd").unwrap();
        let hpke = Hpke::new(HpkeMode::Auth, &HpkeSuite::X25519_AES_128_GCM_SHA256);
        let encap = auth_encap(&hpke, &pk_em, &sk_em, &pk_rm, &sk_sm, &pk_sm);
        let decap = hpke.auth_decap(&pk_em, &sk_rm, &pk_rm, &pk_sm).unwrap();
        assert_eq!(encap, decap);
        assert_eq!(encap.as_slice(), hex::decode("2d6db4cf719dc7293fcbf3fa64690708e44e2bebc81f84608677958c0d4448a7").unwrap());
        let info = hex::decode("4f6465206f6e2061204772656369616e2055726e").unwrap();
        let key = hpke.key_schedule(&encap, &info, Hpke::DEFAULT_PSK, Hpke::DEFAULT_PSK_ID).unwrap();
        assert_eq!(key.key(), hex::decode("b062cb2c4dd4bca0ad7c7a12bbc341e6").unwrap());
        assert_eq!(key.iv(), hex::decode("a1bc314c1942ade7051ffed0").unwrap());
        assert_eq!(key.exp(), hex::decode("ee1a093e6e1c393c162ea98fdf20560c75909653550540a2700511b65c88c6f1").unwrap());
    }

    #[test]
    fn test_x25519_kem_auth_psk() {
        let pk_em = hex::decode("820818d3c23993492cc5623ab437a48a0a7ca3e9639c140fe1e33811eb844b7c").unwrap();
        let sk_em = hex::decode("14de82a5897b613616a00c39b87429df35bc2b426bcfd73febcb45e903490768").unwrap();
        let pk_rm = hex::decode("1d11a3cd247ae48e901939659bd4d79b6b959e1f3e7d66663fbc9412dd4e0976").unwrap();
        let sk_rm = hex::decode("cb29a95649dc5656c2d054c1aa0d3df0493155e9d5da6d7e344ed8b6a64a9423").unwrap();
        let pk_sm = hex::decode("2bfb2eb18fcad1af0e4f99142a1c474ae74e21b9425fc5c589382c69b50cc57e").unwrap();
        let sk_sm = hex::decode("fc1c87d2f3832adb178b431fce2ac77c7ca2fd680f3406c77b5ecdf818b119f4").unwrap();
        let psk = hex::decode("0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82").unwrap();
        let psk_id = hex::decode("456e6e796e20447572696e206172616e204d6f726961").unwrap();

        let hpke = Hpke::new(HpkeMode::AuthPsk, &HpkeSuite::X25519_AES_128_GCM_SHA256);
        let encap = auth_encap(&hpke, &pk_em, &sk_em, &pk_rm, &sk_sm, &pk_sm);
        let decap = hpke.auth_decap(&pk_em, &sk_rm, &pk_rm, &pk_sm).unwrap();
        assert_eq!(encap, decap);
        assert_eq!(encap.as_slice(), hex::decode("f9d0e870aba28d04709b2680cb8185466c6a6ff1d6e9d1091d5bf5e10ce3a577").unwrap());
        let info = hex::decode("4f6465206f6e2061204772656369616e2055726e").unwrap();
        let key = hpke.key_schedule(&encap, &info, &psk, &psk_id).unwrap();
        assert_eq!(key.key(), hex::decode("1364ead92c47aa7becfa95203037b19a").unwrap());
        assert_eq!(key.iv(), hex::decode("99d8b5c54669807e9fc70df1").unwrap());
        assert_eq!(key.exp(), hex::decode("f048d55eacbf60f9c6154bd4021774d1075ebf963c6adc71fa846f183ab2dde6").unwrap());
    }

    #[test]
    fn test_x25519_chacha20_poly1305() {
        let pk_em = hex::decode("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a").unwrap();
        let sk_em = hex::decode("f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600").unwrap();
        let pk_rm = hex::decode("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a").unwrap();
        let sk_rm = hex::decode("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb").unwrap();

        let hpke = Hpke::new(HpkeMode::Base, &HpkeSuite::X25519_CHACHA20_POLY1305_SHA256);
        let encap = encap(&hpke, &pk_em, &sk_em, &pk_rm);
        let decap = hpke.decap(&pk_em, &sk_rm, &pk_rm).unwrap();
        assert_eq!(encap, decap);
        assert_eq!(encap.as_slice(), hex::decode("0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7").unwrap());
        let info = hex::decode("4f6465206f6e2061204772656369616e2055726e").unwrap();
        let key = hpke.key_schedule(&encap, &info, Hpke::DEFAULT_PSK, Hpke::DEFAULT_PSK_ID).unwrap();
        assert_eq!(key.key(), hex::decode("ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91").unwrap());
        assert_eq!(key.iv(), hex::decode("5c4d98150661b848853b547f").unwrap());
        assert_eq!(key.exp(), hex::decode("a3b010d4994890e2c6968a36f64470d3c824c8f5029942feb11e7a74b2921922").unwrap());
    }
}