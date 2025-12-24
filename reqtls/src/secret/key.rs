use p256::elliptic_curve::sec1::ToEncodedPoint;
use crate::error::RlsResult;
use super::super::message::key_exchange::NamedCurve;

#[allow(non_camel_case_types)]
pub enum PriKey {
    x25519(x25519_dalek::EphemeralSecret),
    Secp256r1(p256::ecdh::EphemeralSecret),
}

impl PriKey {
    pub fn new(name_cure: &NamedCurve) -> RlsResult<PriKey> {
        match name_cure {
            NamedCurve::x25519 => {
                let mut rng = rand::rngs::ThreadRng::default();
                let keypair = x25519_dalek::EphemeralSecret::random_from_rng(&mut rng);
                Ok(PriKey::x25519(keypair))
            }
            NamedCurve::Secp256r1 => {
                let mut rng = rand::rngs::ThreadRng::default();
                let keypair = p256::ecdh::EphemeralSecret::try_from_rng(&mut rng)?;
                Ok(PriKey::Secp256r1(keypair))
            }
        }
    }
    pub fn diffie_hellman(self, pub_key: impl AsRef<[u8]>) -> RlsResult<Vec<u8>> {
        match self {
            PriKey::x25519(v) => {
                let pub_key: [u8; 32] = pub_key.as_ref().try_into()?;
                let pub_key = x25519_dalek::PublicKey::from(pub_key);
                let share_secret = v.diffie_hellman(&pub_key);
                Ok(share_secret.to_bytes().to_vec())
            }
            PriKey::Secp256r1(v) => {
                let pub_key = p256::PublicKey::from_sec1_bytes(pub_key.as_ref())?;
                let share_secret = v.diffie_hellman(&pub_key);
                Ok(share_secret.raw_secret_bytes().to_vec())
            }
        }
    }

    pub fn pub_key(&self) -> Vec<u8> {
        match self {
            PriKey::x25519(v) => {
                let pub_key = x25519_dalek::PublicKey::from(v);
                pub_key.to_bytes().to_vec()
            }
            PriKey::Secp256r1(v) => {
                let pub_key = v.public_key().to_encoded_point(false);
                pub_key.as_bytes().to_vec()
            }
        }
    }
}

