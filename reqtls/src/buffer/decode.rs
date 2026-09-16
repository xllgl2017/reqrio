use crate::error::RlsResult;
#[cfg(feature = "quic")]
use crate::message::QUICPacket;
use crate::{Aead, BufferError, CipherSuite, Version};
use crate::boring::Iv;

#[repr(C)]
pub struct TlsDecodeBuffer<'a> {
    suite: &'static CipherSuite,
    quic: bool,
    head: &'a [u8],
    origin: &'a [u8],
    decoded: &'a mut [u8],
}

impl<'a> TlsDecodeBuffer<'a> {
    pub fn from_buffer(origin: &'a [u8], decoded: &'a mut [u8], suite: &'static CipherSuite) -> RlsResult<Self> {
        if decoded.len() < origin.len() - 5 - suite.trans_iv_len {
            return Err(BufferError::CapacityTooSmall {
                current: decoded.len(),
                file: file!(),
                needed: origin.len() - 5 - suite.trans_iv_len,
                line: line!(),
            }.into());
        }
        let (head, origin) = origin.split_at(5);
        Ok(TlsDecodeBuffer {
            suite,
            quic: false,
            head,
            origin,
            decoded,
        })
    }

    #[cfg(feature = "quic")]
    pub fn from_quic(packet: &'a QUICPacket, decoded: &'a mut [u8]) -> Self {
        TlsDecodeBuffer {
            suite: &CipherSuite::TLS_AES_128_GCM_SHA256,
            quic: true,
            head: packet.hdr_raw(),
            origin: packet.payload.as_ref(),
            decoded,
        }
    }

    pub fn aad(&self, seq: u64) -> RlsResult<Vec<u8>> {
        if self.quic { return Ok(self.head.to_vec()); }
        match *self.suite.version {
            Version::TLS_1_3 => Ok(self.tls13_aad()),
            Version::TLS_1_2 | Version::TLCP => Ok(self.tls12_aad(seq)),
            _ => Err("Unsupported version".into()),
        }
    }

    ///tls1.2 aad: seq||head[0..3]||pd_len(not tag)
    fn tls12_aad(&self, seq: u64) -> Vec<u8> {
        let mut res = vec![0; 13];
        res[0..8].copy_from_slice(seq.to_be_bytes().as_ref());
        res[8..11].copy_from_slice(&self.head[..3]);
        let payload_len = self.origin.len() as u16 - self.suite.trans_iv_len as u16 - 16;
        res[11..13].copy_from_slice(&payload_len.to_be_bytes());
        res
    }

    ///tls1.3 aad: head[0..3]||pd_len(tag)
    fn tls13_aad(&self) -> Vec<u8> {
        let mut res = vec![0; 5];
        res[0..3].copy_from_slice(&self.head[..3]);
        let payload_len = self.origin.len() as u16;
        res[3..5].copy_from_slice(&payload_len.to_be_bytes());
        res
    }

    pub fn encrypted_payload(&self) -> &[u8] {
        &self.origin[self.suite.trans_iv_len..]

        // let len = self.origin.len() - self.suite.trans_iv_len;
        // unsafe { slice::from_raw_parts(self.origin.add(self.suite.trans_iv_len), len) }
    }

    pub fn explicit_iv(&self) -> &[u8] {
        &self.origin[..self.suite.trans_iv_len]
        // unsafe { slice::from_raw_parts(self.origin, self.suite.trans_iv_len) }
    }

    pub fn decrypted_buffer(&mut self) -> &mut [u8] {
        self.decoded
        // unsafe { slice::from_raw_parts_mut(self.decoded, self.origin_len - self.suite.trans_iv_len) }
    }

    pub fn nonce(&self, iv: &Iv, seq: u64) -> Vec<u8> {
        match *self.suite.aead() {
            Aead::AES_128_GCM | Aead::AES_256_GCM => match *self.suite.version {
                Version::TLS_1_3 => iv.as_array(seq, None).into_owned(),
                _ => iv.decrypting_iv(Some(self.explicit_iv())).into_owned()
            },
            Aead::ChaCha20_POLY1305 => iv.as_array(seq, None).into_owned(),
            Aead::AES_128_CBC_SHA |
            Aead::AES_128_CBC_SHA256 |
            Aead::AES_256_CBC_SHA |
            Aead::AES_256_CBC_SHA256 |
            Aead::AES_256_CBC_SHA384 |
            Aead::SM4_CBC_SM3 => iv.decrypting_iv(Some(self.explicit_iv())).into_owned(),
            _ => panic!("gen iv failed"),
        }
    }
}

