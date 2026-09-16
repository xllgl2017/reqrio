use crate::{CipherSuite, RecordType, Version};
use std::ops::Range;
#[cfg(feature = "quic")]
use crate::message::QUICPacket;

pub struct PayloadEncodeBuffer<'a> {
    encoded: &'a mut [u8],
    plain_offset: Range<usize>,
    encode_offset: Range<usize>,
}

impl<'a> PayloadEncodeBuffer<'a> {
    pub fn new_tls(suite: &'static CipherSuite, ct: &RecordType, buffer: &'a mut [u8], origin: &'a [u8]) -> PayloadEncodeBuffer<'a> {
        let mut plain_offset = suite.trans_iv_len..suite.trans_iv_len + origin.len();
        buffer[plain_offset.clone()].copy_from_slice(origin);
        if suite.version == &Version::TLS_1_3 {
            buffer[plain_offset.end] = ct.as_u8();
            plain_offset.end += 1
        }
        PayloadEncodeBuffer {
            encoded: buffer,
            encode_offset: suite.trans_iv_len..suite.trans_iv_len + plain_offset.len() + suite.tag_len(plain_offset.len()),
            plain_offset,

        }
    }

    #[cfg(feature = "quic")]
    pub fn new_quic(buffer: &'a mut [u8], pd_len: usize) -> PayloadEncodeBuffer<'a> {
        PayloadEncodeBuffer {
            encoded: buffer,
            plain_offset: 0..pd_len - 16,
            encode_offset: 0..pd_len,
        }
    }

    fn add_explicit_iv(&mut self, suite: &'static CipherSuite, iv: &[u8]) {
        match suite.trans_iv_len {
            8 => self.encoded[..8].copy_from_slice(&iv[4..]),
            16 => self.encoded[..16].copy_from_slice(&iv[..16]),
            0 => {}
            _ => panic!("unsupported suite specification"),
        }
    }

    pub fn origin_payload(&self) -> &[u8] {
        &self.encoded[self.plain_offset.clone()]
    }

    pub fn encoded_payload(&mut self) -> &mut [u8] {
        &mut self.encoded[self.encode_offset.clone()]
    }
}

pub struct CipherEncodeBuffer<'a> {
    suite: &'static CipherSuite,
    head: &'a mut [u8],
    record_len: usize,
    payload: PayloadEncodeBuffer<'a>,
    quic: bool,
}


impl<'a> CipherEncodeBuffer<'a> {
    pub(crate) fn new_tls(rt: RecordType, buffer: &'a mut [u8], origin: &'a [u8], suite: &'static CipherSuite) -> CipherEncodeBuffer<'a> {
        let (head, payload) = buffer.split_at_mut(5);
        match *suite.version {
            Version::TLS_1_3 => {
                head[0] = 23;
                head[1] = 3;
                head[2] = 3;
            }
            Version::TLS_1_2 => {
                head[0] = rt.as_u8();
                head[1] = 3;
                head[2] = 3;
            }
            Version::TLCP => {
                head[0] = rt.as_u8();
                head[1] = 1;
                head[2] = 1;
            }
            _ => unreachable!(),
        };
        CipherEncodeBuffer {
            suite,
            head,
            record_len: 0,
            payload: PayloadEncodeBuffer::new_tls(suite, &rt, payload, origin),
            quic: false,
        }
    }

    #[cfg(feature = "quic")]
    pub(crate) fn new_quic(buffer: &'a mut [u8], packet: &QUICPacket, suite: &'static CipherSuite) -> CipherEncodeBuffer<'a> {
        let (head, payload) = buffer.split_at_mut(packet.hdr_len());
        CipherEncodeBuffer {
            suite,
            head,
            record_len: 0,
            payload: PayloadEncodeBuffer::new_quic(payload, packet.pd_len() - packet.flag.num_len()),
            quic: true,
        }
    }

    pub fn payload(&mut self) -> &mut PayloadEncodeBuffer<'a> {
        &mut self.payload
    }

    pub fn add_explicit_iv(&mut self, iv: &[u8]) {
        self.payload.add_explicit_iv(self.suite, iv)
    }

    pub fn set_encrypted_len(&mut self, len: usize) {
        if self.quic { return; }
        let len = self.suite.trans_iv_len + len;
        self.record_len = len + 5;
        self.head[3..5].copy_from_slice(&(len as u16).to_be_bytes());
    }

    pub fn aad(&self, seq: u64) -> Vec<u8> {
        if self.quic { return self.head.to_vec(); }
        match *self.suite.version {
            Version::TLS_1_3 => self.tls13_aad(),
            _ => self.tls12_aad(seq)
        }
    }

    fn tls13_aad(&self) -> Vec<u8> {
        let mut res = vec![0; 5];
        res[0..3].copy_from_slice(&self.head[0..3]);
        let len = self.payload.encode_offset.len() as u16;
        res[3..5].copy_from_slice(&len.to_be_bytes());
        res
    }

    fn tls12_aad(&self, seq: u64) -> Vec<u8> {
        let mut res = vec![0; 13];
        let ptr = res.as_mut_ptr() as *mut u64;
        unsafe { ptr.write_unaligned(seq); }
        res[0..8].copy_from_slice(&seq.to_be_bytes());
        res[8..11].copy_from_slice(&self.head[..3]);
        res[11..13].copy_from_slice(&(self.payload.plain_offset.len() as u16).to_be_bytes());
        res
    }

    pub fn record_len(&self) -> usize { self.record_len }
}


#[cfg(test)]
mod tests {
    use crate::buffer::CipherEncodeBuffer;
    use crate::{CipherSuite, RecordType};

    #[test]
    fn test_encode_buffer() {
        let mut buffer = [0; 1024];
        let payload = (1..100).collect::<Vec<u8>>();
        let record_type = RecordType::ApplicationData;

        let suite = &CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        let mut encode = CipherEncodeBuffer::new_tls(record_type, &mut buffer, &payload, suite);
        encode.add_explicit_iv(&[14; 12]);
        assert_eq!(encode.head, [record_type.as_u8(), 3, 3, 0, 0]);
        assert_eq!(encode.payload.origin_payload(), payload);
        let mut pd = Vec::with_capacity(suite.trans_iv_len + payload.len() + 16);
        pd.extend_from_slice(&payload);
        pd.extend([0; 16]);
        assert_eq!(encode.payload.encoded_payload(), pd);

        let suite = &CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256;
        let mut buffer = [0; 1024];
        let mut encode = CipherEncodeBuffer::new_tls(record_type, &mut buffer, &payload, suite);
        assert_eq!(encode.head, [record_type.as_u8(), 3, 3, 0, 0]);
        assert_eq!(encode.payload.origin_payload(), payload);
        assert_eq!(encode.payload.encoded_payload(), pd);

        let suite = &CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA;
        let mut buffer = [0; 1024];
        let mut encode = CipherEncodeBuffer::new_tls(record_type, &mut buffer, &payload, suite);
        encode.add_explicit_iv(&[77; 16]);
        assert_eq!(encode.head, [record_type.as_u8(), 3, 3, 0, 0]);
        assert_eq!(encode.payload.origin_payload(), payload);
        assert_eq!(&encode.payload.encoded_payload()[..pd.len()], pd);
    }

    #[test]
    fn test_tls13_buffer() {
        let mut buffer = [0; 1024];
        let payload = (1..100).collect::<Vec<u8>>();
        let record_type = RecordType::HandShake;

        let suite = &CipherSuite::TLS_AES_128_GCM_SHA256;
        let mut encode = CipherEncodeBuffer::new_tls(record_type, &mut buffer, &payload, suite);
        encode.add_explicit_iv(&[14; 12]);
        assert_eq!(encode.head, [23, 3, 3, 0, 0]);
        let mut pd = Vec::with_capacity(suite.trans_iv_len + payload.len() + 16);
        pd.extend_from_slice(&payload);
        pd.push(record_type.as_u8());
        assert_eq!(encode.payload.origin_payload(), pd);
        pd.extend([0; 16]);
        assert_eq!(encode.payload.encoded_payload(), pd);


        let suite = &CipherSuite::TLS_CHACHA20_POLY1305_SHA256;
        let mut buffer = [0; 1024];
        let mut encode = CipherEncodeBuffer::new_tls(record_type, &mut buffer, &payload, suite);
        assert_eq!(encode.head, [23, 3, 3, 0, 0]);
        pd = pd[..pd.len() - 16].to_vec();
        assert_eq!(encode.payload.origin_payload(), pd);
        pd.extend([0; 16]);
        assert_eq!(encode.payload.encoded_payload(), pd);
    }
}