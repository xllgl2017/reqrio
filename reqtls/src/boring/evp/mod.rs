pub mod cipher;
mod aead;
mod error;
mod iv;

pub use aead::{AeadCtx, AeadDir};
pub use cipher::Cipher;
pub use error::EvpError;
pub use iv::Iv;

#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
pub enum CipherType {
    AES_128_CBC = 0,
    AES_192_CBC = 1,
    AES_256_CBC = 2,
    AES_128_ECB = 3,
    AES_192_ECB = 4,
    AES_256_ECB = 5,
    AES_128_CTR = 6,
    AES_192_CTR = 7,
    AES_256_CTR = 8,
    AES_128_GCM = 9,
    AES_192_GCM = 10,
    AES_256_GCM = 11,
    AES_128_OFB = 12,
    AES_192_OFB = 13,
    AES_256_OFB = 14,
    DES_CBC = 15,
    DES_ECB = 16,
    RC4 = 17,
    SM4_ECB = 18,
    SM4_CBC = 19,
    SM4_CTR = 20,
    SM4_CTR_32 = 21,
    SM4_OFB = 22,
    SM4_CFB = 23,
    SM4_GCM = 27,
    DES_DED3_CBC = 24,
    DES_DED3_ECB = 25,
    CHACHA20_POLY1305 = 26,
}

#[cfg(test)]
mod tests {
    use crate::boring::AeadDir;
    use crate::buffer::{CipherEncodeBuffer, TlsDecodeBuffer};
    use crate::{AeadCtx, CipherSuite, RecordType};

    fn test_cipher_tls(suite: &'static CipherSuite, key: &[u8], en: &[u8]) {
        let iv = [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        let payload = [1, 2, 3, 4, 5, 61, 2, 3, 4, 5, 6, 7, 8, 9, 23, 23];
        let mac_key = vec![12; suite.mac_key_size];
        let mut buffer = [0; 1024];
        let mut record_buffer = CipherEncodeBuffer::new_tls(RecordType::HandShake, &mut buffer, &payload, suite);
        record_buffer.add_explicit_iv(&iv);

        let mut real_key = Vec::with_capacity(mac_key.len() + key.len());
        real_key.extend_from_slice(mac_key.as_slice());
        real_key.extend_from_slice(key);
        let aead = AeadCtx::new_with_key(*suite.aead(), AeadDir::Seal, &real_key).unwrap();
        aead.seal(&iv, &record_buffer.aad(0), &mut record_buffer).unwrap();
        let len = record_buffer.record_len();
        assert_eq!(&buffer[..len], en);


        let mut decoded_buffer = vec![0; 1024];
        let mut record_buffer = TlsDecodeBuffer::from_buffer(&buffer[..len], &mut decoded_buffer, suite).unwrap();
        let aead = AeadCtx::new_with_key(*suite.aead(), AeadDir::Open, &real_key).unwrap();
        let len = aead.open(&iv, &record_buffer.aad(0).unwrap(), &mut record_buffer).unwrap();
        assert_eq!(decoded_buffer[..len], payload);
    }

    #[test]
    fn test_cipher_cryptor() {
        let key = [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8].to_vec();
        test_cipher_tls(
            &CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            &key,
            &[22, 3, 3, 0, 64, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 225, 181, 85, 149, 189, 100, 192, 39, 33, 30, 205, 22, 123, 49, 172, 97, 106, 123, 166, 131, 129, 167, 149, 187, 174, 174, 240, 122, 9, 87, 56, 140, 117, 152, 228, 72, 33, 112, 254, 70, 101, 122, 70, 56, 86, 138, 18, 134],
        );
        test_cipher_tls(
            &CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
            &key,
            &[22, 3, 3, 0, 80, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 225, 181, 85, 149, 189, 100, 192, 39, 33, 30, 205, 22, 123, 49, 172, 97, 150, 39, 188, 217, 227, 123, 176, 202, 171, 118, 173, 133, 177, 212, 23, 239, 79, 83, 238, 222, 83, 155, 116, 15, 213, 225, 52, 26, 134, 201, 207, 232, 194, 72, 163, 90, 108, 33, 90, 207, 135, 156, 79, 245, 245, 89, 69, 218],
        );


        let key = [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8].to_vec();
        test_cipher_tls(
            &CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            &key,
            &[22, 3, 3, 0, 64, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 14, 154, 194, 131, 254, 83, 135, 224, 182, 116, 28, 102, 151, 64, 116, 65, 233, 40, 102, 87, 64, 5, 139, 184, 61, 216, 62, 94, 54, 212, 193, 146, 8, 193, 18, 124, 254, 208, 135, 126, 57, 190, 219, 84, 217, 103, 135, 96],
        );
        test_cipher_tls(
            &CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA256,
            &key,
            &[22, 3, 3, 0, 80, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 14, 154, 194, 131, 254, 83, 135, 224, 182, 116, 28, 102, 151, 64, 116, 65, 177, 4, 110, 167, 103, 133, 161, 68, 66, 82, 136, 32, 242, 209, 242, 141, 15, 246, 195, 188, 2, 244, 70, 74, 142, 211, 190, 241, 141, 138, 35, 83, 209, 223, 105, 29, 219, 11, 66, 143, 26, 215, 62, 69, 192, 39, 68, 227],
        );
        test_cipher_tls(
            &CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
            &key,
            &[22, 3, 3, 0, 96, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 14, 154, 194, 131, 254, 83, 135, 224, 182, 116, 28, 102, 151, 64, 116, 65, 69, 90, 210, 242, 249, 68, 56, 215, 228, 165, 35, 39, 182, 148, 179, 128, 14, 191, 51, 49, 128, 170, 146, 205, 56, 8, 34, 192, 78, 178, 233, 122, 153, 25, 193, 53, 84, 243, 227, 111, 212, 236, 62, 214, 206, 240, 42, 232, 245, 246, 24, 145, 92, 181, 124, 12, 172, 150, 19, 195, 58, 123, 93, 40],
        );
    }
}