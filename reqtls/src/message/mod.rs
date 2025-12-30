use crate::error::RlsResult;
use certificate::{CertificateStatus, Certificates};
use client_hello::ClientHello;
use key_exchange::{ClientKeyExchange, ServerKeyExchange};
use server_hello::{ServerHello, ServerHelloDone};
use session_ticket::SessionTicket;
use std::fmt::Debug;
use std::ops::{Index, IndexMut, Range, RangeFrom, RangeTo};
use crate::extend::Aead;

pub mod certificate;
pub mod client_hello;
pub mod server_hello;
pub mod key_exchange;
mod session_ticket;


pub struct Payload<'a>(&'a mut [u8]);

impl<'a> Payload<'a> {
    pub fn explicit(&self, aead: &Aead) -> &[u8] {
        match aead {
            Aead::AES_128_GCM | Aead::AES_256_GCM => &self.0[..8],
            _ => &self.0[..0]
        }
    }

    pub fn insert_explicit(&mut self, aead: &Aead, explicit: &[u8]) {
        match aead {
            Aead::AES_128_GCM | Aead::AES_256_GCM => self.0[..8].copy_from_slice(explicit),
            _ => {}
        }
    }


    pub fn from_slice(bytes: &'a mut [u8]) -> Payload<'a> {
        Payload(bytes)
    }

    pub fn encrypting_payload(&mut self, aead: &Aead) -> &mut [u8] {
        let len = self.0.len();
        match aead {
            Aead::AES_128_GCM | Aead::AES_256_GCM => &mut self.0[8..len - 16],
            Aead::ChaCha20_POLY1305 => &mut self.0[..len - 16],
            _ => self.0
        }
    }

    pub fn decrypting_payload(&mut self, aead: &Aead) -> &mut [u8] {
        match aead {
            Aead::AES_128_GCM | Aead::AES_256_GCM => &mut self.0[8..],
            Aead::ChaCha20_POLY1305 => &mut self.0,
            _ => self.0
        }
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl<'a> Debug for Payload<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(hex::encode(&self.0).as_str())
    }
}

impl<'a> Index<Range<usize>> for Payload<'a> {
    type Output = [u8];

    fn index(&self, index: Range<usize>) -> &Self::Output {
        &self.0[index]
    }
}

impl<'a> IndexMut<Range<usize>> for Payload<'a> {
    fn index_mut(&mut self, index: Range<usize>) -> &mut [u8] {
        &mut self.0[index]
    }
}

impl<'a> Index<RangeTo<usize>> for Payload<'a> {
    type Output = [u8];

    fn index(&self, index: RangeTo<usize>) -> &Self::Output {
        &self.0[index]
    }
}

impl<'a> IndexMut<RangeTo<usize>> for Payload<'a> {
    fn index_mut(&mut self, index: RangeTo<usize>) -> &mut [u8] {
        &mut self.0[index]
    }
}

impl<'a> Index<RangeFrom<usize>> for Payload<'a> {
    type Output = [u8];

    fn index(&self, index: RangeFrom<usize>) -> &Self::Output {
        &self.0[index]
    }
}

impl<'a> IndexMut<RangeFrom<usize>> for Payload<'a> {
    fn index_mut(&mut self, index: RangeFrom<usize>) -> &mut [u8] {
        &mut self.0[index]
    }
}


#[derive(Debug)]
pub enum Message<'a> {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    Certificate(Certificates),
    ServerKeyExchange(ServerKeyExchange),
    ServerHelloDone(ServerHelloDone),
    ClientKeyExchange(ClientKeyExchange),
    NewSessionTicket(SessionTicket),
    Payload(Payload<'a>),
    CertificateStatus(CertificateStatus),
    CipherSpec,
}

impl<'a> Message<'a> {
    pub fn from_bytes(bytes: &mut [u8], payload: bool) -> RlsResult<Message<'_>> {
        if !payload {
            let handshake_type = HandshakeType::from_byte(bytes[0]).unwrap();
            match handshake_type {
                HandshakeType::ClientHello => Ok(Message::ClientHello(ClientHello::from_bytes(handshake_type, &bytes)?)),
                HandshakeType::ServerHello => Ok(Message::ServerHello(ServerHello::from_bytes(handshake_type, &bytes)?)),
                HandshakeType::Certificate => Ok(Message::Certificate(Certificates::from_bytes(handshake_type, &bytes)?)),
                HandshakeType::ServerKeyExchange => Ok(Message::ServerKeyExchange(ServerKeyExchange::from_bytes(handshake_type, &bytes)?)),
                HandshakeType::ServerHelloDone => Ok(Message::ServerHelloDone(ServerHelloDone::from_bytes(handshake_type, &bytes)?)),
                HandshakeType::ClientKeyExchange => Ok(Message::ClientKeyExchange(ClientKeyExchange::from_bytes(handshake_type, &bytes)?)),
                HandshakeType::NewSessionTicket => Ok(Message::NewSessionTicket(SessionTicket::from_bytes(handshake_type, &bytes)?)),
                HandshakeType::CertificateStatus => Ok(Message::CertificateStatus(CertificateStatus::from_bytes(handshake_type, &bytes))),
                HandshakeType::CipherSpec => Ok(Message::CipherSpec),
            }
        } else {
            Ok(Message::Payload(Payload(bytes)))
        }
    }

    pub fn payload_len(&self) -> u32 {
        match self {
            Message::ClientHello(v) => v.len(),
            Message::ServerHello(v) => v.len(),
            Message::Certificate(v) => v.len(),
            Message::ServerKeyExchange(v) => v.len(),
            Message::ServerHelloDone(v) => v.len(),
            Message::ClientKeyExchange(v) => v.len(),
            Message::NewSessionTicket(v) => v.len(),
            Message::Payload(v) => v.len() as u32,
            Message::CertificateStatus(v) => v.len(),
            Message::CipherSpec => 0
        }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        match self {
            Message::ClientHello(v) => v.as_bytes(),
            Message::ServerHello(v) => v.as_bytes(),
            Message::Certificate(v) => v.as_bytes(),
            Message::ServerKeyExchange(v) => v.as_bytes(),
            Message::ServerHelloDone(v) => v.as_bytes(),
            Message::ClientKeyExchange(v) => v.as_bytes(),
            Message::NewSessionTicket(v) => v.as_bytes(),
            Message::CipherSpec => vec![HandshakeType::ClientHello.as_u8()],
            Message::CertificateStatus(v) => v.as_bytes(),
            Message::Payload(_) => vec![],
        }
    }

    pub fn client_mut(&mut self) -> Option<&mut ClientHello> {
        match self {
            Message::ClientHello(v) => Some(v),
            _ => None
        }
    }
    pub fn client(&self) -> Option<&ClientHello> {
        match self {
            Message::ClientHello(v) => Some(v),
            _ => None
        }
    }

    // pub fn server(&self) -> Option<&ServerHello> {
    //     match self {
    //         Message::ServerHello(v) => Some(v),
    //         _ => None
    //     }
    // }

    // pub fn server_key_exchange(&self) -> Option<&ServerKeyExchange> {
    //     match self {
    //         Message::ServerKeyExchange(v) => Some(v),
    //         _ => None
    //     }
    // }

    pub fn client_key_exchange_mut(&mut self) -> Option<&mut ClientKeyExchange> {
        match self {
            Message::ClientKeyExchange(v) => Some(v),
            _ => None
        }
    }

    // pub fn take_payload(&mut self) -> Option<Bytes> {
    //     match self {
    //         Message::Payload(v) => Some(mem::take(v)),
    //         _ => None
    //     }
    // }

    pub fn payload(&self) -> Option<&Payload<'_>> {
        match self {
            Message::Payload(v) => Some(v),
            _ => None
        }
    }

    pub fn payload_mut(&mut self) -> Option<&'a mut Payload<'_>> {
        match self {
            Message::Payload(v) => Some(v),
            _ => None
        }
    }

    // pub fn certificate_status(&self) -> Option<&CertificateStatus> {
    //     match self {
    //         Message::CertificateStatus(v) => Some(v),
    //         _ => None
    //     }
    // }
}

#[derive(Debug, Copy, Clone)]
pub enum HandshakeType {
    ClientHello = 0x1,
    ServerHello = 0x2,
    NewSessionTicket = 0x4,
    Certificate = 0xb,
    ServerKeyExchange = 0xc,
    ServerHelloDone = 0xe,
    ClientKeyExchange = 0x10,
    CipherSpec = 0x14,
    CertificateStatus = 0x16,
}

impl HandshakeType {
    pub fn from_byte(byte: u8) -> Option<HandshakeType> {
        match byte {
            0x1 => Some(HandshakeType::ClientHello),
            0x2 => Some(HandshakeType::ServerHello),
            0x4 => Some(HandshakeType::NewSessionTicket),
            0xb => Some(HandshakeType::Certificate),
            0xc => Some(HandshakeType::ServerKeyExchange),
            0xe => Some(HandshakeType::ServerHelloDone),
            0x10 => Some(HandshakeType::ClientKeyExchange),
            0x14 => Some(HandshakeType::CipherSpec),
            0x16 => Some(HandshakeType::CertificateStatus),
            _ => None
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}
