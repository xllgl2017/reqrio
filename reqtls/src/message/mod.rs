use certificate::{Certificates, CertificateStatus};
use client_hello::ClientHello;
use key_exchange::{ClientKeyExchange, ServerKeyExchange};
use server_hello::{ServerHello, ServerHelloDone};
use session_ticket::SessionTicket;
use std::mem;
use crate::error::RlsResult;
use super::bytes::Bytes;

pub mod certificate;
pub mod client_hello;
pub mod server_hello;
pub mod key_exchange;
mod session_ticket;

#[derive(Debug)]
pub enum Message {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    Certificate(Certificates),
    ServerKeyExchange(ServerKeyExchange),
    ServerHelloDone(ServerHelloDone),
    ClientKeyExchange(ClientKeyExchange),
    NewSessionTicket(SessionTicket),
    Payload(Bytes),
    CertificateStatus(CertificateStatus),
    CipherSpec,
}

impl Message {
    pub fn from_bytes(bytes: Vec<u8>, payload: bool) -> RlsResult<Message> {
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
            Ok(Message::Payload(Bytes::new(bytes)))
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
            Message::Payload(v) => v.as_bytes(),
        }
    }

    pub fn client_mut(&mut self) -> Option<&mut ClientHello> {
        match self {
            Message::ClientHello(v) => Some(v),
            _ => None
        }
    }
    // pub fn client(&self) -> Option<&ClientHello> {
    //     match self {
    //         Message::ClientHello(v) => Some(v),
    //         _ => None
    //     }
    // }

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

    pub fn take_payload(&mut self) -> Option<Bytes> {
        match self {
            Message::Payload(v) => Some(mem::take(v)),
            _ => None
        }
    }

    pub fn payload(&self) -> Option<&Bytes> {
        match self {
            Message::Payload(v) => Some(v),
            _ => None
        }
    }

    pub fn payload_mut(&mut self) -> Option<&mut Bytes> {
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
