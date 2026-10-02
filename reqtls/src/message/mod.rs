mod certificate;
mod client_hello;
mod server_hello;
mod key_exchange;
mod session_ticket;
mod alert;
mod encrypted_extension;
#[cfg(feature = "quic")]
mod quic;

use crate::buffer::Buf;
use crate::error::RlsResult;
use crate::suite::KeyExchangeAlg;
use crate::{BufferError, HandShakeError, Reader, RecordType, Version, Writer};
pub use alert::Alert;
use certificate::CertificateStatus;
pub use certificate::Certificates;
pub use certificate::{CertificateRequest, CertificateVerify, CompressedCertificate};
pub use client_hello::ClientHello;
pub use encrypted_extension::EncryptedExtension;
pub use key_exchange::{ClientKeyExchange, NamedCurve, ServerKeyExchange};
#[cfg(feature = "quic")]
pub use quic::*;
pub use server_hello::{ServerHello, ServerHelloDone};
pub use session_ticket::SessionTicket;
use std::fmt::Debug;
use std::fmt::Formatter;

pub struct Message<'a> {
    pub encoded: Buf<'a>,
    pub parsed: MessageParsed<'a>,
}

#[cfg(debug_assertions)]
impl<'a> Debug for Message<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut message = f.debug_struct("Message");
        message.field("encoded", &self.encoded);
        message.field("parsed", &self.parsed);
        message.finish()
    }
}

impl<'a> Message<'a> {
    pub fn new_parsed(parsed: MessageParsed<'a>) -> Message<'a> {
        Message {
            parsed,
            encoded: Buf::default(),
        }
    }

    pub fn from_reader(reader: &mut Reader<'a>, record_type: &RecordType, alg: KeyExchangeAlg, version: &Version) -> RlsResult<Message<'a>> {
        let pos = reader.position();
        let parsed = MessageParsed::from_reader(reader, record_type, alg, version)?;
        let encoded_size = reader.position() - pos;
        reader.set_position(pos);
        Ok(Message {
            encoded: Buf::new_ref(reader.read_slice(encoded_size)?),
            parsed,
        })
    }
}
impl<'a> From<Certificates<'a>> for Message<'a> {
    fn from(value: Certificates<'a>) -> Self {
        Message::new_parsed(MessageParsed::Certificate(value))
    }
}

impl<'a> From<ClientKeyExchange<'a>> for Message<'a> {
    fn from(value: ClientKeyExchange<'a>) -> Self {
        Message::new_parsed(MessageParsed::ClientKeyExchange(value))
    }
}


pub enum MessageParsed<'a> {
    UnParsed,
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    Certificate(Certificates<'a>),
    CompressedCertificate(CompressedCertificate<'a>),
    ServerKeyExchange(ServerKeyExchange<'a>),
    ServerHelloDone(ServerHelloDone),
    ClientKeyExchange(ClientKeyExchange<'a>),
    NewSessionTicket(SessionTicket),
    Payload(Buf<'a>),
    CertificateStatus(CertificateStatus<'a>),
    CertificateRequest(CertificateRequest<'a>),
    CertificateVerify(CertificateVerify<'a>),
    Alert(Alert),
    CipherSpec,
    Finished(Buf<'a>),
    EncryptedExtension(EncryptedExtension),
}

impl<'a> MessageParsed<'a> {
    pub fn from_bytes(bytes: &'a [u8], record_type: &RecordType, alg: KeyExchangeAlg, version: &Version) -> RlsResult<MessageParsed<'a>> {
        let mut reader = Reader::from_slice(bytes);
        MessageParsed::from_reader(&mut reader, record_type, alg, version)
    }

    fn from_reader_handshake(reader: &mut Reader<'a>, alg: KeyExchangeAlg, version: &Version) -> RlsResult<MessageParsed<'a>> {
        let handshake_type = HandshakeType::new(reader.read_u8()?);
        match handshake_type {
            HandshakeType::ClientHello => Ok(MessageParsed::ClientHello(ClientHello::from_reader(reader)?)),
            HandshakeType::ServerHello => Ok(MessageParsed::ServerHello(ServerHello::from_reader(reader)?)),
            HandshakeType::Certificate => Ok(MessageParsed::Certificate(Certificates::from_reader(version, reader, false)?)),
            HandshakeType::CompressedCertificate => Ok(MessageParsed::CompressedCertificate(CompressedCertificate::from_reader(handshake_type, reader)?)),
            HandshakeType::ServerKeyExchange => Ok(MessageParsed::ServerKeyExchange(ServerKeyExchange::from_reader(handshake_type, reader, version)?)),
            HandshakeType::ServerHelloDone => Ok(MessageParsed::ServerHelloDone(ServerHelloDone::from_reader(handshake_type, reader)?)),
            HandshakeType::ClientKeyExchange => Ok(MessageParsed::ClientKeyExchange(ClientKeyExchange::from_reader(reader, alg)?)),
            HandshakeType::NewSessionTicket => Ok(MessageParsed::NewSessionTicket(SessionTicket::from_reader(reader, version)?)),
            HandshakeType::CertificateStatus => Ok(MessageParsed::CertificateStatus(CertificateStatus::from_reader(handshake_type, reader)?)),
            HandshakeType::CertificateRequest => Ok(MessageParsed::CertificateRequest(CertificateRequest::from_reader(handshake_type, reader)?)),
            HandshakeType::CertificateVerify => Ok(MessageParsed::CertificateVerify(CertificateVerify::from_reader(handshake_type, reader)?)),
            HandshakeType::Finish => {
                let len = reader.read_u24()? as usize;
                Ok(MessageParsed::Finished(Buf::new_ref(reader.read_slice(len)?)))
            }
            HandshakeType::EncryptedExtensions => Ok(MessageParsed::EncryptedExtension(EncryptedExtension::from_reader(reader)?)),
            HandshakeType::MessageHash => Err(HandShakeError::UnsupportedMessage(handshake_type).into()),
            _ => Err(HandShakeError::UnsupportedMessage(handshake_type).into())
        }
    }

    pub fn from_reader(reader: &mut Reader<'a>, record_type: &RecordType, alg: KeyExchangeAlg, version: &Version) -> RlsResult<MessageParsed<'a>> {
        match record_type {
            RecordType::CipherSpec => {
                reader.read_u8()?;
                Ok(MessageParsed::CipherSpec)
            }
            RecordType::Alert => Ok(MessageParsed::Payload(Buf::new_ref(reader.read_slice(2)?))),
            RecordType::HandShake => MessageParsed::from_reader_handshake(reader, alg, version),
            RecordType::ApplicationData => {
                let len = reader.unread_len();
                Ok(MessageParsed::Payload(Buf::new_ref(reader.read_slice(len)?)))
            }
        }
    }

    pub fn len(&self, kea: KeyExchangeAlg) -> usize {
        match self {
            MessageParsed::UnParsed => 0,
            MessageParsed::Certificate(v) => v.len(),
            MessageParsed::CompressedCertificate(v) => v.len(),
            MessageParsed::ServerKeyExchange(v) => v.len(),
            MessageParsed::ServerHelloDone(v) => v.len(),
            MessageParsed::ClientKeyExchange(v) => v.len(kea),
            MessageParsed::Payload(v) => v.len(),
            MessageParsed::CertificateStatus(v) => v.len(),
            MessageParsed::CertificateRequest(v) => v.len(),
            MessageParsed::CertificateVerify(v) => v.len(),
            MessageParsed::Alert(_) => 0,
            MessageParsed::CipherSpec => 1,
            MessageParsed::Finished(v) => 3 + v.len(),
            _ => unreachable!()
        }
    }

    pub fn write_to(self, writer: &mut Writer, kea: KeyExchangeAlg) -> Result<(), BufferError> {
        match self {
            MessageParsed::UnParsed => Ok(()),
            MessageParsed::Certificate(v) => v.write_to(writer),
            MessageParsed::CompressedCertificate(v) => v.write_to(writer),
            MessageParsed::ServerKeyExchange(v) => v.write_to(writer),
            MessageParsed::ServerHelloDone(v) => v.write_to(writer),
            MessageParsed::ClientKeyExchange(v) => v.write_to(writer, kea),
            MessageParsed::Payload(v) => writer.write_slice(v.as_ref()),
            MessageParsed::CertificateStatus(v) => v.write_to(writer),
            MessageParsed::CertificateRequest(v) => v.write_to(writer),
            MessageParsed::CertificateVerify(v) => v.write_to(writer),
            MessageParsed::Alert(_) => Ok(()),
            MessageParsed::CipherSpec => writer.write_u8(1),
            MessageParsed::Finished(v) => {
                writer.write_u16(v.len() as u16)?;
                writer.write_slice(v.as_ref())
            }
            _ => unreachable!()
        }
    }

    pub fn server(&self) -> Option<&ServerHello> {
        match self {
            MessageParsed::ServerHello(v) => Some(v),
            _ => None
        }
    }

    pub fn client_key_exchange_mut(&mut self) -> Option<&mut ClientKeyExchange<'a>> {
        match self {
            MessageParsed::ClientKeyExchange(v) => Some(v),
            _ => None
        }
    }

    pub fn payload(&self) -> Option<&Buf<'a>> {
        match self {
            MessageParsed::Payload(v) => Some(v),
            _ => None
        }
    }
}

#[cfg(debug_assertions)]
impl<'a> Debug for MessageParsed<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageParsed::UnParsed => write!(f, "UnParsed"),
            MessageParsed::ClientHello(v) => if f.alternate() { write!(f, "{:#?}", v) } else { write!(f, "{:?}", v) }
            MessageParsed::ServerHello(v) => if f.alternate() { write!(f, "{:#?}", v) } else { write!(f, "{:?}", v) }
            MessageParsed::Certificate(v) => if f.alternate() { write!(f, "{:#?}", v) } else { write!(f, "{:?}", v) }
            MessageParsed::CompressedCertificate(v) => if f.alternate() { write!(f, "{:#?}", v) } else { write!(f, "{:?}", v) }
            MessageParsed::ServerKeyExchange(v) => if f.alternate() { write!(f, "{:#?}", v) } else { write!(f, "{:?}", v) }
            MessageParsed::ServerHelloDone(v) => if f.alternate() { write!(f, "{:#?}", v) } else { write!(f, "{:?}", v) }
            MessageParsed::ClientKeyExchange(v) => if f.alternate() { write!(f, "{:#?}", v) } else { write!(f, "{:?}", v) }
            MessageParsed::NewSessionTicket(v) => if f.alternate() { write!(f, "{:#?}", v) } else { write!(f, "{:?}", v) }
            MessageParsed::Payload(v) => if f.alternate() { write!(f, "{:#?}", v) } else { write!(f, "{:?}", v) }
            MessageParsed::CertificateStatus(v) => if f.alternate() { write!(f, "{:#?}", v) } else { write!(f, "{:?}", v) }
            MessageParsed::CertificateRequest(v) => if f.alternate() { write!(f, "{:#?}", v) } else { write!(f, "{:?}", v) }
            MessageParsed::CertificateVerify(v) => if f.alternate() { write!(f, "{:#?}", v) } else { write!(f, "{:?}", v) }
            MessageParsed::Alert(v) => if f.alternate() { write!(f, "{:#?}", v) } else { write!(f, "{:?}", v) }
            MessageParsed::CipherSpec => write!(f, "CipherSpec"),
            MessageParsed::Finished(v) => if f.alternate() { writeln!(f, "Finished({:#?})", v) } else { writeln!(f, "Finished({:?})", v) }
            MessageParsed::EncryptedExtension(v) => if f.alternate() { write!(f, "{:#?}", v) } else { write!(f, "{:?}", v) }
        }
    }
}


#[repr(C)]
#[derive(Copy, Clone, PartialEq)]
pub struct HandshakeType(u8);

#[allow(non_upper_case_globals)]
impl HandshakeType {
    pub const ClientHello: HandshakeType = HandshakeType::new(1);
    pub const ServerHello: HandshakeType = HandshakeType::new(2);
    pub const NewSessionTicket: HandshakeType = HandshakeType::new(4);
    pub const EncryptedExtensions: HandshakeType = HandshakeType::new(8);
    pub const Certificate: HandshakeType = HandshakeType::new(11);
    pub const ServerKeyExchange: HandshakeType = HandshakeType::new(12);
    pub const CertificateRequest: HandshakeType = HandshakeType::new(13);
    pub const ServerHelloDone: HandshakeType = HandshakeType::new(14);
    pub const CertificateVerify: HandshakeType = HandshakeType::new(15);
    pub const ClientKeyExchange: HandshakeType = HandshakeType::new(16);
    pub const Finish: HandshakeType = HandshakeType::new(20);
    pub const CertificateStatus: HandshakeType = HandshakeType::new(22);
    pub const CompressedCertificate: HandshakeType = HandshakeType::new(25);
    pub const MessageHash: HandshakeType = HandshakeType::new(254);
    pub const fn new(val: u8) -> HandshakeType {
        HandshakeType(val)
    }
    pub const fn spec(&self) -> &str {
        match *self {
            HandshakeType::ClientHello => "ClientHello",
            HandshakeType::ServerHello => "ServerHello",
            HandshakeType::NewSessionTicket => "NewSessionTicket",
            HandshakeType::EncryptedExtensions => "EncryptedExtensions",
            HandshakeType::Certificate => "Certificate",
            HandshakeType::ServerKeyExchange => "ServerKeyExchange",
            HandshakeType::CertificateRequest => "CertificateRequest",
            HandshakeType::ServerHelloDone => "ServerHelloDone",
            HandshakeType::CertificateVerify => "CertificateVerify",
            HandshakeType::ClientKeyExchange => "ClientKeyExchange",
            HandshakeType::Finish => "Finish",
            HandshakeType::CertificateStatus => "CertificateStatus",
            HandshakeType::CompressedCertificate => "CompressedCertificate",
            _ => "Unknown",
        }
    }

    pub const fn inner(&self) -> u8 {
        self.0
    }

    pub const fn into_inner(self) -> u8 {
        self.0
    }
}

impl Debug for HandshakeType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}(0x{:02x})", self.spec(), self.0)
    }
}