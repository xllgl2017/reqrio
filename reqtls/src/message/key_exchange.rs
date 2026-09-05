use super::super::boring::SignatureAlgorithm;
use super::super::message::HandshakeType;
use crate::buffer::Buf;
use crate::error::RlsResult;
use crate::suite::KeyExchangeAlg;
use crate::{u24, BufferError, Reader, Version, Writer};
use std::fmt::{Debug, Display, Formatter};

#[derive(Debug, Copy, Clone)]
pub enum CurveType {
    NamedCurve = 0x3
}

impl CurveType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x3 => Some(Self::NamedCurve),
            _ => None
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

#[derive(Copy, Clone, Hash, PartialEq, Eq)]
pub struct NamedCurve(u16);

#[allow(non_upper_case_globals)]
impl NamedCurve {
    pub const X25519: u16 = 0x1d;
    pub const X448: u16 = 0x1e;
    pub const X25519MLKEM768: u16 = 0x11ec;
    pub const SecP256r1MLKEM768: u16 = 0x11eb;
    pub const SecP384r1MLKEM1024: u16 = 0x11ed;
    pub const SecP256r1: u16 = 0x0017;
    pub const SecP384r1: u16 = 0x0018;
    pub const SecP521r1: u16 = 0x0019;
    pub const FFDHE2048: u16 = 0x0100;
    pub const FFDHE3072: u16 = 0x0101;
    pub const FFDHE4096: u16 = 0x0102;
    pub const FFDHE6144: u16 = 0x0103;
    pub const FFDHE8192: u16 = 0x0104;


    pub const ECC_SM2: u16 = 0xFFFF;


    pub const ALL: [u16; 13] = [
        NamedCurve::X25519,
        NamedCurve::X448,
        NamedCurve::SecP256r1,
        NamedCurve::SecP384r1,
        NamedCurve::SecP521r1,
        NamedCurve::X25519MLKEM768,
        NamedCurve::SecP256r1MLKEM768,
        NamedCurve::SecP384r1MLKEM1024,
        NamedCurve::FFDHE2048,
        NamedCurve::FFDHE3072,
        NamedCurve::FFDHE4096,
        NamedCurve::FFDHE6144,
        NamedCurve::FFDHE8192
    ];

    fn spec(&self) -> &str {
        match self.0 {
            NamedCurve::X25519 => "X25519",
            NamedCurve::X448 => "X448",
            NamedCurve::X25519MLKEM768 => "X25519MLKEM768",
            NamedCurve::SecP256r1 => "Secp256r1",
            NamedCurve::SecP384r1 => "Secp384r1",
            NamedCurve::SecP521r1 => "Secp521r1",
            NamedCurve::FFDHE2048 => "FFDHE2048",
            NamedCurve::FFDHE3072 => "FFDHE3072",
            NamedCurve::FFDHE4096 => "FFDHE4096",
            NamedCurve::FFDHE6144 => "FFDHE6144",
            NamedCurve::FFDHE8192 => "FFDHE8192",
            NamedCurve::ECC_SM2 => "ECC_SM2",
            _ => "Reserved"
        }
    }

    pub fn new(v: u16) -> NamedCurve {
        NamedCurve(v)
    }

    pub fn into_inner(self) -> u16 { self.0 }

    pub fn as_u16(&self) -> u16 {
        self.0
    }

    pub fn is_reserved(&self) -> bool {
        crate::REVERSED.contains(&self.0)
    }
}

impl From<u16> for NamedCurve {
    fn from(v: u16) -> Self { NamedCurve(v) }
}

impl PartialEq<u16> for &NamedCurve {
    fn eq(&self, other: &u16) -> bool {
        &self.0 == other
    }
}

impl Debug for NamedCurve {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}(0x{:04x})", self.spec(), self.0)
    }
}

impl Display for NamedCurve {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}(0x{:04x})", self.spec(), self.0)
    }
}

impl PartialEq<u16> for NamedCurve {
    fn eq(&self, other: &u16) -> bool {
        &self.0 == other
    }
}


#[derive(Debug)]
pub struct ServerHellmanParam<'a> {
    curve_type: CurveType,
    named_curve: NamedCurve,
    pub_key_len: u8,
    pub_key: Buf<'a>,
    signature_algorithm: SignatureAlgorithm,
    signature_len: u16,
    signature: Buf<'a>,
}

impl<'a> ServerHellmanParam<'a> {
    pub fn new() -> ServerHellmanParam<'a> {
        ServerHellmanParam {
            curve_type: CurveType::NamedCurve,
            named_curve: NamedCurve::SecP384r1.into(),
            pub_key_len: 0,
            pub_key: Buf::Ref(&[]),
            signature_algorithm: SignatureAlgorithm::RSA_PSS_RSAE_SHA256.into(),
            signature_len: 0,
            signature: Buf::Ref(&[]),
        }
    }
    pub fn from_reader(reader: &mut Reader<'a>, version: &Version) -> RlsResult<ServerHellmanParam<'a>> {
        let mut res = ServerHellmanParam::new();
        if !matches!(version, &Version::TLCP) {
            res.curve_type = CurveType::from_u8(reader.read_u8()?).ok_or("CurveType Unknown")?;
            res.named_curve = NamedCurve::new(reader.read_u16()?);
            res.pub_key_len = reader.read_u8()?;
            res.pub_key = Buf::Ref(reader.read_slice(res.pub_key_len as usize)?);
            res.signature_algorithm = SignatureAlgorithm::new(reader.read_u16()?);
        } else {
            res.named_curve = NamedCurve::ECC_SM2.into();
            res.signature_algorithm = SignatureAlgorithm::new(0);
        }
        res.signature_len = reader.read_u16()?;
        res.signature = Buf::Ref(reader.read_slice(res.signature_len as usize)?);
        Ok(res)
    }

    pub fn len(&self) -> usize {
        8 + self.pub_key.len() + self.signature.len()
    }

    pub fn write_to(self, writer: &mut Writer) -> Result<(), BufferError> {
        writer.write_u8(self.curve_type as u8)?;
        writer.write_u16(self.named_curve.0)?;
        writer.write_u8(self.pub_key.len() as u8)?;
        writer.write_slice(self.pub_key.as_ref())?;
        writer.write_u16(self.signature_algorithm.into_inner())?;
        writer.write_u16(self.signature.len() as u16)?;
        writer.write_slice(self.signature.as_ref())
    }

    pub fn curve_type(&self) -> &CurveType { &self.curve_type }

    pub fn pub_key(&self) -> &Buf<'a> {
        &self.pub_key
    }

    pub fn named_curve(&self) -> &NamedCurve {
        &self.named_curve
    }

    pub fn signature(&self) -> &Buf<'a> {
        &self.signature
    }

    pub fn signature_algorithm(&self) -> &SignatureAlgorithm {
        &self.signature_algorithm
    }

    pub fn set_pub_key(&mut self, pub_key: Buf<'a>) {
        self.pub_key = pub_key;
    }

    pub fn set_signature(&mut self, signature: Buf<'a>) {
        self.signature = signature;
    }
}

#[derive(Debug)]
pub struct ServerKeyExchange<'a> {
    handshake_type: HandshakeType,
    hellman_param: ServerHellmanParam<'a>,
}

impl<'a> Default for ServerKeyExchange<'a> {
    fn default() -> Self {
        ServerKeyExchange {
            handshake_type: HandshakeType::ServerKeyExchange,
            hellman_param: ServerHellmanParam::new(),
        }
    }
}

impl<'a> ServerKeyExchange<'a> {
    pub fn from_reader(ht: HandshakeType, reader: &mut Reader<'a>, version: &Version) -> RlsResult<ServerKeyExchange<'a>> {
        reader.read_u24()?;
        Ok(ServerKeyExchange {
            handshake_type: ht,
            hellman_param: ServerHellmanParam::from_reader(reader, version)?,
        })
    }

    pub fn is_empty(&self) -> bool { self.len() == 0 }

    pub fn len(&self) -> usize {
        4 + self.hellman_param.len()
    }

    pub fn write_to(self, writer: &mut Writer) -> Result<(), BufferError> {
        writer.write_u8(self.handshake_type as u8)?;
        writer.write_u24(self.hellman_param.len() as u24)?;
        self.hellman_param.write_to(writer)
    }

    pub fn hellman_param(&self) -> &ServerHellmanParam<'a> {
        &self.hellman_param
    }

    pub fn hellman_param_mut(&mut self) -> &mut ServerHellmanParam<'a> { &mut self.hellman_param }
}

#[derive(Debug)]
pub struct ClientHellmanParam<'a> {
    pub_key_len: u16,
    pub_key: Buf<'a>,
}

impl<'a> ClientHellmanParam<'a> {
    pub fn new() -> ClientHellmanParam<'a> {
        ClientHellmanParam {
            pub_key_len: 0,
            pub_key: Buf::Ref(&[]),
        }
    }

    pub fn from_reader(reader: &mut Reader<'a>, alg: KeyExchangeAlg) -> RlsResult<ClientHellmanParam<'a>> {
        let mut res = ClientHellmanParam::new();
        res.pub_key_len = match alg {
            KeyExchangeAlg::RSA | KeyExchangeAlg::ECC => reader.read_u16()?,
            _ => reader.read_u8()? as u16,
        };
        // let key_size = suite.map(|x| x.key_size()).unwrap_or(1);
        // res.pub_key_len = if key_size == 2 { reader.read_u16()? } else { reader.read_u8()? as u16 };
        res.pub_key = Buf::Ref(reader.read_slice(res.pub_key_len as usize)?);
        Ok(res)
    }
    pub fn len(&self, alg: KeyExchangeAlg) -> usize {
        let key_size = if matches!(alg, KeyExchangeAlg::RSA | KeyExchangeAlg::ECC) { 2 } else { 1 };
        key_size + self.pub_key.len()
    }

    pub fn write_to(self, writer: &mut Writer, alg: KeyExchangeAlg) -> Result<(), BufferError> {
        match alg {
            KeyExchangeAlg::RSA | KeyExchangeAlg::ECC => writer.write_u16(self.pub_key.len() as u16)?,
            _ => writer.write_u8(self.pub_key.len() as u8)?,
        }
        writer.write_slice(self.pub_key.as_ref())
    }

    pub fn pub_key(&self) -> &Buf<'a> {
        &self.pub_key
    }
}

#[derive(Debug)]
pub struct ClientKeyExchange<'a> {
    handshake_type: HandshakeType,
    hellman_param: ClientHellmanParam<'a>,
}

impl<'a> Default for ClientKeyExchange<'a> {
    fn default() -> Self {
        ClientKeyExchange {
            handshake_type: HandshakeType::ClientKeyExchange,
            hellman_param: ClientHellmanParam::new(),
        }
    }
}

impl<'a> ClientKeyExchange<'a> {
    pub fn from_reader(reader: &mut Reader<'a>, alg: KeyExchangeAlg) -> RlsResult<ClientKeyExchange<'a>> {
        reader.read_u24()?;
        Ok(ClientKeyExchange {
            handshake_type: HandshakeType::ClientKeyExchange,
            hellman_param: ClientHellmanParam::from_reader(reader, alg)?,
        })
    }

    pub fn len(&self, kea: KeyExchangeAlg) -> usize {
        4 + self.hellman_param.len(kea)
    }

    pub fn write_to(self, writer: &mut Writer, kea: KeyExchangeAlg) -> Result<(), BufferError> {
        writer.write_u8(self.handshake_type as u8)?;
        writer.write_u24(self.hellman_param.len(kea) as u24)?;
        self.hellman_param.write_to(writer, kea)
    }

    pub fn set_pub_key(&mut self, pub_key: &'a [u8]) {
        self.hellman_param.pub_key = Buf::Ref(pub_key);
        self.hellman_param.pub_key_len = self.hellman_param.pub_key.len() as u16;
    }

    pub fn hellman_param(&self) -> &ClientHellmanParam<'a> {
        &self.hellman_param
    }
}

