use crate::{rand, CipherSuite, Version};
use std::fmt::{Debug, Formatter};
use std::ptr::null_mut;
use std::slice;

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum KeyType {
    Initial,
    Handshake,
    Application,
}

#[derive(Debug, Clone)]
pub struct TlsSession {
    ticket_len: u16,
    ticket_capacity: usize,
    ticket: *mut u8,
    session_id_len: u8,
    session_id_capacity: usize,
    session_id: *mut u8,
    master_secret: [u8; 48],
}

impl Drop for TlsSession {
    fn drop(&mut self) {
        if !self.session_id.is_null() {
            drop(unsafe { Vec::from_raw_parts(self.session_id, self.session_id_len as usize, self.session_id_capacity) });
            self.session_id = null_mut();
        }
        if !self.ticket.is_null() {
            drop(unsafe { Vec::from_raw_parts(self.ticket, self.ticket_len as usize, self.ticket_capacity) });
            self.ticket = null_mut();
        }
    }
}

unsafe impl Sync for TlsSession {}
unsafe impl Send for TlsSession {}

impl Default for TlsSession {
    fn default() -> TlsSession {
        let session_id = rand::random::<[u8; 32]>().to_vec();
        TlsSession::new(session_id)
    }
}

impl TlsSession {
    pub fn new(session_id: Vec<u8>) -> TlsSession {
        let (session_id, session_id_len, session_id_capacity) = session_id.into_raw_parts();
        TlsSession {
            ticket_len: 0,
            ticket_capacity: 0,
            ticket: null_mut(),
            session_id_len: session_id_len as u8,
            session_id_capacity,
            session_id,
            master_secret: [0u8; 48],
        }
    }


    pub fn ticket(&self) -> &[u8] {
        if self.ticket.is_null() { return &[]; }
        unsafe { slice::from_raw_parts(self.ticket, self.ticket_len as usize) }
    }

    pub fn set_ticket(&mut self, ticket: Vec<u8>) {
        if ticket.is_empty() { return; }
        if !self.ticket.is_null() {
            drop(unsafe { Vec::from_raw_parts(self.ticket, self.ticket_len as usize, self.ticket_capacity) });
            self.ticket = null_mut();
        }
        let (ticket, ticket_len, ticket_capacity) = ticket.into_raw_parts();
        self.ticket = ticket;
        self.ticket_len = ticket_len as u16;
        self.ticket_capacity = ticket_capacity;
    }

    pub fn session_id(&self) -> &[u8] {
        if self.session_id.is_null() { return &[]; }
        unsafe { slice::from_raw_parts(self.session_id, self.session_id_len as usize) }
    }

    pub fn master_secret(&self) -> &[u8; 48] { &self.master_secret }

    pub fn master_secret_mut(&mut self) -> &mut [u8; 48] { &mut self.master_secret }

    pub fn set_session_id(&mut self, session_id: &[u8]) {
        if session_id.is_empty() { return; }
        if !self.session_id.is_null() {
            drop(unsafe { Vec::from_raw_parts(self.session_id, self.session_id_len as usize, self.session_id_capacity) });
            self.session_id = null_mut();
        }
        let (session_id, session_id_len, session_id_capacity) = session_id.to_vec().into_raw_parts();
        self.session_id = session_id;
        self.session_id_len = session_id_len as u8;
        self.session_id_capacity = session_id_capacity;
    }
}

#[derive(Debug)]
pub(crate) struct Tls12Key {
    client_key: [u8; 80],
    server_key: [u8; 80],
    key_size: usize,
    mac_size: usize,
    client_iv: [u8; 16],
    server_iv: [u8; 16],
    iv_size: usize,
    explicit_len: usize,
}

impl Tls12Key {
    fn new(suite: &'static CipherSuite) -> Tls12Key {
        Tls12Key {
            mac_size: suite.mac_key_size,
            client_key: [0; 80],
            server_key: [0; 80],
            key_size: suite.key_size,
            client_iv: [0; 16],
            server_iv: [0; 16],
            iv_size: suite.fix_iv_size,
            explicit_len: suite.explict_iv_size,
        }
    }
}

#[derive(Debug)]
pub(crate) struct Tls13Key {
    client_key: [u8; 32],
    server_key: [u8; 32],
    key_size: usize,
    client_iv: [u8; 16],
    server_iv: [u8; 16],
    iv_size: usize,
}

impl Tls13Key {
    pub fn new(suite: &'static CipherSuite) -> Tls13Key {
        Tls13Key {
            client_key: [0; 32],
            server_key: [0; 32],
            key_size: suite.key_size,
            client_iv: [0; 16],
            server_iv: [0; 16],
            iv_size: suite.fix_iv_size,
        }
    }
}

#[derive(Debug)]
pub(crate) struct QUICKey {
    client_key: [u8; 32],
    server_key: [u8; 32],
    key_size: usize,
    client_iv: [u8; 16],
    server_iv: [u8; 16],
    iv_size: usize,
    #[cfg(feature = "quic")]
    client_hp_key: [u8; 32],
    #[cfg(feature = "quic")]
    server_hp_key: [u8; 32],
    hp_key_size: usize,
}

impl QUICKey {
    fn new(suite: &'static CipherSuite) -> QUICKey {
        QUICKey {
            client_key: [0; 32],
            server_key: [0; 32],
            key_size: suite.key_size,
            client_iv: [0; 16],
            server_iv: [0; 16],
            iv_size: suite.fix_iv_size,
            #[cfg(feature = "quic")]
            client_hp_key: [0; 32],
            #[cfg(feature = "quic")]
            server_hp_key: [0; 32],
            hp_key_size: suite.key_size,
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
pub(crate) enum KeyBlock {
    Uninitialed,
    Tls12(Tls12Key),
    Tls13(Tls13Key),
    QUIC {
        initial: Box<QUICKey>,
        handshake: Box<QUICKey>,
        application: Box<QUICKey>,
    },
}

impl Debug for KeyBlock {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyBlock::Uninitialed => write!(f, "Uninitialed"),
            KeyBlock::Tls12(_) => write!(f, "Tls12"),
            KeyBlock::Tls13(_) => write!(f, "Tls13"),
            KeyBlock::QUIC { .. } => write!(f, "QUIC"),
        }
    }
}

impl KeyBlock {
    pub fn init(&mut self, quic: bool, typ: KeyType, suite: &'static CipherSuite) {
        match (quic, typ, *suite.version) {
            (false, _, Version::TLS_1_2 | Version::TLCP) => {
                debug_assert!(matches!(self, KeyBlock::Uninitialed));
                *self = KeyBlock::Tls12(Tls12Key::new(suite))
            }
            (false, _, Version::TLS_1_3) => {
                debug_assert!(matches!(self, KeyBlock::Uninitialed));
                *self = KeyBlock::Tls13(Tls13Key::new(suite))
            }
            (true, KeyType::Initial, _) => {
                debug_assert!(matches!(self, KeyBlock::Uninitialed));
                *self = KeyBlock::QUIC {
                    initial: Box::new(QUICKey::new(suite)),
                    handshake: Box::new(QUICKey::new(suite)),
                    application: Box::new(QUICKey::new(suite)),
                }
            }
            (true, KeyType::Handshake, _) => {
                assert!(matches!(self, KeyBlock::QUIC {..}));
                if let KeyBlock::QUIC { handshake, application, .. } = self {
                    handshake.key_size = suite.key_size;
                    handshake.iv_size = suite.fix_iv_size;
                    handshake.hp_key_size = suite.key_size;
                    application.key_size = suite.key_size;
                    application.iv_size = suite.fix_iv_size;
                    application.hp_key_size = suite.key_size;
                }
            }
            (_, _, _) => unreachable!()
        }
    }

    pub fn client_key(&self, typ: KeyType) -> &[u8] {
        match self {
            KeyBlock::Tls12(key) => &key.client_key[..key.mac_size + key.key_size],
            KeyBlock::Tls13(key) => &key.client_key[..key.key_size],
            KeyBlock::QUIC {
                initial,
                handshake,
                application
            } => match typ {
                KeyType::Initial => &initial.client_key[..initial.key_size],
                KeyType::Handshake => &handshake.client_key[..handshake.key_size],
                KeyType::Application => &application.client_key[..application.key_size],
            },
            _ => unreachable!()
        }
    }

    pub fn client_key_mut(&mut self, typ: KeyType) -> &mut [u8] {
        match self {
            KeyBlock::Tls13(key) => &mut key.client_key[..key.key_size],
            KeyBlock::QUIC {
                initial,
                handshake,
                application
            } => match typ {
                KeyType::Initial => &mut initial.client_key[..initial.key_size],
                KeyType::Handshake => &mut handshake.client_key[..handshake.key_size],
                KeyType::Application => &mut application.client_key[..application.key_size],
            },
            _ => unreachable!()
        }
    }

    pub fn server_key(&self, typ: KeyType) -> &[u8] {
        match self {
            KeyBlock::Tls12(key) => &key.server_key[..key.mac_size + key.key_size],
            KeyBlock::Tls13(key) => &key.server_key[..key.key_size],
            KeyBlock::QUIC {
                initial,
                handshake,
                application
            } => match typ {
                KeyType::Initial => &initial.server_key[..initial.key_size],
                KeyType::Handshake => &handshake.server_key[..handshake.key_size],
                KeyType::Application => &application.server_key[..application.key_size],
            },
            _ => unreachable!()
        }
    }

    pub fn server_key_mut(&mut self, typ: KeyType) -> &mut [u8] {
        match self {
            KeyBlock::Tls13(key) => &mut key.server_key[..key.key_size],
            KeyBlock::QUIC {
                initial,
                handshake,
                application
            } => match typ {
                KeyType::Initial => &mut initial.server_key[..initial.key_size],
                KeyType::Handshake => &mut handshake.server_key[..handshake.key_size],
                KeyType::Application => &mut application.server_key[..application.key_size],
            },
            _ => unreachable!()
        }
    }

    pub fn client_iv(&self, typ: KeyType) -> &[u8] {
        match self {
            KeyBlock::Tls12(key) => &key.client_iv[..key.iv_size + key.explicit_len],
            KeyBlock::Tls13(key) => &key.client_iv[..key.iv_size],
            KeyBlock::QUIC {
                initial,
                handshake,
                application
            } => match typ {
                KeyType::Initial => &initial.client_iv[..initial.iv_size],
                KeyType::Handshake => &handshake.client_iv[..handshake.iv_size],
                KeyType::Application => &application.client_iv[..application.iv_size],
            },
            _ => unreachable!()
        }
    }

    pub fn client_iv_mut(&mut self, typ: KeyType) -> &mut [u8] {
        match self {
            KeyBlock::Tls13(key) => &mut key.client_iv[..key.iv_size],
            KeyBlock::QUIC {
                initial,
                handshake,
                application
            } => match typ {
                KeyType::Initial => &mut initial.client_iv[..initial.iv_size],
                KeyType::Handshake => &mut handshake.client_iv[..handshake.iv_size],
                KeyType::Application => &mut application.client_iv[..application.iv_size],
            },
            _ => unreachable!()
        }
    }

    pub fn server_iv(&self, typ: KeyType) -> &[u8] {
        match self {
            KeyBlock::Tls12(key) => &key.server_iv[..key.iv_size + key.explicit_len],
            KeyBlock::Tls13(key) => &key.server_iv[..key.iv_size],
            KeyBlock::QUIC {
                initial,
                handshake,
                application
            } => match typ {
                KeyType::Initial => &initial.server_iv[..initial.iv_size],
                KeyType::Handshake => &handshake.server_iv[..handshake.iv_size],
                KeyType::Application => &application.server_iv[..application.iv_size],
            },
            _ => unreachable!()
        }
    }

    pub fn server_iv_mut(&mut self, typ: KeyType) -> &mut [u8] {
        match self {
            KeyBlock::Tls13(key) => &mut key.server_iv[..key.iv_size],
            KeyBlock::QUIC {
                initial,
                handshake,
                application
            } => match typ {
                KeyType::Initial => &mut initial.server_iv[..initial.iv_size],
                KeyType::Handshake => &mut handshake.server_iv[..handshake.iv_size],
                KeyType::Application => &mut application.server_iv[..application.iv_size],
            },
            _ => unreachable!()
        }
    }

    pub fn bufs(&mut self) -> Vec<&mut [u8]> {
        let KeyBlock::Tls12(key) = self else { unreachable!() };
        let (client_iv, explicit) = key.client_iv.split_at_mut(key.iv_size);
        let (client_mac_key, client_key) = key.client_key.split_at_mut(key.mac_size);
        let (server_mac_key, server_key) = key.server_key.split_at_mut(key.mac_size);
        vec![
            client_mac_key,
            server_mac_key,
            &mut client_key[..key.key_size],
            &mut server_key[..key.key_size],
            client_iv,
            &mut key.server_iv[..key.iv_size],
            &mut explicit[..key.explicit_len]
        ]
    }
    #[cfg(feature = "quic")]
    pub fn client_hp_key(&self, typ: KeyType) -> &[u8] {
        match self {
            KeyBlock::QUIC {
                initial,
                handshake,
                application
            } => match typ {
                KeyType::Initial => &initial.client_hp_key[..initial.hp_key_size],
                KeyType::Handshake => &handshake.client_hp_key[..handshake.hp_key_size],
                KeyType::Application => &application.client_hp_key[..application.hp_key_size],
            },
            _ => unreachable!()
        }
    }
    #[cfg(feature = "quic")]
    pub fn client_hp_key_mut(&mut self, typ: KeyType) -> &mut [u8] {
        match self {
            KeyBlock::QUIC {
                initial,
                handshake,
                application
            } => match typ {
                KeyType::Initial => &mut initial.client_hp_key[..initial.hp_key_size],
                KeyType::Handshake => &mut handshake.client_hp_key[..handshake.hp_key_size],
                KeyType::Application => &mut application.client_hp_key[..application.hp_key_size],
            },
            _ => unreachable!()
        }
    }
    #[cfg(feature = "quic")]
    pub fn server_hp_key(&self, typ: KeyType) -> &[u8] {
        match self {
            KeyBlock::QUIC {
                initial,
                handshake,
                application
            } => match typ {
                KeyType::Initial => &initial.server_hp_key[..initial.hp_key_size],
                KeyType::Handshake => &handshake.server_hp_key[..handshake.hp_key_size],
                KeyType::Application => &application.server_hp_key[..application.hp_key_size],
            },
            _ => unreachable!()
        }
    }
    #[cfg(feature = "quic")]
    pub fn server_hp_key_mut(&mut self, typ: KeyType) -> &mut [u8] {
        match self {
            KeyBlock::QUIC {
                initial,
                handshake,
                application
            } => match typ {
                KeyType::Initial => &mut initial.server_hp_key[..initial.hp_key_size],
                KeyType::Handshake => &mut handshake.server_hp_key[..handshake.hp_key_size],
                KeyType::Application => &mut application.server_hp_key[..application.hp_key_size],
            },
            _ => unreachable!()
        }
    }

    pub fn send_key(&self, typ: KeyType, server: bool) -> &[u8] {
        match server {
            true => self.server_key(typ),
            false => self.client_key(typ)
        }
    }

    pub fn send_iv(&self, typ: KeyType, server: bool) -> &[u8] {
        match server {
            true => self.server_iv(typ),
            false => self.client_iv(typ)
        }
    }
    #[cfg(feature = "quic")]
    pub fn send_hp_key(&self, typ: KeyType, server: bool) -> &[u8] {
        match server {
            true => self.server_hp_key(typ),
            false => self.client_hp_key(typ)
        }
    }

    pub fn recv_key(&self, typ: KeyType, server: bool) -> &[u8] {
        match server {
            true => self.client_key(typ),
            false => self.server_key(typ)
        }
    }

    pub fn recv_iv(&self, typ: KeyType, server: bool) -> &[u8] {
        match server {
            true => self.client_iv(typ),
            false => self.server_iv(typ)
        }
    }

    #[cfg(feature = "quic")]
    pub fn recv_hp_key(&self, typ: KeyType, server: bool) -> &[u8] {
        match server {
            true => self.client_hp_key(typ),
            false => self.server_hp_key(typ)
        }
    }
}