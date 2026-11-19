use crate::error::HlsResult;
use crate::stream::quic::QUICStream;
use reqtls::quic::{QUICError, QUICFrame};
use std::mem;
use std::ops::{Deref, DerefMut};
#[cfg(feature = "aync")]
use std::pin::Pin;
#[cfg(feature = "aync")]
use std::task::{Context, Poll};
use crate::*;

pub(crate) enum QUICConnState<S> {
    Connecting(Box<QUICStream<S>>),
    Finished,
}

impl<S> QUICConnState<S> {
    pub fn take(&mut self) -> QUICStream<S> {
        match mem::replace(self, QUICConnState::Finished) {
            QUICConnState::Connecting(stream) => *stream,
            QUICConnState::Finished => unreachable!()
        }
    }
}

impl<S> Deref for QUICConnState<S> {
    type Target = QUICStream<S>;
    fn deref(&self) -> &Self::Target {
        match self {
            QUICConnState::Connecting(stream) => stream,
            QUICConnState::Finished => unreachable!(),
        }
    }
}

impl<S> DerefMut for QUICConnState<S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            QUICConnState::Connecting(stream) => stream,
            QUICConnState::Finished => unreachable!(),
        }
    }
}

#[must_use = "do nothing unless `.wait()/.await`"]
pub struct QUICConnect<'a, S> {
    pub(crate) state: QUICConnState<S>,
    pub(crate) config: Config<'a>,
    pub(crate) sent_hello: bool,
    #[cfg(feature = "aync")]
    pub(crate) timeout_reset: bool,
}

impl<'a, S> QUICConnect<'a, S> {
    fn build_client_hello(&mut self, force: bool) -> Result<(), QUICError> {
        let state = self.state.deref_mut();
        state.tls_write_buffer.reset();
        state.conn.make_initial_cipher(force)?;
        let config = self.config.client_mut().ok_or(HandShakeError::MissingClientConfig)?;
        state.build_client_hello(config)?;
        state.tls_write_buffer.used_empty(5);
        Ok(())
    }

    fn initial_retry(&mut self) -> Result<(), QUICError> {
        self.state.crypto_offset = 0;
        self.state.tr_last_offset = 0;
        self.state.udp_read_buffer.reset();
        self.state.packet_offsets.clear();
        self.state.current = PacketType::Initial;
        self.state.tls_write_buffer.reset();
        self.build_client_hello(true)
    }

    fn handshake_finish(&mut self) -> Result<QUICStream<S>, QUICError> {
        let mut stream = self.state.take();
        stream.conn.recv_nums_mut().clear();
        stream.conn.tls_conn().make_cipher(false)?;
        stream.conn.make_sample_cipher(KeyType::Application)?;
        stream.current = PacketType::ShortHeader;
        stream.tls_read_buffer.reset();
        stream.tr_last_offset = 0;
        Ok(stream)
    }

    fn handle_message(&mut self) -> Result<(), QUICError> {
        let state = self.state.deref_mut();
        let mut reader = Reader::from_slice(state.tls_read_buffer.filled());
        let mut read_len = 0;
        while let Ok(message) = Message::from_reader(&mut reader, RecordType::HandShake, KeyExchangeAlg::NULL, Version::TLS_1_3) {
            read_len += message.encoded.len();
            let is_server_hello = message.parsed.server().is_some();
            QUICStream::<S>::handle_handshake(&mut StreamParam {
                handshake_finish: &mut state.handshake_finish,
                encrypted_channel: &mut state.encrypted_channel,
                hello_retrying: &mut state.hello_retrying,
                write_buffer: &mut state.tls_write_buffer,
                conn: state.conn.tls_conn(),
            }, Some(&mut self.config), message, Version::TLS_1_3)?;
            if is_server_hello && !state.hello_retrying {
                self.state.conn.make_sample_cipher(KeyType::Handshake)?;
                self.state.current = PacketType::Handshake;
                self.state.tls_read_buffer.reset();
                self.state.tr_last_offset = 0;
                self.state.crypto_offset = 0;
                return Ok(());
            }
        }
        self.state.tls_read_buffer.used_empty(read_len);
        Ok(())
    }

    pub fn build_crypto(&mut self) -> Result<Buffer, BufferError> {
        let state = self.state.deref_mut();
        let mut writer = state.alloc_buffer();
        let chunks = state.tls_write_buffer.filled().chunks(350);
        let start = state.crypto_offset;
        if state.crypto_offset == 0 { QUICFrame::Ping.write_to(&mut writer)?; }
        for chunk in chunks {
            if writer.len() + chunk.len() > 1210 { break; }
            QUICFrame::Crypto {
                offset: state.crypto_offset,
                value: Buf::new_ref(chunk),
                buf_pos: 0..0,
            }.write_to(&mut writer)?;
            state.crypto_offset += chunk.len();
        }
        state.tls_write_buffer.used_empty(state.crypto_offset - start);
        let num_len = quic::variant_len(self.state.conn.seq);
        if writer.len() + num_len + 16 < 1232 {
            QUICFrame::Padding(1232 - writer.len() - num_len - 16).write_to(&mut writer)?;
        };
        Ok(writer)
    }
}

impl<'a> QUICConnect<'a, std::net::UdpSocket> {
    pub fn wait(mut self) -> HlsResult<QUICStream<std::net::UdpSocket>> {
        if !self.sent_hello {
            self.build_client_hello(false)?;
        }
        loop {
            while !self.state.tls_write_buffer.is_empty() {
                let state = self.state.deref_mut();
                if state.hello_retrying { state.tls_write_buffer.used_empty(5); }
                let flag = QUICFlag::new(state.current);
                let crypto = self.build_crypto()?;
                self.state.send(crypto, flag)?;
            }

            if self.state.handshake_finish { break; }
            let off = self.state.read_next_packet().wait()?;
            if self.state.conn.recv_nums().need_ack() && let Some(ack) = self.state.build_ack(true) {
                self.state.send(ack, QUICFlag::new(PacketType::Handshake))?;
            };
            match self.state.handle_queues(off, &mut Default::default(), |_, _, _, _| Ok(None)) {
                Err(HlsError::QUIC(QUICError::InitialRetry)) => self.initial_retry()?,
                Ok(_) => {}
                Err(e) => return Err(e),
            }
            self.handle_message()?;
        }
        let stream = self.handshake_finish()?;
        Ok(stream)
    }
}

#[cfg(feature = "aync")]
impl<'a> Future for QUICConnect<'a, tokio::net::UdpSocket> {
    type Output = HlsResult<QUICStream<tokio::net::UdpSocket>>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let connector = self.get_mut();
        if !connector.timeout_reset {
            connector.state.timeout.reset_connect();
            connector.timeout_reset = true;
        }
        if !connector.sent_hello {
            if connector.state.tls_write_buffer.is_empty() { connector.build_client_hello(false)?; }
            connector.sent_hello = true;
        }
        loop {
            while !connector.state.udp_write_buffer.is_empty() {
                let state = connector.state.deref_mut();
                let writer = Pin::new(&mut state.socket);
                match writer.poll_send_to(cx, state.udp_write_buffer.filled(), state.addr)? {
                    Poll::Ready(len) => connector.state.udp_write_buffer.used_empty(len),
                    Poll::Pending => {
                        connector.state.timeout.connect_timeout(cx)?;
                        return Poll::Pending;
                    }
                };
            }
            connector.state.udp_write_buffer.reset();
            while !connector.state.tls_write_buffer.is_empty() {
                let state = connector.state.deref_mut();
                if state.hello_retrying { state.tls_write_buffer.used_empty(5); }
                let flag = QUICFlag::new(state.current);
                let buffer = connector.build_crypto()?;
                connector.state.make_message(buffer, flag)?;


                // let mut writer = state.write_crypto(state.current);
                // let pending = Pin::new(&mut writer).poll(cx).is_pending();
                // let chunk_size = writer.chunk_size;
                // state.tls_write_buffer.used_empty(chunk_size);
                if connector.state.poll_send(cx).is_pending() {
                    connector.state.timeout.connect_timeout(cx)?;
                    return Poll::Pending;
                }
            }
            if connector.state.handshake_finish { break; }

            let mut reader = connector.state.read_next_packet();
            let off = match Pin::new(&mut reader).poll(cx)? {
                Poll::Pending => {
                    connector.state.timeout.connect_timeout(cx)?;
                    return Poll::Pending;
                }
                Poll::Ready(off) => off,
            };
            let pending = if connector.state.conn.recv_nums().need_ack() &&
                let Some(ack) = connector.state.build_ack(true) {
                connector.state.make_message(ack, QUICFlag::new(PacketType::Handshake))?;
                // let mut writer = connector.state.send_ack(QUICFlag::new_long(PacketType::Handshake), true);
                connector.state.poll_send(cx).is_pending()
            } else { false };
            match connector.state.handle_queues(off, &mut Default::default(), |_, _, _, _| Ok(None)) {
                Err(HlsError::QUIC(QUICError::InitialRetry)) => connector.initial_retry()?,
                Ok(_) => {}
                Err(e) => return Poll::Ready(Err(e)),
            }
            connector.handle_message()?;
            if pending {
                connector.state.timeout.connect_timeout(cx)?;
                return Poll::Pending;
            }
        }
        let stream = connector.handshake_finish()?;
        Poll::Ready(Ok(stream))
    }
}
