use std::io;
use reqtls::*;
use crate::error::{HlsError, HlsResult};
use crate::stream::ConnParam;
use std::io::{Read, Write};
use crate::{Buffer, ALPN};

pub struct SyncStream<S> {
    conn: Connection,
    stream: S,
    handshake_finished: bool,
    buffer: Buffer,
}

impl<S: Read + Write> SyncStream<S> {
    pub fn connect(mut param: ConnParam, mut stream: S) -> HlsResult<SyncStream<S>> {
        let client_random = rand::random::<[u8; 32]>();
        let mut conn = Connection::new(client_random.to_vec());
        let mut client_hello = RecordLayer::from_bytes(param.fingerprint.client_hello_mut(), false)?;
        client_hello.messages.client_mut().ok_or(HlsError::NonePointer)?.set_random(client_random.clone());
        client_hello.messages.client_mut().ok_or(HlsError::NonePointer)?.set_server_name(param.url.addr().host());
        client_hello.messages.client_mut().ok_or(HlsError::NonePointer)?.set_session_id(rand::random());
        match param.alpn {
            ALPN::Http20 => client_hello.messages.client_mut().ok_or(HlsError::NonePointer)?.add_h2_alpn(),
            _ => client_hello.messages.client_mut().ok_or(HlsError::NonePointer)?.remove_h2_alpn()
        }
        client_hello.messages.client_mut().ok_or(HlsError::NonePointer)?.remove_tls13();
        let bs = client_hello.handshake_bytes();
        conn.update_session(&bs[5..])?;
        stream.write(&bs)?;
        // conn.update_session(&client_hello.message.as_bytes())?;
        // stream.write(&client_hello.as_bytes())?;
        stream.flush()?;
        let mut stream = SyncStream {
            stream,
            conn,
            handshake_finished: false,
            buffer: Buffer::with_capacity(16413),
        };
        while !stream.handshake_finished {
            stream.read_packet()?;
            stream.handle_message(&mut param)?;
        }
        stream.read_packet()?;
        let mut record = RecordLayer::from_bytes(stream.buffer.filled_mut(), stream.handshake_finished)?;
        stream.conn.read_message(&mut record)?;
        Ok(stream)
    }

    pub fn read_packet(&mut self) -> HlsResult<()> {
        self.buffer.reset();
        self.buffer.sync_read_limit(&mut self.stream, 5)?;
        if self.buffer.len() < 5 { return Err(HlsError::InvalidHeadSize)?; }
        let payload_len = u16::from_be_bytes([self.buffer[3], self.buffer[4]]) as usize;
        while self.buffer.len() - 5 < payload_len {
            self.buffer.sync_read_limit(&mut self.stream, payload_len + 5 - self.buffer.len())?;
        }
        if !self.handshake_finished { self.conn.update_session(&self.buffer.filled()[5..])?; }
        let record_type = RecordType::from_byte(self.buffer[0]).ok_or("LayerType Unknown")?;
        if let RecordType::CipherSpec = record_type {
            self.handshake_finished = true;
        }
        Ok(())
    }

    fn handle_message(&mut self, param: &mut ConnParam) -> HlsResult<()> {
        let record = RecordLayer::from_bytes(self.buffer.filled_mut(), self.handshake_finished)?;
        match record.context_type {
            RecordType::CipherSpec => self.handshake_finished = true,
            RecordType::Alert => {}
            RecordType::HandShake => {
                match record.messages {
                    Message::ServerHello(v) => self.conn.set_by_server_hello(v),
                    Message::ServerKeyExchange(v) => {
                        // println!("{:#?}", v);
                        self.conn.set_by_exchange_key(v.hellman_param().pub_key().clone(), v.hellman_param().named_curve().clone())
                    }
                    Message::ServerHelloDone(_) => {
                        let keypair = PriKey::new(self.conn.named_curve())?;
                        let client_pub_key = keypair.pub_key();
                        let mut client_key_exchange = RecordLayer::from_bytes(param.fingerprint.client_key_exchange_mut(), false)?;
                        client_key_exchange.messages.client_key_exchange_mut().unwrap().set_pub_key(client_pub_key);
                        let bs = client_key_exchange.handshake_bytes();
                        self.conn.update_session(&bs[5..])?;
                        self.stream.write(&bs)?;
                        self.stream.flush()?;

                        self.stream.write(&param.fingerprint.change_cipher_spec())?;
                        self.stream.flush()?;
                        let share_secret = keypair.diffie_hellman(self.conn.server_pub_key().as_ref())?;
                        let handshake_hash = self.conn.session_hash()?;
                        self.conn.make_cipher(&share_secret, handshake_hash.clone())?;

                        self.buffer.reset();
                        self.conn.make_finish_message(&handshake_hash, &mut self.buffer[..45])?;
                        self.stream.write(&self.buffer[..45])?;
                        self.stream.flush()?;
                    }
                    _ => {}
                }
            }
            RecordType::ApplicationData => {}
        }
        Ok(())
    }

    // pub fn write_tls(&mut self, buf: &[u8]) -> HlsResult<()> {
    //     let layer = self.conn.make_message(RecordType::ApplicationData, buf.to_vec())?;
    //     self.stream.write(&layer.as_bytes())?;
    //     Ok(())
    // }
    //
    //
    // pub fn read_tls(&mut self) -> HlsResult<Vec<u8>> {
    //     let layer = self.read_packet()?;
    //     let payload = self.conn.read_message(layer)?;
    //     Ok(payload)
    // }
    //
    // pub fn flush(&mut self) -> HlsResult<()> {
    //     self.stream.flush()?;
    //     Ok(())
    // }

    pub fn shutdown(&mut self) -> HlsResult<()> {
        self.buffer.reset();
        self.buffer.set_len(31);
        self.buffer[13..15].copy_from_slice(&[1, 0]);
        self.conn.make_message(RecordType::Alert, &mut self.buffer[..31])?;
        self.stream.write(&self.buffer[..31])?;
        self.stream.flush()?;
        Ok(())
    }

    pub fn alpn(&self) -> Option<&str> {
        Some(self.conn.alpn()?.value())
    }
}

impl<S: Read> Read for SyncStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.buffer.sync_read_limit(&mut self.stream, 5)?;
        let len = u16::from_be_bytes([self.buffer[3], self.buffer[4]]) as usize;
        while self.buffer.len() - 5 < len {
            self.buffer.sync_read_limit(&mut self.stream, len + 5 - self.buffer.len())?;
        }
        let mut record = RecordLayer::from_bytes(self.buffer.filled_mut(), self.handshake_finished)?;
        let rt = record.context_type.as_u8();
        let len = self.conn.read_message(&mut record)?;
        if rt == 0x15 && &self.buffer[13..13 + len] == &[1, 0] {
            return Err(HlsError::PeerClosedConnection.into());
        }
        buf[..len].copy_from_slice(&self.buffer[13..13 + len]);
        self.buffer.reset();
        Ok(len)
    }
}


impl<S: Write> Write for SyncStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut sent = 0;
        for chunk in buf.chunks(16384) {
            self.buffer.reset();
            let len = 13 + chunk.len() + 16;
            self.buffer.push_slice_in(13, chunk);
            self.conn.make_message(RecordType::ApplicationData, &mut self.buffer[..len])?;
            self.stream.write(&self.buffer[..len])?;
            sent += len;
        }
        Ok(sent)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}