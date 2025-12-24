use reqtls::*;
use crate::error::{HlsError, HlsResult};
use crate::stream::ConnParam;
use std::io::{Read, Write};
use crate::ALPN;

pub struct SyncStream<S> {
    conn: Connection,
    stream: S,
    handshake_finished: bool,
}

impl<S: Read + Write> SyncStream<S> {
    pub fn connect(mut param: ConnParam, mut stream: S) -> HlsResult<SyncStream<S>> {
        let client_random = rand::random::<[u8; 32]>();
        let mut conn = Connection::new(client_random.to_vec());
        let client_hello = &mut param.fingerprint.client_hello;
        client_hello.message.client_mut().ok_or(HlsError::NonePointer)?.set_random(client_random.clone());
        client_hello.message.client_mut().ok_or(HlsError::NonePointer)?.set_server_name(param.url.addr().host());
        client_hello.message.client_mut().ok_or(HlsError::NonePointer)?.set_session_id(rand::random());
        match param.alpn {
            ALPN::Http20 => client_hello.message.client_mut().ok_or(HlsError::NonePointer)?.add_h2_alpn(),
            _ => client_hello.message.client_mut().ok_or(HlsError::NonePointer)?.remove_h2_alpn()
        }
        conn.update_session(&client_hello.message.as_bytes())?;
        stream.write(&client_hello.as_bytes())?;
        stream.flush()?;
        let mut stream = SyncStream {
            stream,
            conn,
            handshake_finished: false,
        };
        while !stream.handshake_finished {
            let record = stream.read_packet()?;
            stream.handle_message(record, &mut param)?;
        }
        let record = stream.read_packet()?;
        // println!("{:#?}", record);
        stream.conn.read_message(record)?;
        Ok(stream)
    }

    pub fn read_packet(&mut self) -> HlsResult<RecordLayer> {
        let mut head = [0; 5];
        let len = self.stream.read(&mut head)?;
        if len == 0 { return Err(HlsError::PeerClosedConnection); }
        if len != 5 { return Err(HlsError::InvalidHeadSize); }
        let mut res = RecordLayer::new();
        res.context_type = RecordType::from_byte(head[0]).ok_or("LayerType Unknown")?;
        res.version = Version::new(u16::from_be_bytes([head[1], head[2]]));
        res.len = u16::from_be_bytes([head[3], head[4]]);

        let mut buffer = Vec::with_capacity(res.len as usize);
        buffer.resize(res.len as usize, 0); //unsafe { buffer.set_len(res.len); }
        let mut index = 0;
        while index < res.len as usize {
            let len = self.stream.read(&mut buffer[index..])?;
            if len == 0 { return Err(HlsError::PeerClosedConnection); }
            index += len;
        }
        if !self.handshake_finished { self.conn.update_session(&buffer)?; }
        res.message = match res.context_type {
            RecordType::HandShake => Message::from_bytes(buffer, self.handshake_finished)?,
            RecordType::ApplicationData => Message::from_bytes(buffer, true)?,
            _ => {
                self.handshake_finished = true;
                Message::CipherSpec
            }
        };
        Ok(res)
    }

    fn handle_message(&mut self, record: RecordLayer, param: &mut ConnParam) -> HlsResult<()> {
        match record.context_type {
            RecordType::CipherSpec => self.handshake_finished = true,
            RecordType::Alert => {}
            RecordType::HandShake => {
                match record.message {
                    Message::ServerHello(v) => self.conn.set_by_server_hello(v),
                    Message::ServerKeyExchange(v) => {
                        // println!("{:#?}", v);
                        self.conn.set_by_exchange_key(v.hellman_param().pub_key().clone(), v.hellman_param().named_curve().clone())
                    }
                    Message::ServerHelloDone(_) => {
                        let keypair = PriKey::new(self.conn.named_curve())?;
                        let client_pub_key = keypair.pub_key();
                        let client_key_exchange = &mut param.fingerprint.client_key_exchange;
                        client_key_exchange.message.client_key_exchange_mut().unwrap().set_pub_key(client_pub_key);
                        self.conn.update_session(client_key_exchange.message.as_bytes())?;
                        self.stream.write(&client_key_exchange.as_bytes())?;
                        self.stream.flush()?;

                        self.stream.write(&param.fingerprint.change_cipher_spec.as_bytes())?;
                        self.stream.flush()?;

                        let share_secret = keypair.diffie_hellman(self.conn.server_pub_key().as_ref())?;
                        let handshake_hash = self.conn.session_hash()?;
                        self.conn.make_cipher(&share_secret, handshake_hash.clone())?;

                        let record_layer = self.conn.make_finish_message(&handshake_hash)?;
                        self.stream.write(&record_layer.as_bytes())?;
                        self.stream.flush()?;
                    }
                    _ => {}
                }
            }
            RecordType::ApplicationData => {}
        }
        Ok(())
    }

    pub fn write_tls(&mut self, buf: &[u8]) -> HlsResult<()> {
        let layer = self.conn.make_message(RecordType::ApplicationData, buf.to_vec())?;
        self.stream.write(&layer.as_bytes())?;
        Ok(())
    }


    pub fn read_tls(&mut self) -> HlsResult<Vec<u8>> {
        let layer = self.read_packet()?;
        let payload = self.conn.read_message(layer)?;
        Ok(payload)
    }

    pub fn flush(&mut self) -> HlsResult<()> {
        self.stream.flush()?;
        Ok(())
    }

    pub fn shutdown(&mut self) -> HlsResult<()> {
        let layer = self.conn.make_message(RecordType::Alert, vec![1, 0])?;
        self.stream.write(&layer.as_bytes())?;
        self.stream.flush()?;
        Ok(())
    }

    pub fn alpn(&self) -> Option<&str> {
        Some(self.conn.alpn()?.value())
    }
}