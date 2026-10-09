use crate::config::{ClientConfig, Config};
use crate::error::RlsResult;
use crate::*;
#[cfg(feature = "log")]
use log::debug;
#[cfg(all(debug_assertions, feature = "log"))]
use log::{trace, warn};
use crate::finger::RecordParam;

pub struct StreamParam<'a> {
    pub handshake_finish: &'a mut bool,
    pub encrypted_channel: &'a mut bool,
    pub hello_retrying: &'a mut bool,
    pub write_buffer: &'a mut Writer,
    pub conn: &'a mut Connection,
}

pub trait StreamHandle {
    const CHANGE_CIPHER_SPEC: [u8; 6] = [20, 3, 3, 0, 1, 1];

    fn stream_param(&mut self) -> (&Writer, StreamParam<'_>);

    fn build_client_hello(&mut self, config: &ClientConfig) -> RlsResult<()> {
        let (_, param) = self.stream_param();
        let mut record_param = RecordParam::from(config);
        record_param.writer = param.write_buffer;
        record_param.conn = param.conn;
        config.fingerprint.build_client_hello(record_param)?;
        param.conn.update_session(&param.write_buffer.filled()[5..])?;
        Ok(())
    }

    /// 处理ServerHello，当为HelloRetry时准备新的ClientHello
    /// * `param` - 流参数
    /// * `server_hello` - 已解析的结构
    /// * 返回是否为hello_retry
    fn handle_server_hello(param: &mut StreamParam<'_>, config: &ClientConfig, version: Version, server_hello: ServerHello) -> Result<bool, RlsError> {
        let hello_retry = param.conn.set_by_server_hello(&server_hello, version)?;
        if hello_retry {
            #[cfg(feature = "log")]
            debug!("[ParsingServerHello] hello_retry=true; retry_share={:?}", param.conn.named_curve());
            let server_entries = [KeyEntry::new(param.conn.named_curve())];
            let mut record_param = RecordParam::from(config);
            record_param.writer = param.write_buffer;
            record_param.conn = param.conn;
            record_param.entries_count = server_entries.len();
            record_param.entries = server_entries.as_ptr();
            record_param.hrr = true;
            config.fingerprint.build_client_hello(record_param)?;
            param.conn.hello_retry(&param.write_buffer.filled()[5..])?;
            *param.hello_retrying = true;
            return Ok(true);
        }
        *param.hello_retrying = false;
        Ok(false)
    }

    fn handle_server_hello_done(param: &mut StreamParam<'_>, config: &mut ClientConfig) -> Result<(), RlsError> {
        let offset = param.write_buffer.offset().end;
        let kea = param.conn.cipher_suite().exchange_alg();
        if !config.client_cert.is_empty() {
            //client certificate
            let mut certificate = Certificates::default();
            if let Some(cert) = config.client_cert.get_mut(0) {
                certificate.add_certificate(cert.as_der()?.as_slice());
            }
            param.write_buffer.write_u8(RecordType::HandShake.as_u8())?;
            param.write_buffer.write_u16(param.conn.version().into_inner())?;
            param.write_buffer.write_u16(certificate.len() as u16)?;
            param.conn.update_session(param.write_buffer.slice_at(offset + 5))?;
        }
        let offset = param.write_buffer.offset().end;
        //client key exchange
        param.write_buffer.write_u8(RecordType::HandShake.as_u8())?;
        param.write_buffer.write_u16(param.conn.version().into_inner())?;
        let mut client_key_exchange = ClientKeyExchange::default();
        let pub_key = param.conn.pub_share_key()?;
        client_key_exchange.set_pub_key(pub_key.as_ref());
        param.write_buffer.write_u16(client_key_exchange.len(kea) as u16)?;
        client_key_exchange.write_to(param.write_buffer, kea)?;

        param.conn.update_session(param.write_buffer.slice_at(offset + 5))?;
        param.conn.make_cipher(false)?;
        //certificate verify
        if !config.client_cert.is_empty() && !config.client_cert.is_empty() {
            let offset = param.write_buffer.len();
            param.conn.handle_mtls_client(param.write_buffer, config.cert_key)?;
            param.conn.update_session(param.write_buffer.slice_at(offset + 5))?;
        }
        //change_cipher_spec
        param.write_buffer.write_u8(20)?;
        param.write_buffer.write_u16(param.conn.version().inner())?;
        param.write_buffer.write_u8(0)?;
        param.write_buffer.write_u8(1)?;
        param.write_buffer.write_u8(1)?;
        //finish
        let record_len = param.conn.make_finish_message(param.write_buffer.unfilled(), false)?;
        param.write_buffer.add_len(record_len);
        Ok(())
    }

    fn handle_by_alert(&mut self) -> Result<Alert, RlsError> {
        let (read_buffer, param) = self.stream_param();
        match param.encrypted_channel {
            true => {
                let len = param.conn.read_message(read_buffer.filled(), param.write_buffer.unfilled())?;
                Ok(Alert::from_bytes(&param.write_buffer.unfilled()[..len])?)
            }
            false => Ok(Alert::from_bytes(&read_buffer.filled()[5..7])?)
        }
    }

    fn handle_finish(param: &mut StreamParam<'_>) -> Result<(), RlsError> {
        if param.conn.server() && param.conn.version() == Version::TLS_1_2 {
            let offset = param.write_buffer.offset().end;
            let tbs = rand::random::<[u8; 276]>();
            let ticket = SessionTicket::new(3600, tbs.as_ref());
            param.write_buffer.write_slice(&[22, 3, 3])?;
            param.write_buffer.write_u16((ticket.len() + 1) as u16)?;
            param.write_buffer.write_u8(HandshakeType::NewSessionTicket.into_inner())?;
            ticket.write_to(param.write_buffer)?;
            param.conn.update_session(param.write_buffer.slice_at(offset + 5))?;
        }
        if (param.conn.certs().is_empty()) || param.conn.server() {
            #[cfg(feature = "log")]
            debug!("[HandleRecord] Recover TLS_1.2");
            param.write_buffer.write_slice(&Self::CHANGE_CIPHER_SPEC)?;
            let len = param.conn.make_finish_message(param.write_buffer.unfilled(), param.conn.server())?;
            param.write_buffer.add_len(len);
            *param.handshake_finish = true;
        }
        Ok(())
    }

    fn handle_handshake(param: &mut StreamParam<'_>, mut config: Option<&mut Config<'_>>, message: Message<'_>, version: Version) -> RlsResult<()> {
        #[cfg(all(debug_assertions, feature = "log"))]
        trace!("[HandleHandshake] message: {:?}]", message);
        match message.parsed {
            MessageParsed::ServerHello(server_hello) => {
                param.conn.update_session(message.encoded.as_ref())?;
                let config = config.as_mut().and_then(|x| x.client_mut())
                    .ok_or(HandShakeError::MissingClientConfig)?;
                let hello_retry = Self::handle_server_hello(param, config, version, server_hello)?;
                if hello_retry { return Ok(()); }
            }
            MessageParsed::Certificate(v) => {
                param.conn.update_session(message.encoded.as_ref())?;
                let config = config.as_mut().and_then(|x| x.client_mut())
                    .ok_or(HandShakeError::MissingClientConfig)?;
                param.conn.set_by_certificate(v, config.ca_certs, config.sni)?;
            }
            MessageParsed::CertificateStatus(_) => param.conn.update_session(message.encoded.as_ref())?,
            MessageParsed::ServerKeyExchange(v) => {
                param.conn.update_session(message.encoded.as_ref())?;
                param.conn.set_by_server_exchange_key(v)?
            }
            MessageParsed::ServerHelloDone(_) => {
                param.conn.update_session(message.encoded)?;
                let config = config.as_mut().and_then(|x| x.client_mut())
                    .ok_or(HandShakeError::MissingClientConfig)?;
                Self::handle_server_hello_done(param, config)?;
                *param.handshake_finish = true;
                return Ok(());
            }
            MessageParsed::ClientHello(v) => {
                param.conn.update_session(message.encoded.as_ref())?;
                let config = config.as_mut().and_then(|x| x.server_mut())
                    .ok_or(HandShakeError::MissingClientConfig)?;
                let reader = Reader::from_ptr(v.extensions as *const u8, v.extend_len as usize);
                param.conn.handle_extension(reader)?;
                param.conn.handle_client_hello(param.write_buffer, config, v)?;
                // Self::handle_client_hello(param, config, &v)?;
                return Ok(());
            }
            MessageParsed::ClientKeyExchange(v) => {
                param.conn.update_session(message.encoded.as_ref())?;
                param.conn.set_by_client_exchange_key(v);
                param.conn.make_cipher(false)?;
            }
            MessageParsed::CertificateRequest(v) => {
                param.conn.update_session(message.encoded.as_ref())?;
                let config = config.as_mut().and_then(|x| x.client_mut())
                    .ok_or(HandShakeError::MissingClientConfig)?;
                param.conn.set_by_cert_req(v, config.client_cert.first_mut())?;
            }
            MessageParsed::NewSessionTicket(ticket) => {
                param.conn.update_session(message.encoded.as_ref())?;
                param.conn.set_by_session_ticket(ticket)
            }
            MessageParsed::Finished(_) => {
                param.conn.verify_finish(message.encoded.as_ref(), true)?;
                *param.handshake_finish = true;
                if !(param.conn.version() == Version::TLS_1_3 && param.conn.server()) {
                    if !param.conn.derived.quic { param.write_buffer.write_slice(&Self::CHANGE_CIPHER_SPEC)?; }
                    let len = param.conn.make_finish_message(param.write_buffer.unfilled(), false)?;
                    param.write_buffer.add_len(len);
                }
            }
            MessageParsed::EncryptedExtension(ee) => {
                param.conn.handle_extension(Reader::from_ptr(ee.extension as *const u8, ee.ext_len as usize))?;
                param.conn.update_session(message.encoded.as_ref())?;
            }
            MessageParsed::CompressedCertificate(cc) => {
                let config = config.as_mut().and_then(|x| x.client_mut())
                    .ok_or(HandShakeError::MissingClientConfig)?;
                param.conn.set_by_compressed_certificate(cc, config.ca_certs, config.sni)?;
                param.conn.update_session(message.encoded.as_ref())?;
            }
            MessageParsed::CertificateVerify(verify) => {
                param.conn.verify_cert(verify, true)?;
                param.conn.update_session(message.encoded.as_ref())?;
            }
            _ => {
                #[cfg(all(debug_assertions, feature = "log"))]
                warn!("unhandled message: {:?}", message);
            }
        }
        Ok(())
    }


    fn handle_record(&mut self, record_len: usize, mut config: Option<&mut Config<'_>>, app_buf: &mut [u8]) -> Result<usize, RlsError> {
        let (read_buffer, mut param) = self.stream_param();
        let record = RecordLayer::from_bytes(read_buffer.filled(), param.conn.cipher_suite().exchange_alg(), *param.encrypted_channel)?;
        match record.content_type {
            RecordType::CipherSpec => {
                #[cfg(all(debug_assertions, feature = "log"))]
                trace!("[HandleRecord] {:?}", record);
                *param.encrypted_channel = !*param.hello_retrying;
                if param.conn.certs().is_empty() && param.conn.version() == Version::TLS_1_2 {
                    param.conn.make_cipher(true)?;
                }
            }
            RecordType::Alert => {
                #[cfg(all(debug_assertions, feature = "log"))]
                trace!("[HandleRecord] {:?}", record);
                return Err(RlsError::Alert(self.handle_by_alert()?));
            }
            RecordType::HandShake => match *param.encrypted_channel {
                true => {
                    #[cfg(all(debug_assertions, feature = "log"))]
                    trace!("[HandleRecord] {:?}", record);
                    let out = param.write_buffer.unfilled();
                    let len = param.conn.read_message(&read_buffer.filled()[..record_len], out)?;
                    param.conn.verify_finish(&out[..len], !param.conn.server())?;
                    Self::handle_finish(&mut param)?;
                }
                false => for message in record.messages {
                    Self::handle_handshake(&mut param, config.as_deref_mut(), message, record.version)?
                }
            }
            RecordType::ApplicationData => {
                #[cfg(all(debug_assertions, feature = "log"))]
                trace!("[HandleRecord] {:?}", record);
                return self.handle_by_application(record_len, config, app_buf);
            }
        }
        Ok(0)
    }


    fn handle_by_application(&mut self, record_len: usize, mut config: Option<&mut Config>, app_buf: &mut [u8]) -> Result<usize, RlsError> {
        let (read_buffer, mut param) = self.stream_param();
        let len = match param.conn.version() {
            Version::TLS_1_3 => {
                let len = param.conn.read_message(&read_buffer.filled()[..record_len], app_buf)?;
                let record_type = RecordType::from_byte(app_buf[len - 1])?;
                match record_type {
                    RecordType::Alert => return Err(RlsError::Alert(Alert::from_bytes(&app_buf[..len - 1])?)),
                    RecordType::HandShake => {
                        let mut msg_readers = Reader::from_slice(&app_buf[..len - 1]);
                        while msg_readers.unread_len() > 0 {
                            let message = Message::from_reader(&mut msg_readers, &record_type, param.conn.cipher_suite().exchange_alg(), param.conn.version())?;
                            Self::handle_handshake(&mut param, config.as_deref_mut(), message, Version::TLS_1_3)?;
                        }
                        0
                    }
                    RecordType::CipherSpec => {
                        *param.encrypted_channel = true;
                        0
                    }
                    RecordType::ApplicationData => len - 1
                }
            }
            _ => param.conn.read_message(&read_buffer.filled()[..record_len], app_buf)?
        };
        Ok(len)
    }
}