use crate::buffer::{CipherDecodeBuffer, CipherEncodeBuffer};
use crate::error::RlsResult;
use crate::message::{QUICFrame, QUICPacket};
use crate::quic::QUICRange;
use crate::suite::iv::Iv;
use crate::{Buf, Buffer, BufferError, Cipher, CipherSuite, CipherType, Connection, PacketType, Reader, TlsSession, Version, WriteExt};
#[cfg(feature = "log")]
use log::trace;
use std::path::PathBuf;
use crate::key::KeyType;

pub struct QUICConnection {
    recv_sample: Cipher,
    send_sample: Cipher,
    conn: Connection,
    recv_nums: QUICRange,
    current: KeyType,
}

impl QUICConnection {
    pub fn new(session: TlsSession, key_log: Option<PathBuf>, verify: bool) -> QUICConnection {
        let mut conn = Connection::new_client(session, key_log, true).with_verify(verify);
        conn.cipher_suite = &CipherSuite::TLS_AES_128_GCM_SHA256;
        conn.version = Version::TLS_1_3;
        QUICConnection {
            conn,
            recv_sample: Cipher::aes_128_ecb(),
            send_sample: Cipher::aes_128_ecb(),
            recv_nums: QUICRange::default(),
            current: KeyType::Initial,
        }
    }


    /// [rfc9001 5.2](https://datatracker.ietf.org/doc/html/rfc9001#name-initial-secrets)
    pub fn make_initial_cipher(&mut self, cid: &Buf<'_>, force: bool) -> RlsResult<()> {
        if !self.conn.recv_cipher.is_null() && !self.conn.send_cipher.is_null() & !force { return Ok(()); }
        //清空现有的handshake bytes
        self.conn.session_bytes.clear();
        if !force { self.conn.derived.init(KeyType::Initial, &CipherSuite::TLS_AES_128_GCM_SHA256); }
        #[cfg(feature = "log")]
        trace!("[QUIC] MakeCipher dcid={:?}", cid);
        self.conn.derived.make_initial_quic_secret(cid.as_ref())?;
        self.conn.derived_key_cipher(KeyType::Initial)?;
        self.make_sample_cipher(KeyType::Initial)?;
        Ok(())
    }

    ///update sample cipher
    pub fn make_sample_cipher(&mut self, typ: KeyType) -> RlsResult<()> {
        println!("{:?}-{:?}-{}", self.conn.cipher_suite, self.current, self.conn.server);
        let cipher = self.get_cipher(self.conn.cipher_suite.cipher());
        self.send_sample = Cipher::new(cipher);
        self.recv_sample = Cipher::new(cipher);
        let shk = self.conn.derived.key_block().send_hp_key(typ, self.conn.server);
        self.send_sample.set_secret_key(shk, None);
        let rhk = self.conn.derived.key_block().recv_hp_key(typ, self.conn.server);
        self.recv_sample.set_secret_key(rhk, None);
        self.current = typ;
        Ok(())
    }

    fn get_cipher(&self, cipher: CipherType) -> CipherType {
        match cipher {
            CipherType::AES_128_GCM => CipherType::AES_128_ECB,
            CipherType::AES_256_GCM => CipherType::AES_256_ECB,
            CipherType::CHACHA20_POLY1305 => CipherType::CHACHA20_POLY1305,
            _ => unreachable!()
        }
    }

    fn init_cipher(&mut self, suite: Option<&'static CipherSuite>, typ: KeyType) -> RlsResult<()> {
        if self.current == typ { return Ok(()); }
        let suite = suite.unwrap_or(self.conn.cipher_suite);
        println!("{:?}>>{:?}; suite={:?}", self.current, typ, suite);
        self.recv_sample = Cipher::new(self.get_cipher(suite.cipher()));
        let rhk = self.conn.derived.key_block().recv_hp_key(typ, self.conn.server);
        self.recv_sample.set_secret_key(rhk, None);
        let rk = self.conn.derived.key_block().recv_key(typ, self.conn.server);
        self.conn.recv_cipher.set_key(rk, &[], suite)?;
        let ri = self.conn.derived.key_block().recv_iv(typ, self.conn.server);
        self.conn.recv_cipher.set_iv(Iv::new(ri, vec![]));
        self.current = typ;
        Ok(())
    }

    ///[rfc9001](https://datatracker.ietf.org/doc/html/rfc9001#name-header-protection-sample)
    pub fn read_message<'a>(&mut self, packet: &mut QUICPacket<'a>, reader: &mut Reader<'a>, buffer: &mut [u8]) -> RlsResult<usize> {
        let sample_offset = packet.pn_offset + 4;
        let sample = &reader.inner()[sample_offset..sample_offset + 16];
        let suite = if packet.flag.packet_type() == PacketType::Initial { Some(&CipherSuite::TLS_AES_128_GCM_SHA256) } else { None };
        let typ = match packet.flag.packet_type() {
            PacketType::Initial => KeyType::Initial,
            PacketType::Handshake => KeyType::Handshake,
            PacketType::Retry => return Err("conn quic retry".into()),
            PacketType::ShortHeader => KeyType::Application
        };
        self.init_cipher(suite, typ)?;
        let mut mask = self.recv_sample.encrypt(sample)?;
        mask.truncate(5);
        packet.decode(&mask, reader).unwrap();
        // println!("{:#?}", packet);
        if buffer.len() < packet.payload.len() {
            return Err(BufferError::CapacityTooSmall {
                needed: packet.payload.len(),
                current: buffer.len(),
                file: file!(),
                line: line!(),
            }.into());
        }
        let buffer = CipherDecodeBuffer::from_quic(packet, buffer)?;


        let len = self.conn.recv_cipher.decrypt(Some(packet.num), buffer).unwrap();
        self.recv_nums.insert(packet.num);
        Ok(len)
    }


    pub fn build_message(&mut self, mut packet: &mut QUICPacket, frames: &mut Vec<QUICFrame<'_>>, buffer: &mut Buffer) -> RlsResult<()> {
        if packet.padding_size() != 0 {
            frames.push(QUICFrame::Padding(packet.padding_size()));
        }
        packet.encode()?;
        if packet.len() > 1500 { return Err(BufferError::UdpMsgTooLarge.into()); }
        buffer.write_slice(packet.hdr_raw())?;
        for frame in frames {
            frame.write_to(buffer)?;
        }
        buffer.add_len(16);
        self.make_message(buffer.filled_mut(), &mut packet)?;
        Ok(())
    }


    pub fn make_message<'a>(&mut self, buffer: &mut [u8], packet: &mut QUICPacket<'a>) -> RlsResult<()> {
        let encode_buffer = CipherEncodeBuffer::new_quic(buffer, packet, self.conn.cipher_suite);
        self.conn.send_cipher.encrypt(Some(packet.num), encode_buffer)?;
        let sample = &buffer[packet.pn_offset + 4..packet.pn_offset + 20];
        let mut mask = self.send_sample.encrypt(sample)?;
        mask.truncate(5);
        match packet.flag.is_long_header() {
            true => buffer[0] ^= mask[0] & 0x0f,
            false => buffer[0] ^= mask[0] & 0x1f
        }
        let pn_offset = packet.pn_offset..packet.pn_offset + packet.flag.num_len();
        buffer[pn_offset].iter_mut().enumerate().for_each(|(i, x)| {
            *x ^= mask[i + 1]
        });
        Ok(())
    }

    pub fn tls_conn(&mut self) -> &mut Connection {
        &mut self.conn
    }

    pub fn recv_nums(&self) -> &QUICRange {
        &self.recv_nums
    }

    pub fn recv_nums_mut(&mut self) -> &mut QUICRange {
        &mut self.recv_nums
    }
}


#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::ops::Range;
    use crate::connection::quic::QUICConnection;
    use crate::message::QUICFrame;
    use crate::{Buf, Buffer, KeyExchangeAlg, Message, QUICPacket, Reader, RecordType, TlsSession, Version, WriteExt};

    fn decode(conn: &mut QUICConnection, origin: &[u8], queues: &mut Vec<(usize, u64, Range<usize>)>, bid: u64) -> Buffer {
        let mut reader = Reader::from_slice(origin);
        let mut packet = QUICPacket::from_reader(&mut reader).unwrap();
        let mut rb = Buffer::with_capacity(1500);
        let len = conn.read_message(&mut packet, &mut reader, rb.unfilled()).unwrap();
        let mut reader = Reader::from_slice(&rb.unfilled()[..len]);
        while reader.unread_len() > 0 {
            let frame = QUICFrame::from_reader(&mut reader).unwrap();
            if let QUICFrame::Crypto { offset, value, buf_pos } = frame {
                println!("write: offset={}; len={}; next_offset: {}", offset, value.len(), offset + value.len());
                queues.push((offset, bid, buf_pos))
            }
        }
        rb
    }

    fn merge_buffer(mut queues: Vec<(usize, u64, Range<usize>)>, bufs: HashMap<u64, Buffer>) -> Buffer {
        let mut buffer = Buffer::with_capacity(4096);
        let mut last_offset = 0;
        while !queues.is_empty() {
            let pos = queues.iter().position(|x| x.0 == last_offset).unwrap();
            let (_, bid, pos) = queues.remove(pos);
            let buf = &bufs[&bid];
            last_offset += pos.len();
            buffer.write_slice(buf.slice(pos)).unwrap();
        }
        buffer
    }

    #[test]
    fn test_quic_read() {
        let mut conn = QUICConnection::new(TlsSession::default(), None, true);
        conn.conn.server = true;
        let cid = Buf::Vec(hex::decode("5826e10f9e47274a").unwrap());
        conn.make_initial_cipher(&cid, false).unwrap();
        let mut queues = vec![];
        let mut bufs = HashMap::new();
        let raw = hex::decode("cd00000001085826e10f9e47274a000044d0993ab805680e67b4ea7ae47bc5e56b20d8db153d61b499345f4866e3a0132fc87837f6306c971d0d6d6fdf05c48400d650e7de4a63bbc120056e8d9db3ae75c9132d33e6be90a660dc9b0761af9aa5c559d8ffd8970ce50962000097fc4ca9ddc77b791986574e0126fd2edbd9ca847d44d0bd07f24acd47e36a40c29bb47df3dc67db936417c321f666f752c9614f661da188b6fd08bd4a9fb7b2953d359e56808190d504ab0a716af80a0d3fe8888260e4b47d0a0eeae4180eb8faa737d58f3dd61002439bb72b96cf2ce31abe9e532461c47bcf7140d0999f62dd689aa60c287725f5d459b9342ed75f2b43c8328fd7f67c59bd45aceca52800e131a86c4fd25cf60c6f3fc28ab8bae30bf0842522fccf6bd9a74caf90726d667512a90c0235a55b0a991767195c36dcadd569c67aecad1209e9015f867b52789ba0667c30c9500ccc10cc8cebef6263cd74a051f39ece3468274ec53f0604f207d8ee631cad74d185e262c3133f9af955e7d4bb432069940e1e0159e15ab476ed22f3382efc51450fb28d38370e0626a9070f26be69a7cd40a5e71523b7df30186e87a8de2034974eefaebb5ed8216cec13898bcadba5cf9141b4da2161662302176af658b6aef4e5f1d2a026d69d2f9dffaad2cf79b5f4a7b3aead97ad1fe59b195270ef98aa30ac6022dfc6c33afeb87dd0129e701d7b19f7ccd83e7141bfe15ccd28b2b83fcd39577170e72176220b182f0956b4b7fe22d802491a8403dad869116dded38535edc4450d86e3aa77fe8bc6dde380d3bd3f694b2ef27879c48eb00dbf480aaf798b18e7853b841e519a439511b6e90d870b957b051ac6817947060fac8d6add3218d0af1ccbe36193361b8949b820c30b554e9ca66a48903fc5db703b0c893c761abe0603dbebeb616bc39623848536335c491ab002e5f65990577c33d6ac47433dff60c189470135c07576543ecf1ecb90e6db893489a751df1502891d9b484b1995d322f4da7bdf062f50b5aa9d28d0f4b64fdc2e21778d9ce2944a9bfe2e1eaadac0a79b0026452ecb76b9abc94f6c79f5d9ebc36f9d5294d8ea9d4219b06c1c3dfa8101f36494c32f4b814719408c7bafeaaa66c86bb119b95dda3058a59609c284ed10ef4f5338a50da530583b3e93b8a64929a206b9b4ed1b542726abe4d63e5e9bcd869ffeff32d3e88eb44140149e0d3488a6a70351042f6ff4cb5f501e10178ce2b3a9e34d397918d6cbb8a41dbea0c9cdafa8a033db3335180539e115e8b4a66f5fc3638a9d0f95cedcfb2188aaff600e32a6ed418d01f89cf83ed92e0bef3dbd3e520c7e4811519edb437cc202ea83e089dd21e65cc726f509830ce6cc43b9055525e2e92d1b7859681172f6c89b9e9034d1880f7a9b879959ed493bd28cfc65b669498339b31c4728a06de924710f8a81b9a16dc9d45873ae200285ef71ff6f07a5ee30f93d04ac47a2f40676dce6d45b32aedc8abc0216e4c20a53821f74114a51bb1a79e77c972aab80e52ae2a0724979961d70c653003a07b03e062550cf8feddde9285066632a6b5932d4812e2473c362e0bc08e4246dd151e6aba41fb6cc80038f8a1c869cfff0f3de9d809446eae5a680185d87c0a1cc9875cc144ea31a4bd02af8eb6bb5315749def35756565400ae1cf6e470c6fb06a8927b8f2c8ccef65dd7cfdf8a3eef96f284018d823e25c4bf27137d0104f32358c8c975072d8f24b7d429232fe6").unwrap();
        let b1 = decode(&mut conn, &raw, &mut queues, 0);
        bufs.insert(0, b1);
        let raw = hex::decode("cb00000001085826e10f9e47274a000044d0fdb52b1c8728b1a687358c3ed724bc67189882df3bb76fb9c1e1cf249433aff4beda350240e1fabf4efdf22395513bc28b600f5ba155abdf67d4f90a7b3d69d171bb2da686e9ac332cdac5d45ea67488be0f5ff2b4c176df8d768bf8c2e6450c418d3afd10b0be1f11dc997bd08df624af805cddb04cc7822969e990898563d31f705ac2ddea429dd9c65bba723fef31b2ef2f51c06377ebeb16b0278ceb966db689b87135c8e2dba2f40309420a80b380c785d1c0e652b1fc501d5a7851a8ea51cbc2f10b9f4457719b5eaee3dd928ee534334021cbd980c4215e56696de2e2fde43a7b5e209447d96eabeac51e01cd4a5f0a6bf9f502943de809530e8fd8a33bf9faf02824ba58ebfa23dd9c6018dd52f171b792b3b888a3b2a8ca8bd0cc7e18cc24dcfedd84f412b8fccee1e9f75bed4bae7bf4ad4fd48291c2e09ae10179d788351a0758d43251fe6c66acd2f755e8306d8a9272a72010883e1b2ec2fb07e8c10195a97e9feece483d13ac471edda5414c54cdf086d78d2491e79f97168d37e487f08e135ec4f9f4a152dd04f6cdc3251a59e51a87949caaf337e71d98acf44dff1f7f77571de6fd6a74562056ab6d35fd93472396b52025a3a475ece9b00331c3095a0ce165c4c37740491692f462e28c0909c1435c837c9e5efe7483bd35a1f56672c170d861d12cf6e44c6ae5979721bb3971993dc33867eca840acd3f8d6bc11b7db82a9285145b720c22bef8107e2c32dd5d45cf2319f29590ce573881147e413a5a5b694cdb64b6fb4899f71f97b21e14d9d0065bd3ef0376c58bfaddc9ecd239ae293d682cd47e6a0f27734ac5ef873722558f15f3cdd57afd33a5fb8c03611920ab8f6fa691da592ac7beddf13b4304e689a2254e4a5407f07d8b6a612c0e0b40e66d7a0107a8ed5c1bc53507e2cfed9ada69ed934b8f3d8256933efd31ec07158f63aff6a52a64bd41a95c198fbb84073df89939f11cd956181a1f51627583e2755091969cbfbf4b2181700f92a364c25ad2cc223a20f4b1cc30b8305f270675eef98ce323b80aa6ec282ec3e0d4e04e310b25b1624c2f8fcfea771f0154bb9fbf46c7bd3ddf359f23cee5749e95bfce2d193238207abffb43564ba11095b1a9ea64f6207086733ba167bc5db0b5410a0fef767d7052d4f482f669a302dd03a2dafafd66732c2741c56715ec886240af13b8537fc758ce1656c1e8c10f588d6640b082c41bb313dc66abec77bf8fb905adb2dfd62f06c5f6d65995306864d70f523c20873d6aff5217d67c49fdf1de75563e4ba2bae2a1f8ccd1a613fa816b8939e26e7b4521188283abd10482f518b3a8712cafff80c219557c2398cc6c6dc84b33402c83df70b80bfefab79c096252e09fa1775b37ccbf0fc634ba4899d6e7e71581b8cbe8a49236f8e9e83b2673adfb874a4eafe7df8b7dccf553f0c37063c0207fe5a8c0242352bb454ece4c5afefdb6905d5537ef759ed20a7938ce0cb8617b1906df509862fe850a9644da74c0fd8a21683919e9e7d8ef4bdd047a9f1d1be63131bc2a323813d5fa726bb554c83214d33390213a6ab6cb20902183212e0680ced3e63be01ccd45c2c33d5f6b896994e43c6f0c633b13a1b28fbc5b2aa96a09edb19ad7a25971b960f1846283e6624fa4bfa845087621260a17a0fbae1a197b2b0967c014682288d26a566f09f9e0baf380de8612b16af49eb8a2fbf7b0762e9c1da958269e703").unwrap();
        let b2 = decode(&mut conn, &raw, &mut queues, 1);
        bufs.insert(1, b2);
        let mut buffer = merge_buffer(queues, bufs);
        let mut reader = Reader::from_slice(buffer.filled());


        let message = Message::from_reader(&mut reader, &RecordType::HandShake, KeyExchangeAlg::NULL, &Version::TLS_1_3);
        assert!(message.is_ok());
        buffer.used_empty(reader.position());
        assert!(buffer.is_empty());

        let mut conn = QUICConnection::new(TlsSession::default(), None, true);
        let cid = Buf::Vec(hex::decode("5826e10f9e47274a").unwrap());
        conn.make_initial_cipher(&cid, false).unwrap();
        let mut queues = vec![];
        let mut bufs = HashMap::new();
        let raw = hex::decode("c900000001000818c8588d0880882d004016b3948a9a3e9b16341cb4b0b03d2b36554573afe3f81f").unwrap();
        let b1 = decode(&mut conn, &raw, &mut queues, 0);
        bufs.insert(0, b1);
        let raw = hex::decode("c700000001000818c8588d0880882d0044d043aa4376713503d55285c2b88e98e965b0ddfe5bc7dad2bbbb98af0a91624b8cbcd6d88868d62a08f522ca1cb228fe813b902630a6b53db2e18288c16ce6f47ff3f8c9945323861db59a5af47d831cca13ac1b3b45cdaab3eb6d769be80db08ed859e1c6a3f1f3820ab46be7982444abf84b1e3131ffeda5be050d9caf65b60fc4c8953e71d568cbf2f09cdacde8ba6a98d9839f362dac89e9273b714b520a3bf191d8636337760276ca488284bdcc52b827a3e639622eec936c4d4952a89dbdf26098d196c6cc5812987ac8620c378e49ca88cc16fb941aaf45ea72daad5bd3744719440086f93e28cd8ba95f4ba6d63bc2e5a0fd35dc90f9c98b512996f884b61e3557f111a80c0ddfeb681ebb83d47436fdd72a53c8deca490991dc674309a208db8dabdb9f31439272a8a1c3da7f7e2b515f6c842c53176ae204caa3c691cd4a3b540fea3f5500998faa1d369478b6b0001d17ec47e0d4bee673352dea22cb451f32f5152727b36e5bc0c6a0df79772bff7b1cb5f435c751143027403f5891934b8d7aff8cb91243f1b23b6ae7a7448f2c3490c0c285b40f812077f12e76d91edae64b98545aff2105411e938739658ca9e11f351f2f1c1ae2ecca69b747103a90c93920d34e4052f9280740b015a583f90d3bcc0d99f7f6b75a100e64c17ab8c0c899baadda676feabddc10854b5123429f7a8322a88f1650f648e684f5c86459ba61c5db24c663900b8eb9b52ce80f7b80e565fb994674b5533105f794fed3dac25ae58f8e82c52945983b391d60ec4a966c6b902ad0a8c262bbfbb3dad5f2df72d04b07b7f337c5e64ab7bd978946363a01aba6ccda3c6748e79be2821991c8bdf179fb6f2c82ba332a874077e02adb777b3484af1f3af55e66d80edfa6b2a065d7b910b8fa5f3fc7d9c55358dbf69daa7ff3675e6412951c096231ffdcfdcacd920e639a66a7ae34623a593cb3426c426cb4a51595e7bf3e34fabe06a16a84354527fd02b3caa7d678168822b40805e251c8e670c3cdf7fcf5bac34fc5e98a2d1c2f25e4d39de93447a33607685271424c83bb8ca4dca7dd12d072e2363a6903dedac1f5ac53f2ef013b6ac56696a43a89c4a6b65ed2a2c10898eb037f8a6e23df8d5ff789a2eb18d6f00e6b92cb6445444739670d5d6cf520802cf28215d081452366c9063b6d0325e07fca73b0e86a52c33a6f80ff0a0b136ad74544d0f80b3337c9d91288bac16954c54848772a0bae735131044cfa40634b2b5e3f60865319ce59d3ee8f6f348515c3b74bc8f89157eb42c1fbe9120983e42654a8f46e78966d2a666e69cd9f96776ad373baf9155fcd24bd247b5db539b9fda168dd0ecfa2346ea9d310ed5e6c7c360aa699026c7209846bd6e59af2419078e7a52d0af3336a9202ffbfdf26646b608cfbd58df91a94d5bf496414095190bbf293d05584fb177904581c3c71a4b09bb004db06771d8dfba7e6e99a69e59a42715434bdc902381bd6cb3b62cf3dfb8e46400403bc1ed65e687363e4f7508637cf150aa5a734bccb9c016fa80103f47c2ae71c7390a5d9a976180c0408980bbf57f62a4bd2c83730902e89aa700bb075cbbe9f99188caf1f4379be07642a5bfe40d990c646a994b4d501e48e528d8e4b872d8f934fb5b268bd9b14f05b7c093e8ae0b1a32e8a05b4b71c452016865f432abcc389faea4748eb748e4d199ba160d26fa2444a9d7ea8d5e5ec4e43e4e5886c").unwrap();
        let b2 = decode(&mut conn, &raw, &mut queues, 1);
        bufs.insert(1, b2);
        let raw = hex::decode("c500000001000818c8588d0880882d0044d095802cc093702a6ace76b4cdd3aa16ad6fc293b831cfeabc0d606a9f54397bc4b139a66b353b47344576d1db0267c2309464342a18c542ccf3f7ed6d9ac939a861bf5968d1ca9a651575295d9b31804f3983bd1d8ab9d4b5aaa17d46d30c35740de8503e3287fe7de6ec6013b6674aa0fb30a1f3638ac065576ae0a34b54aae6b828d488a474515ad89189d5e3830bed63a3a4f291fedf4cc722ca8f584caa8ffe2549c4af1000540d8effbbe930ba45d10a509d2e14ceb535bde805517f7a104e4f3298a83605063ea2572b97a5ca4302e35a613d272d7c156ca6ddafc6f2129911f7590c2a3596a8f7741edf0554239cfbdeec73dc2c0cbea9a0f18d674a2b0a80b62abf26ab5822157187dec9645760ac8f6c278f7da518cd6d97a310fbb1cd233796df62afdb8e957276a30a89859f32b8fdbf41ffe6f21eb38295d20f9edee4f1c874c5886f728c23793bfb16a6325ece4c9bfd10f2d13da29f9e3fce150725ebfa573e55d5b8aedc3a522d825b6a5bfdf8b596785236d78afc12ccb93cbdd765b9679650d79379e1a2b695b58a7c6370e1fb5425b2ed3732c190d0cca4cf80f1c247d884c3f405d9715b57d926b437608894ab30335a8292dbf3b62532b4913d34d7a91328329a3168486774e21a130f5f56abc948f567fad6fe3decbb40d6419dba32ca60d0440113ac2c356aa5fa13c6fcb93fee56559a1a5757b046610ec854097d93fe3dc38f19d24424e4103b327d902951f8b499104682a5966b93fc93aedd32af9ab567bcbc066a05c908d59cf0023f72fb29996f5f24e8984e502d2ec0b2b9afb82aa6b47fe365304655a9c77c50bec1eb181a52ebf685a824968ede171b84d66972c3bd17fde1e9cb7a384c6e54aa3df1918f457ee33bdbcffe88fa4753994dc7cf3a19d3a6de4a2f7470762c47ed930569e2bce6418e1baad8bdc23cfd7b6c9f76c5041dd6519a6adea862fb7ec3db32877af7ab27ec3836c587cf4f297ae60fd24100b5a6ec29b5c0eed2592306881b9ee8a783fbae4d1cbde865cedd50c8baf9867e7782e16c3493f0f81ac055696584dcf80d08062345f80e53203bcf40852ee0326889c9c6c85dc3046c4d10e273e8241af4564b88f853684b5893d1278af579f13e2af02f11ae0bf9dc0cd2bb2cb15cc106e5b96713c1f190bb8d9e04949a339341054806b4540f73348982dfeaff6aebe50a62193de32d8e018394d8b0fa01eadfb83eade55b3df284a1ad372d6e057c6d74c730ace22b4912b6ddcfed4475953ae2011208bb769d0a789f4f9b145a61d8fa8201343fa7a534a854b5d2f3ad730961187124f4a8b4f4db0e5ef772a6c5b9a66f3b827c12c508d7f05d772d468a9886ca4c406126c633bfd408ce8233eecf00567ab0f750232234422d161f059b095d3a7b92d0e0d3ff9404c8417eb18d7c25e0135ea887170569dc6068ddad5731755b7960cc70cd0d920671730f1652e97abb48e888cb7f6102a73d5680ca1a74f1e2439809d727b3c913cb6943f830aac2f4da2cf97de24b976ac6d5ab93b76c564a955b0affbd2c23b1207eede7f58a59cab365cd80fc66c5df2c978284d1028e3c891bd6425980e52ed3951022cc9cfd8c3e0e6ba776c5b5f4884047b7e54d454e45273676902235e6acc40ec2f83c18b938e7581a9665ba7e3ff35444f42a3ae53396921c222550c98ca3b182ef00caa9962eb292690317eb4ded54e43d99b8a82548").unwrap();
        let b3 = decode(&mut conn, &raw, &mut queues, 2);
        bufs.insert(2, b3);

        let mut buffer = merge_buffer(queues, bufs);
        let mut reader = Reader::from_slice(buffer.filled());
        let message = Message::from_reader(&mut reader, &RecordType::HandShake, KeyExchangeAlg::NULL, &Version::TLS_1_3);
        assert!(message.is_ok());
        buffer.used_empty(reader.position());
        assert!(buffer.is_empty())
    }
}