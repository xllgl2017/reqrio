use super::record::RecordLayer;
use crate::cipher::suite::CipherSuite;
use crate::error::{RlsError, RlsResult};
use crate::extend::formats::EcPointFormat;
use crate::extend::group::GroupType;
use crate::extend::{Extension, ExtensionType};
use crate::version::Version;

#[derive(Debug, Clone)]
pub struct Fingerprint {
    client_hello: Vec<u8>,
    client_key_exchange: Vec<u8>,
    change_cipher_spec: Vec<u8>,
}

impl Fingerprint {
    fn new() -> Fingerprint {
        Fingerprint {
            client_hello: vec![],
            client_key_exchange: vec![],
            change_cipher_spec: vec![],
        }
    }

    pub fn default() -> RlsResult<Fingerprint> {
        let default = "16030107120100070e030348853c3196bf1baa176acac0b0fe608e384f64a48cb9d16eb17c52dfb9a73bd3201a5e217537bc3af3e314e4d89639ba76ce25114009dc2c2235660730c4e3899a0020dada130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010006a51a1a0000002d00020101000b00020100000500050100000000003304ef04edfafa00010011ec04c0c399b44b802ea789831e2625ebd68a136b713e80a50233a22dbc8002a6aab07ba3afd935e2f315ddb72dfa4a94f75a7494da759b03780f558a3d0a0608a38d8af2122d1ccca3a9121b5387e9da46d913b539b0c9d6b4a68a9a15f825892b26ce70815b159a7dee77ab7ea5b4fd30b9f202818ba6c7551a65f011654307b334716e667651c4e7a2a5e14ff43b271fe627273246268628157b641a62751e30b263657f160868d8d7b8095439d97941759874943c6a12da92b7d146e4e870a4e90541a23b7c5ab1c6448f7188563a097c5f78a349073737d7a37cdb08bcb09ca6dc31b4229260d88a93c7a948411e7da3b309c41987771bf8c71151aa9bc4369f1515463587c42387bb48c52846491b1d9227c0686fa1549246f44424aa258e443b431096ec2ccd377a88e24c98229236fa016bab815466c40eeae134ca77704348a2b6627cbed551d1ea0daf635206d425f600c73edc4b98c02bdf0b5efc7b73ce75a2924043e2436c944771630259f0516b30b529a64062b3098dc8343852e598887c88dbaa0b2c709b1a58941916ba4edb9caec90eb6f930f9da5cb58bb855862b59263eeda31d2a06a89763b838d10f6a0c3199c1b10bcc9d1549b0e860a1f0901698c350b7eb5e86104ff631361fd6beec2c77806362833c2efa3063810c86faa7b5ab92389eab258320265fb23f0d7a2b3a9aad03c94604cb43d532376314b2e8d4cfedda36b578b590e6146ea18c6847a0569c8318a68620f294e9d9875d014549695bd3ca68c430577092a375ac3a37203a0336c1e134b45af2548bccc8ce075e4e74a370f16d4bcbc90c8cb42ed09b5dd05c620528d9dac66833bc02e7734967c6a7cc4bebe95b85d7275b976c9ac0997eb264a0a684d4279512054a3258a39e604f1ec148ca2130d29a1ab92b53c1b0ab4ee3805f339201e968847b78739175fd695181b7a7ce500bd31a0685926e04d5ce6d2b612845ba68d39f617c21afa75f26bca95c17507698af280c0c5f21890ab78a8e56b1e94509b226066624a7c6701c3ae461c54161e7d5760279acc167cc01908b7d4a19576459e9b6276ce2c791990851fb9f8b197cf0c96de1fb61cd1c13c222c5194182edc4695e295d54a506fa09b0881169a6f32a8afc0acd5644876b5e698105f36a56a16aaf49041ea34a92619969b983025d585ee6f1bcfa131e995431b2b3a68b514534a599af1c13ad095d38cb458a1a8ac7f51524503166a63cf6d8963aa89a20c37013984672f79a9be13f93719d89e765a82a4775d531b3ebcb8b4c2935510ba6a770bc10a8a4ec60f01a9a20250050d96c535454f5b69b8cf8c00c44790f3964a1f4b2fabc5a85f061348c89e3ba1797c0c26bf3bbcad70d93822f932a18ca7ca0cf866c6b1b4de2571606f01eb2e5ab3be719c91370f29363a218aacf40284dc6c3c59671df4b62d5e44e81039c3498248a7659f0074996533e8097a0aee389a6d9ae9364b3a64bcf4e576f67802b89943ae03a24d2772726887f5fc803933111d4aa35da30a78b560bb4ec2dc918a3998281f046093f897919078ebdf05ec7f7ce03311a79bc49cb537322e8c6a6abbe56a55f6e1555e384ba6fa9c4f8e0189d3650c26aee67cbe704d7465022c259b6534361651c9b6d71fc98e18f84ff8aa1f3e880bcdbd8eddd440e3d7e99580bd9bc7f83f444daa761442c1a625dc5d44da361001d0020afa0c21e9ab34f115732ecb8e6b5d83379c4660811738d8be560cafde446fd0b0000000e000c0000093338686d7a672e636e002b0007064a4a03040303000a000c000afafa11ec001d0017001800230000001b000302000244690005000302683200170000fe0d011a0000010001960020cb3de92f31efcfcd5a53c79fbe3200c1f481e37199aa290649f1abad6ed5031e00f0dcb724c041356d77ecf7cf213696ee291b549ee48b028251d6ddde9865586ea997acd0a5210799395fd9682738cf609dd99a9c829efbc5ba83ffc2d8932b551886b5c1ebc1ac1233273e5ccfe8fa1e50fb0812f05f0fcb607672a934c778acc998173d746e8672f2aa6b60efa66369ffd7c03b9d7dcf3fc3f0cdb255347d8394dae22615b14c5ff626fa8e65b5d93278da980f307f21af1a124cab78db6d41d1cfe69d7f1ab90038f7d209f85e7d7d5ad045a2ca484569320dcae3f33b163992f0e68268899d3dabdb83f3177f115f97d165ba545ef9c193a16abc8ad3b24d458af544fb553218136e8dfa1230aa000c0010000e000c02683208687474702f312e3100120000000d0012001004030804040105030805050108060601ff01000100eaea0001001603030046100000424104ff635373fbbfbc37444a2026372f57fd06c5205bacfe32b61261a9d29bf1fca57f91ef22cb2ba46af8cf9ae7c3123f56634099af297dcd30835cd81664005fb9140303000101";
        Fingerprint::from_hex_all(default)
    }

    pub fn from_hex_all(hex_str: impl AsRef<str>) -> RlsResult<Fingerprint> {
        let mut data = hex::decode(hex_str.as_ref())?;
        let mut res = Fingerprint::new();
        let len = u16::from_be_bytes([data[3], data[4]]);
        let client_hello = data.drain(..len as usize + 5).collect::<Vec<u8>>();
        res.client_hello = client_hello; //RecordLayer::from_bytes(&mut client_hello, false)?;
        let len = u16::from_be_bytes([data[3], data[4]]);
        let client_key_exchange = data.drain(..len as usize + 5).collect::<Vec<u8>>();

        let len = u16::from_be_bytes([data[3], data[4]]);
        let change_cipher_spec = data.drain(..len as usize + 5).collect::<Vec<u8>>();
        res.change_cipher_spec = change_cipher_spec; //RecordLayer::from_bytes(&mut change_cipher_spec, false)?;
        if client_key_exchange.len() == 6 {
            res.change_cipher_spec = res.client_key_exchange;
            res.client_key_exchange = hex::decode("1603030046100000424104ff635373fbbfbc37444a2026372f57fd06c5205bacfe32b61261a9d29bf1fca57f91ef22cb2ba46af8cf9ae7c3123f56634099af297dcd30835cd81664005fb9")?;
        } else {
            res.client_key_exchange = client_key_exchange;
        }
        Ok(res)
    }

    pub fn from_ja3(ja3: impl AsRef<str>) -> RlsResult<Fingerprint> {
        let mut res = Fingerprint::default()?;
        res.set_ja3(ja3)?;
        Ok(res)
    }

    pub fn from_ja4(ja4: impl AsRef<str>) -> RlsResult<Fingerprint> {
        let mut res = Fingerprint::default()?;
        res.set_ja4(ja4)?;
        Ok(res)
    }

    pub fn set_ja3(&mut self, ja3: impl AsRef<str>) -> RlsResult<()> {
        let mut record = RecordLayer::new();
        let client_hello = record.message.client_mut().ok_or(RlsError::ClientHelloNone)?;
        let mut items = ja3.as_ref().split(",");
        let version = items.next().ok_or("version not found")?.parse::<u16>()?;
        client_hello.set_version(Version::new(version));
        let mut cipher_suites = vec![];
        let suites = items.next().ok_or("suites not found")?.split("-");
        for suite in suites {
            cipher_suites.push(CipherSuite::new(suite.parse()?));
        }
        client_hello.set_cipher_suites(cipher_suites);
        let mut extensions = vec![];
        let exts = items.next().ok_or("exts not found")?.split("-");
        for ext in exts {
            let extend = Extension::from_type(ExtensionType::new(ext.parse()?));
            extensions.push(extend);
        }
        let groups = extensions.iter_mut().find(|x| x.supported_groups().is_some()).ok_or("group not found")?;
        let groups = groups.supported_groups_mut().ok_or("group not found")?;
        let gps = items.next().ok_or("groups not found")?.split("-");
        for kid in gps {
            groups.add_group(GroupType::new(kid.parse()?));
        }
        let fts = items.next().ok_or("fts not found")?.split("-");
        let formats = extensions.iter_mut().find(|x| x.ex_point_formats().is_some()).ok_or("ec format not found")?;
        let formats = formats.ex_point_formats_mut().ok_or("ec format not found")?;
        for ft in fts {
            formats.add_format(EcPointFormat::from_u8(ft.parse()?).unwrap());
        }
        client_hello.set_extension(extensions);
        self.client_hello = record.handshake_bytes();
        Ok(())
    }

    pub fn set_ja4(&mut self, ja4: impl AsRef<str>) -> RlsResult<()> {
        let mut record = RecordLayer::new();
        let client_hello = record.message.client_mut().ok_or(RlsError::ClientHelloNone)?;
        let mut items = ja4.as_ref().split(",");
        let version = items.next().ok_or("version not found")?.parse::<u16>()?;
        client_hello.set_version(Version::new(version));
        self.client_hello = record.handshake_bytes();
        Ok(())
    }

    pub fn client_hello_mut(&mut self) -> &mut [u8] { &mut self.client_hello }

    pub fn client_key_exchange_mut(&mut self) -> &mut [u8] { &mut self.client_key_exchange }

    pub fn change_cipher_spec(&self) -> &[u8] { &self.change_cipher_spec }
}