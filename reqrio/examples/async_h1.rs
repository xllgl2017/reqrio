use reqrio::*;
use std::fmt::{Debug, Formatter};
use std::marker::PhantomData;
use std::os::raw::c_int;
use std::{fs, slice};

#[cfg(feature = "log")]
const LOGER: Logger = Logger {
    module: &[],
    debug_file: None,
    info_file: None,
    warn_file: None,
    error_file: None,
    out_file: None,
};

#[cfg(feature = "log")]
fn test_log() {
    set_logger(&LOGER).unwrap();
    set_max_level(LevelFilter::Trace);
}

#[repr(C)]
#[derive(Default)]
struct Hostname {
    len: u16,
    ptr: *const u8,
}

#[cfg(debug_assertions)]
impl Debug for Hostname {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut struct_debug = f.debug_struct("Hostname");
        struct_debug.field("len", &self.len);
        let slice = unsafe { slice::from_raw_parts(self.ptr, self.len as usize) };
        let hostname = std::str::from_utf8(slice).unwrap_or("");
        struct_debug.field("ptr", &hostname);
        struct_debug.finish()
    }
}

#[repr(C)]
#[derive(Default)]
struct ServerName {
    typ: u8,
    ptr: *const u8,
}


#[repr(C)]
#[derive(Default)]
struct KeyShare {
    len: u16,
    ptr: *const u8,
}

#[cfg(debug_assertions)]
impl Debug for KeyShare {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut struct_debug = f.debug_struct("KeyShare");
        struct_debug.field("len", &self.len);
        let mut entries = vec![];
        let mut reader = Reader::from_ptr(self.ptr, self.len as usize);
        while reader.pos < reader.size {
            let mut entry = KeyEntry::default();
            unsafe { KeyEntry_parse(&mut reader, &mut entry) };
            entries.push(entry);
        }
        struct_debug.field("entries", &entries);
        struct_debug.finish()
    }
}

#[repr(C)]
#[derive(Default)]
struct KeyEntry {
    group: u16,
    key_len: u16,
    key: *const u8,
}

#[cfg(debug_assertions)]
impl Debug for KeyEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut struct_debug = f.debug_struct("KeyEntry");
        struct_debug.field("group", &NamedCurve::new(self.group));
        struct_debug.field("key_len", &self.key_len);
        let slice = unsafe { slice::from_raw_parts(self.key, self.key_len as usize) };
        struct_debug.field("key", &hex::encode(slice));
        struct_debug.finish()
    }
}

#[cfg(debug_assertions)]
impl Debug for ServerName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut debug_struct = f.debug_struct("ServerName");
        debug_struct.field("type", &self.typ);
        if self.typ == 0x0 {
            let mut reader = Reader::from_ptr(self.ptr, usize::MAX);
            let mut hostname = Hostname::default();
            unsafe { Hostname_parse(&mut reader, &mut hostname) };
            debug_struct.field("hostname", &hostname);
        }
        debug_struct.finish()
    }
}

#[repr(C)]
#[derive(Default)]
#[cfg_attr(debug_assertions, derive(Debug))]
struct StatusRequest {
    typ: u8,
    resp_id_len: u16,
    req_ext_len: u16,
}


#[derive(Debug)]
enum ExtensionType {
    ServerName = 0x0,
    StatusRequest = 0x5,
    SupportedGroup = 0xa,
    EcPointFormats = 0xb,
    SignatureAlgorithms = 0xd,
    ApplicationLayerProtocolNegotiation = 0x10,
    SignedCertificateTimestamp = 0x12,
    Padding = 0x15,
    EncryptTheMac = 0x16,
    ExtendMasterSecret = 0x17,
    SessionTicket = 0x23,
    CompressionCertificate = 0x1b,
    SupportedVersions = 0x2b,
    PskKeyExchangeMode = 0x2d,
    PostHandshakeAuth = 0x31,
    KeyShare = 0x33,
    RenegotiationInfo = 0xff01,
    EncryptedClientHello = 0xfe0d,
    ApplicationSetting = 0x44cd,
    PreSharedKey = 0x29,
    ApplicationSettingOld = 0x4469,
    QuicTrpParameters = 0x0039,
}

impl From<u16> for ExtensionType {
    fn from(val: u16) -> ExtensionType {
        match val {
            0 => ExtensionType::ServerName,
            5 => ExtensionType::StatusRequest,
            0xa => ExtensionType::SupportedGroup,
            0xb => ExtensionType::EcPointFormats,
            0xd => ExtensionType::SignatureAlgorithms,
            0x10 => ExtensionType::ApplicationLayerProtocolNegotiation,
            0x12 => ExtensionType::SignedCertificateTimestamp,
            0x15 => ExtensionType::Padding,
            0x16 => ExtensionType::EncryptTheMac,
            0x17 => ExtensionType::ExtendMasterSecret,
            0x23 => ExtensionType::SessionTicket,
            0x1b => ExtensionType::CompressionCertificate,
            0x2b => ExtensionType::SupportedVersions,
            0x2d => ExtensionType::PskKeyExchangeMode,
            0x31 => ExtensionType::PostHandshakeAuth,
            0x33 => ExtensionType::KeyShare,
            0xff01 => ExtensionType::RenegotiationInfo,
            0xfe0d => ExtensionType::EncryptedClientHello,
            0x44cd => ExtensionType::ApplicationSetting,
            0x29 => ExtensionType::PreSharedKey,
            0x4469 => ExtensionType::ApplicationSettingOld,
            0x0039 => ExtensionType::QuicTrpParameters,
            _ => ExtensionType::Padding
        }
    }
}

#[repr(C)]
#[derive(Default)]
struct Extension {
    typ: u16,
    len: u16,
    value: *const u8,
}

#[cfg(debug_assertions)]
impl Debug for Extension {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut debug_struct = f.debug_struct("Extension");
        let typ = ExtensionType::from(self.typ);
        debug_struct.field("type", &typ);
        debug_struct.field("len", &self.len);
        let mut reader = Reader::from_ptr(self.value, self.len as usize);
        match typ {
            ExtensionType::ServerName => {
                let filled = unsafe { slice::from_raw_parts(self.value, self.len as usize) };
                let list_len = u16::from_be_bytes([filled[0], filled[1]]);
                debug_struct.field("list_len", &list_len);
                reader.pos += 2;
                let mut server_names = vec![];
                while reader.pos < reader.size {
                    let mut server_name = ServerName::default();
                    unsafe { ServerName_parse(&mut reader, &mut server_name) };
                    server_names.push(server_name);
                }
                debug_struct.field("server_name", &server_names);
            }
            ExtensionType::StatusRequest => {
                let mut status_request = StatusRequest::default();
                unsafe { StatusRequest_parse(&mut reader, &mut status_request) };
                debug_struct.field("status_requests", &status_request);
            }
            ExtensionType::Padding => {
                debug_struct.field("value", &self.len);
            }
            ExtensionType::KeyShare => {
                let mut key_share = KeyShare::default();
                unsafe { KeyShare_parse(&mut reader, &mut key_share) };
                debug_struct.field("key_share", &key_share);
            }
            _ => {}
        }
        debug_struct.finish()
    }
}

#[repr(C)]
struct BufRef {
    ptr: *const u8,
    len: usize,
}

#[cfg(debug_assertions)]
impl Debug for BufRef {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.ptr.is_null() || self.len == usize::MAX {
            let mut debug_struct = f.debug_struct("BufRef");
            debug_struct.field("ptr", &self.ptr);
            debug_struct.field("len", &self.len);
            debug_struct.finish()
        } else {
            let slice = unsafe { slice::from_raw_parts(self.ptr, self.len) };
            write!(f, "{}", hex::encode(slice))
        }
    }
}

#[repr(C)]
#[derive(Default)]
struct ClientHello {
    len: u24,
    ver: u16,
    random: *const u8,
    session_id_len: u8,
    session_id: *const u8,
    suite_len: u16,
    suites: *const u8,
    comp_method_len: u8,
    comp_method: *const u8,
    ext_len: u16,
    extension: *const u8,
}

#[cfg(debug_assertions)]
impl Debug for ClientHello {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut debug_struct = f.debug_struct("ClientHello");
        debug_struct.field("len", &self.len);
        debug_struct.field("ver", &Version::new(self.ver));
        let random = hex::encode(unsafe { slice::from_raw_parts(self.random, 32) });
        debug_struct.field("random", &random);
        debug_struct.field("session_id_len", &self.session_id_len);
        let session_id = hex::encode(unsafe { slice::from_raw_parts(self.session_id, self.session_id_len as usize) });
        debug_struct.field("session_id", &session_id);
        debug_struct.field("suite_len", &self.suite_len);
        let suites = unsafe { slice::from_raw_parts(self.suites, self.suite_len as usize) };
        let suites = suites.chunks(2).map(|chunk| {
            let suite = u16::from_be_bytes([chunk[0], chunk[1]]);
            CipherSuite::from(suite)
        }).collect::<Vec<_>>();
        debug_struct.field("suites", &suites);
        debug_struct.field("comp_method_len", &self.comp_method_len);
        let comp_methods = hex::encode(unsafe { slice::from_raw_parts(self.comp_method, self.comp_method_len as usize) });
        debug_struct.field("comp_method", &comp_methods);
        debug_struct.field("ext_len", &self.ext_len);
        let mut reader = Reader::from_ptr(self.extension, self.ext_len as usize);
        let mut extensions = vec![];
        while reader.pos < reader.size {
            let mut extension = Extension::default();
            unsafe { Extension_parse(&mut reader, &mut extension) };
            extensions.push(extension);
        }
        debug_struct.field("extensions", &extensions);
        debug_struct.finish()
    }
}


#[repr(C)]
#[derive(Default)]
struct HandShake {
    typ: u8,
    len: usize,
    ptr: *const u8,
}

impl HandShake {
    pub fn client_hello(&self) -> ClientHello {
        let mut client_hello = ClientHello::default();
        unsafe { ClientHello_parse(&mut Reader::from_ptr(self.ptr, usize::MAX), &mut client_hello) };
        client_hello
    }
}

#[cfg(debug_assertions)]
impl Debug for HandShake {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut debug_struct = f.debug_struct("HandShake");
        let typ = HandshakeType::from_byte(self.typ).unwrap_or(HandshakeType::Finish);
        debug_struct.field("typ", &typ);
        debug_struct.field("len", &self.len);
        match typ {
            HandshakeType::ClientHello => {
                debug_struct.field("client_hello", &self.client_hello());
            }
            HandshakeType::ClientKeyExchange => {
                // debug_struct.field("client_key_exchange", unsafe { self.parsed.client_key_exchange.deref() });
            }
            _ => {}
        }
        debug_struct.finish()
    }
}

#[repr(C)]
#[cfg_attr(debug_assertions, derive(Debug))]
struct Alert {
    level: u8,
    desc: u8,
}

// #[repr(C)]
// #[derive(Default)]
// union Message {
//     handshake: ManuallyDrop<HandShake>,
//     // application: ManuallyDrop<BufRef>,
//     // cipher_spec: u8,
//     // alert: ManuallyDrop<Alert>,
// }


#[repr(C)]
#[derive(Default)]
struct Record {
    typ: u8,
    ver: u16,
    len: u16,
    message: *const u8,
}


#[cfg(debug_assertions)]
impl Debug for Record {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut struct_debug = f.debug_struct("Record");
        let typ = RecordType::from_byte(self.typ).unwrap_or(RecordType::HandShake);
        struct_debug.field("typ", &typ);
        struct_debug.field("ver", &Version::new(self.ver));
        struct_debug.field("len", &self.len);
        match typ {
            RecordType::CipherSpec => {}
            RecordType::Alert => {}
            RecordType::HandShake => {
                let mut messages = vec![];
                let mut reader = Reader::from_ptr(self.message, self.len as usize);
                while reader.pos < reader.size {
                    let mut message = HandShake::default();
                    unsafe { HandShake_parse(&mut reader, &mut message) };
                    messages.push(message);
                }
                struct_debug.field("messages", &messages);
            }
            RecordType::ApplicationData => {}
        }
        // let messages = unsafe { slice::from_raw_parts(self.message, self.count) };
        // match typ {
        //     RecordType::HandShake => {
        //         let handshakes = messages.into_iter().map(|x| unsafe {
        //             x.parsed.handshake.deref()
        //         }).collect::<Vec<_>>();
        //         struct_debug.field("handshake", &handshakes);
        //     }
        //     RecordType::CipherSpec => {
        //         struct_debug.field("cipher_spec", unsafe { &messages[0].parsed.cipher_spec });
        //     }
        //     RecordType::Alert => {
        //         struct_debug.field("alert", unsafe { &messages[0].parsed.alert });
        //     }
        //     RecordType::ApplicationData => {
        //         struct_debug.field("application", unsafe { &messages[0].parsed.application });
        //     }
        // }
        struct_debug.finish()
    }
}

#[repr(C)]
enum KeyExchangeAlg {
    ExchangeAlg_None = 0,
    ExchangeAlg_ECDHE_ECDSA = 1,
    ExchangeAlg_ECDHE_RSA = 2,
    ExchangeAlg_DHE_DSS = 3,
    ExchangeAlg_DHE_RSA = 4,
    ExchangeAlg_DH_ANON = 5,
    ExchangeAlg_DH_DSS = 6,
    ExchangeAlg_DH_RSA = 7,
    ExchangeAlg_RSA = 8,
    ExchangeAlg_ECC = 9,
}

#[repr(C)]
pub struct Reader<'a> {
    ptr: *const u8,
    size: usize,
    pos: usize,
    _unused: &'a PhantomData<()>,
}

impl<'a> Reader<'a> {
    pub fn from_slice(slice: &'a [u8]) -> Reader<'a> {
        Reader::from_ptr(slice.as_ptr(), slice.len())
    }

    pub fn from_ptr(ptr: *const u8, size: usize) -> Reader<'a> {
        Reader {
            ptr,
            pos: 0,
            size,
            _unused: &PhantomData,
        }
    }
}

unsafe extern "C" {
    fn Record_parse(reader: *mut Reader, record: *mut Record) -> c_int;
    fn HandShake_parse(reader: *mut Reader, handshake: *mut HandShake) -> c_int;
    fn ClientHello_parse(reader: *mut Reader, client_hello: *mut ClientHello) -> c_int;
    fn Extension_parse(reader: *mut Reader, extension: *mut Extension) -> c_int;
    fn ServerName_parse(reader: *mut Reader, server_name: *mut ServerName) -> c_int;
    fn Hostname_parse(reader: *mut Reader, hostname: *mut Hostname) -> c_int;
    fn StatusRequest_parse(reader: *mut Reader, extension: *mut StatusRequest) -> c_int;
    fn KeyShare_parse(reader: *mut Reader, key_share: *mut KeyShare) -> c_int;
    fn KeyEntry_parse(reader: *mut Reader, key_entry: *mut KeyEntry) -> c_int;
}


#[tokio::main]
async fn main() {
    #[cfg(feature = "log")]
    test_log();
    let record_bytes = hex::decode("16030107120100070e030348853c3196bf1baa176acac0b0fe608e384f64a48cb9d16eb17c52dfb9a73bd3201a5e217537bc3af3e314e4d89639ba76ce25114009dc2c2235660730c4e3899a0020dada130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010006a51a1a0000002d00020101000b00020100000500050100000000003304ef04edfafa00010011ec04c0c399b44b802ea789831e2625ebd68a136b713e80a50233a22dbc8002a6aab07ba3afd935e2f315ddb72dfa4a94f75a7494da759b03780f558a3d0a0608a38d8af2122d1ccca3a9121b5387e9da46d913b539b0c9d6b4a68a9a15f825892b26ce70815b159a7dee77ab7ea5b4fd30b9f202818ba6c7551a65f011654307b334716e667651c4e7a2a5e14ff43b271fe627273246268628157b641a62751e30b263657f160868d8d7b8095439d97941759874943c6a12da92b7d146e4e870a4e90541a23b7c5ab1c6448f7188563a097c5f78a349073737d7a37cdb08bcb09ca6dc31b4229260d88a93c7a948411e7da3b309c41987771bf8c71151aa9bc4369f1515463587c42387bb48c52846491b1d9227c0686fa1549246f44424aa258e443b431096ec2ccd377a88e24c98229236fa016bab815466c40eeae134ca77704348a2b6627cbed551d1ea0daf635206d425f600c73edc4b98c02bdf0b5efc7b73ce75a2924043e2436c944771630259f0516b30b529a64062b3098dc8343852e598887c88dbaa0b2c709b1a58941916ba4edb9caec90eb6f930f9da5cb58bb855862b59263eeda31d2a06a89763b838d10f6a0c3199c1b10bcc9d1549b0e860a1f0901698c350b7eb5e86104ff631361fd6beec2c77806362833c2efa3063810c86faa7b5ab92389eab258320265fb23f0d7a2b3a9aad03c94604cb43d532376314b2e8d4cfedda36b578b590e6146ea18c6847a0569c8318a68620f294e9d9875d014549695bd3ca68c430577092a375ac3a37203a0336c1e134b45af2548bccc8ce075e4e74a370f16d4bcbc90c8cb42ed09b5dd05c620528d9dac66833bc02e7734967c6a7cc4bebe95b85d7275b976c9ac0997eb264a0a684d4279512054a3258a39e604f1ec148ca2130d29a1ab92b53c1b0ab4ee3805f339201e968847b78739175fd695181b7a7ce500bd31a0685926e04d5ce6d2b612845ba68d39f617c21afa75f26bca95c17507698af280c0c5f21890ab78a8e56b1e94509b226066624a7c6701c3ae461c54161e7d5760279acc167cc01908b7d4a19576459e9b6276ce2c791990851fb9f8b197cf0c96de1fb61cd1c13c222c5194182edc4695e295d54a506fa09b0881169a6f32a8afc0acd5644876b5e698105f36a56a16aaf49041ea34a92619969b983025d585ee6f1bcfa131e995431b2b3a68b514534a599af1c13ad095d38cb458a1a8ac7f51524503166a63cf6d8963aa89a20c37013984672f79a9be13f93719d89e765a82a4775d531b3ebcb8b4c2935510ba6a770bc10a8a4ec60f01a9a20250050d96c535454f5b69b8cf8c00c44790f3964a1f4b2fabc5a85f061348c89e3ba1797c0c26bf3bbcad70d93822f932a18ca7ca0cf866c6b1b4de2571606f01eb2e5ab3be719c91370f29363a218aacf40284dc6c3c59671df4b62d5e44e81039c3498248a7659f0074996533e8097a0aee389a6d9ae9364b3a64bcf4e576f67802b89943ae03a24d2772726887f5fc803933111d4aa35da30a78b560bb4ec2dc918a3998281f046093f897919078ebdf05ec7f7ce03311a79bc49cb537322e8c6a6abbe56a55f6e1555e384ba6fa9c4f8e0189d3650c26aee67cbe704d7465022c259b6534361651c9b6d71fc98e18f84ff8aa1f3e880bcdbd8eddd440e3d7e99580bd9bc7f83f444daa761442c1a625dc5d44da361001d0020afa0c21e9ab34f115732ecb8e6b5d83379c4660811738d8be560cafde446fd0b0000000e000c0000093338686d7a672e636e002b0007064a4a03040303000a000c000afafa11ec001d0017001800230000001b000302000244690005000302683200170000fe0d011a0000010001960020cb3de92f31efcfcd5a53c79fbe3200c1f481e37199aa290649f1abad6ed5031e00f0dcb724c041356d77ecf7cf213696ee291b549ee48b028251d6ddde9865586ea997acd0a5210799395fd9682738cf609dd99a9c829efbc5ba83ffc2d8932b551886b5c1ebc1ac1233273e5ccfe8fa1e50fb0812f05f0fcb607672a934c778acc998173d746e8672f2aa6b60efa66369ffd7c03b9d7dcf3fc3f0cdb255347d8394dae22615b14c5ff626fa8e65b5d93278da980f307f21af1a124cab78db6d41d1cfe69d7f1ab90038f7d209f85e7d7d5ad045a2ca484569320dcae3f33b163992f0e68268899d3dabdb83f3177f115f97d165ba545ef9c193a16abc8ad3b24d458af544fb553218136e8dfa1230aa000c0010000e000c02683208687474702f312e3100120000000d0012001004030804040105030805050108060601ff01000100eaea000100").unwrap();
    println!("{:?}", RecordLayer::from_bytes(&record_bytes, reqtls::KeyExchangeAlg::NULL, false).unwrap());
    let mut reader = Reader::from_slice(&record_bytes);
    let mut record = Record::default();
    let s = unsafe { Record_parse(&mut reader, &mut record) };
    println!("{:#?}", record);
    // unsafe { Record_free(s) };


    // let mut reader = Reader::from_slice(&record_bytes[5..]);
    // let mut message = MaybeUninit::uninit();
    // let ret = unsafe { Message_parse(&mut reader, RecordType::HandShake as u8, KeyExchangeAlg::ExchangeAlg_None, 0, message.as_mut_ptr()) };
    // println!("{}", ret);
    // let mut message = unsafe { message.assume_init() };
    // println!("{:#?}", unsafe { &message.parsed.handshake });
    // unsafe { Message_free(&mut message) };


    // let record = hex::decode("1603030046100000424104ff635373fbbfbc37444a2026372f57fd06c5205bacfe32b61261a9d29bf1fca57f91ef22cb2ba46af8cf9ae7c3123f56634099af297dcd30835cd81664005fb9").unwrap();
    // println!("{:#?}", RecordLayer::from_bytes(&record, reqtls::KeyExchangeAlg::NULL, false).unwrap());
    // let mut reader = Reader::from_slice(&record);
    // let s = unsafe { Record_parse(&mut reader, KeyExchangeAlg::ExchangeAlg_None, 0) };
    // println!("{:#?}", unsafe { s.as_ref() }.unwrap());
    //
    // let record = hex::decode("140303000101").unwrap();
    // println!("{:#?}", RecordLayer::from_bytes(&record, reqtls::KeyExchangeAlg::NULL, false).unwrap());
    // let mut reader = Reader::from_slice(&record);
    // let s = unsafe { Record_parse(&mut reader, KeyExchangeAlg::ExchangeAlg_None, 0) };
    // println!("{:#?}", unsafe { s.as_ref() }.unwrap());


    // let ptr = unsafe { s.as_ref().unwrap().message.handshake[0].parsed.client_hello.suites };
    // let len = unsafe { s.as_ref().unwrap().message.handshake[0].parsed.client_hello.suite_len } / 2;
    // let suites = unsafe { slice::from_raw_parts(ptr, len as usize) };
    // println!("{:04x?}", suites);

    // unsafe { Record_free(s); }
    return;
    // Buffer::check_subscription(fs::read_to_string("TOKEN").unwrap()).unwrap();

    let t = Time::now();
    let mut timeout = Timeout::longer();
    timeout.set_handle_times(1);

    let headers = json::object! {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        "Accept": "*/*",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Dest": "document",
        "sec-fetch-user":"?1",
        "upgrade-insecure-requests":"1",
        "sec-ch-ua": "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Microsoft Edge\";v=\"120\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\"",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Accept-Encoding": "gzip,deflate,br,zstd",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "content-length": "0"
        // "cookie":"_EDGE_V=1; MUIDB=184C10AD397866DF1A1607B038566708; MUID=184C10AD397866DF1A1607B038566708; _UR=QS=0&TQS=0&Pn=0; BFBUSR=BFBHP=0; MUIDB=184C10AD397866DF1A1607B038566708; SRCHD=AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF&AF=NOFORM; SRCHUID=V=2&GUID=EB7B9E5DE58F4D5690F6904732C24C7B&dmnchg=1; USRLOC=HS&ELOC=LAT=23.384721755981445|LON=113.44195556640625|N=%E7%99%BD%E4%BA%91%E5%8C%BA%EF%BC%8C%E5%B9%BF%E4%B8%9C%E7%9C%81|ELT=4|&HS=1; _RwBf=r&r&r&r&r=0&ilt=10&ihpd=5&ispd=3&rc=12&rb=0&rg=200&pc=12&mtu=0&rbb=0&clo=0&v=8&l=2026-03-15T07:00:00.0000000Z&lft=0001-01-01T00:00:00.0000000&aof=0&ard=0001-01-01T00:00:00.0000000&rwdbt=0&rwflt=0&rwaul2=0&g=&o=2&p=&c=&t=0&s=0001-01-01T00:00:00.0000000+00:00&ts=2026-03-15T14:03:35.7211444+00:00&rwred=0&wls=&wlb=&wle=&ccp=&cpt=&lka=0&lkt=0&aad=0&TH=&cid=0&gb=; SRCHUSR=DOB&DS&DS&DS&DS&DS=1&DOB=20260315; _EDGE_S=SID=357AA105805E678827ACB618817066E6; _SS=SID=357AA105805E678827ACB618817066E6; _HPVN=CS=eyJQbiI6eyJDbiI6MSwiU3QiOjAsIlFzIjowLCJQcm9kIjoiUCJ9LCJTYyI6eyJDbiI6MSwiU3QiOjAsIlFzIjowLCJQcm9kIjoiSCJ9LCJReiI6eyJDbiI6MSwiU3QiOjAsIlFzIjowLCJQcm9kIjoiVCJ9LCJBcCI6dHJ1ZSwiTXV0ZSI6dHJ1ZSwiTGFkIjoiMjAyNi0wMy0xNVQwMDowMDowMFoiLCJJb3RkIjowLCJHd2IiOjAsIlRucyI6MCwiRGZ0IjpudWxsLCJNdnMiOjAsIkZsdCI6MCwiSW1wIjozMCwiVG9ibiI6MH0=; SRCHHPGUSR=SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&V&SRCHLANG&SRCHLANG&SRCHLANG&V&SRCHLANG&SRCHLANG=zh-Hans&PREFCOL=0&BRW=NOTP&BRH=M&CW=150&CH=769&SCW=150&SCH=769&DPR=1.0&UTC=480&HV=1773588648&HVE=CfDJ8HAK7eZCYw5BifHFeUHnkJGC6_lT8f9GeruXx8zjPXuk-5GHkofYMoFErMkT8CTKKKsSt5O2HyGmjLyCEXbEREUmwCd8ZBlYMLSDZu1wZ-EI1LDuyIiI1tkP6Usyicm601qX3aJVYqVWUBn-t6h0ZWLiftm4aS627xFj1fE5PD-85i7BWTkhqG0uvaYzuSgB2A&BZA=0&PRVCW=150&PRVCH=769&B=0&EXLTT=7&V=CfDJ8HAK7eZCYw5BifHFeUHnkJGijeRjCoaCMaAnmznMvdEg2GXY8647Wb-7wnHNpePKXRO6KRQ_0cQc-onivd35uV-p-4g0MB0V_Z1ZpW-QSJe9zbPUG-Ks-kQMjzEl6GlLo6N0ciP51vkQdR-P-lCUH58&PR=1"
    };
    let fingerprint = Fingerprint::from_ja4("t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601", fs::read_to_string("TOKEN").unwrap_or("".to_string())).unwrap();
    let mut req = AcReq::new()
        .with_fingerprint(fingerprint)
        .with_timeout(timeout)
        .with_verify(false)
        .with_key_log("2.log")
        .with_auto_redirect(false)
        // .with_proxy(Proxy::Null)
        .with_alpn(ALPN::Http20)
        .with_header_json(headers).unwrap()
        // .with_mtls(vec![], RsaKey::none(), Some(vec![cert]))
        // .with_proxy(Proxy::try_from("http: //222.186.129.68:15265").unwrap())
        // .with_mtls(certs, key)
        // .with_proxy(Proxy::new_socks5("127.0.0.1",10279))
        // .with_proxy(Proxy::new_http_plain("127.0.0.1", 8080))
        // .connect("https://104.18.34.137".sni("whatnot.com")).await.unwrap()
        ;
    // let res = req.post("http://127.0.0.1:8000/log", json::object! {"on": false}).await.unwrap();
    // let res = req.get("https://fk1.moutai519.com.cn/bangcle/api/v1/1/1", None).await.unwrap().json().unwrap();
    // let res = req.post("http://127.0.0.1:8000/upload_wac", res).await.unwrap();
    // // println!("{}", res.raw_string());
    // let res = req.post("http://127.0.0.1:8000/generate", json::object! {
    //     "ua": "Mozilla/5.0 (Linux; Android 12; 2201123C Build/SKQ1.211006.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/123",
    //     "body":{},
    //     "uid": "5656"
    // }).await.unwrap();
    // println!("{}", res.json().unwrap().pretty());
    // return;
    // req.connect("https://test.gmssl.cn/").await.unwrap();
    // let res = req.get("https://test.gmssl.cn/", None).await.unwrap();
    // println!("{}", res.raw_string());
    // let res = req.get("https://www.baidu.com", None).await.unwrap();
    // println!("{}", res.raw_string());


    // let url = "https://www.dickssportinggoods.com/p/2026-topps-flagship-football-mega-box-26topufang4p4ib5vqjhq/26topufang4p4ib5vqjhq";
    // let url = "https://ts3.tc.mm.bing.net/th/id/ODF.dsR0yzVOEBuWxCU9cjAM4Q?w=32&h=32&qlt=96&pcl=fffffa&o=6&pid=1.2";
    // let sid1 = req.send(Method::GET, url, None).await.unwrap();
    // let url = "https://ts3.tc.mm.bing.net/th/id/ODF.pnhuF5msYDWgeLYHsiLTig?w=32&h=32&qlt=95&pcl=fffffa&o=6&pid=1.2";
    // let sid2 = req.send(Method::POST, url, None).await.unwrap();

    // let res1 = req.recv(sid1).await.unwrap();
    // let res1 = req.get(url, None).await.unwrap();
    // println!("{}", res1.raw_string());
    // let res2 = req.recv(sid2).await.unwrap();
    // println!("{}", res2.raw_string());
    // println!("{}", Time::now().as_mills() - t.as_mills())

    // let res1 = req.get("https://docs.rs", None).await.unwrap();
    // let res1 = req.get("https://www.bing.com", None).await.unwrap();
    let res1 = req.get("https://202.89.233.101".sni("cn.bing.com"), None).await.unwrap();
    println!("{}", res1.raw_string());

    // req.set_auto_redirect(false);
    // req.set_url("http://zwfw.hubei.gov.cn/web/user/uias_login.do?appCode=hbzwfw&gotoUrl=http%3A%2F%2Fzwfw.hubei.gov.cn%2Fwebview%2Fgrkj%2Fwelcome.html&p01=").await.unwrap();
    // req.set_url("https://www.jetstar.com").await.unwrap();
    // req.set_url("https://m1.pxb7.com/api/search/h5/product/selectSearchPageList").await.unwrap();
    // req.set_url("https://www.link114.cn/").await.unwrap();
    //
    // req.set_url("https://accounts.pcid.ca/login").await.unwrap();
    // req.set_url("https://xxbg.snssdk.com/fdsf/dsfsdfkdsjfk").await.unwrap();
    // req.set_url("https://www.toutiao.com/article/7600224020776239658/?log_from=99ab1fa2b852c_1769590891442&wid=1769590984039").await.unwrap();
    // req.set_url("https://www.sogou.com").await.unwrap();
    // req.set_url("https://cn.bing.com/search?q=site%EF%BC%9Asite：wLLyn.com&first=0&FORM=PERE2").await.unwrap();
    // req.set_proxy(Proxy::new_socks5("127.0.0.1", 10279));
    // req.set_url("https://m.baidu.com").await.unwrap();
    // req.set_url("https://www.sephora.com/").await.unwrap();
    // req.set_url("https://doc.rust-lang.org/").await.unwrap();
    // req.set_url("https://tls.123408.xyz/api/clean").await.unwrap();
    // req.set_url("https://mcs-mimp-web.sf-express.com/mcs-mimp/sendValidCode").await.unwrap()
    // req.set_url("https://jetstar.com").await.unwrap();
    // req.set_url("https://oauth.hubei.gov.cn:8443/").await.unwrap();
    // let res = req.get("https://dns.alidns.com/resolve?name=crypto.cloudflare.com&type=HTTPS", None).await.unwrap();
    // let res=req.get("https://www.link114.cn/",None).await.unwrap();
    // let res = req.get("https://www.bing.com".params(json::object! {}), vec![0u8; 0].ty(Application::Json)).await.unwrap();
    // let res = req.get("https://117.89.181.21".sni("m.sogou.com"), None).await.unwrap();
    // let url = Url::try_from("https://cn.bing.com/").unwrap();
    // let url = "https://113.108.215.122/xhr/front/trade/priority/rushPurchase/hot/branch/one".sni("h5.moutai519.com.cn").unwrap(); //
    // let url: Url = "https://www.bing.com".try_into().unwrap();
    // let url: Url = "https://cn.bing.com".try_into().unwrap();
    // let url = "https://shop.lululemon.com/help/orders/gift-card-balance";


    // println!("{} {}", res1.header(), res2.header());
    // let res = req.get("https://m.sogou.com", None).await.unwrap();
    // let session=req.stream_mut().tls_session().cloned();
    // req.set_tls_session(session);
    // let res = req.get("https://150.139.229.223".sni("h5.moutai519.com.cn"), None).await.unwrap();
    // let res = req.get("https://aswbe.ana.co.jp/webapps/reservation/flight-search", None).await.unwrap();
    // req.re_conn(None).await.unwrap();
    // let res = req.get("https://aswbe.ana.co.jp/webapps/reservation/flight-search", None).await.unwrap();
    // let res = req.send("https://oauth.hubei.gov.cn:8443/", None).await.unwrap();
    // let res = req.get(url.params(params), None).await.unwrap();
    // req.set_url("https://cn.bing.com/notifications/render?bnptrigger=%7B%22PartnerId%22%3A%22HomePage%22%2C%22IID%22%3A%22Bnp%22%2C%22Attributes%22%3A%7B%22RawRequestURL%22%3A%22%2F%22%7D%7D&IG=AFEA02EAF9E449A99970476597AE6CED&IID=Bnp").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/web/xlsc.aspx?dl=1&f=8").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/hp/api/model").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/sa/simg/favicon-trans-bg-blue-mg-png.png").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/web/xlsc.aspx?dl=1&f=8").await.unwrap();
    // let res = req.get().await.unwrap();
    // let res = req.get().await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/AS/Suggestions?pt=page.home&qry=&csr=1&pths=1&zis=1&pf=1&cvid=AFEA02EAF9E449A99970476597AE6CED").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/hp/api/v1/carousel?&format=json&ecount=20&efirst=0&&").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/notifications/render?bnptrigger=%7B%22PartnerId%22%3A%22HomePage%22%2C%22IID%22%3A%22Bnp%22%2C%22Attributes%22%3A%7B%22RawRequestURL%22%3A%22%2F%22%7D%7D&IG=AFEA02EAF9E449A99970476597AE6CED&IID=Bnp").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/web/xlsc.aspx?dl=1&f=8").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/hp/api/model").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/sa/simg/favicon-trans-bg-blue-mg-png.png").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/web/xlsc.aspx?dl=1&f=8").await.unwrap();
    // let res = req.get().await.unwrap();
    // let res = req.get().await.unwrap();
    // let res = req.get().await.unwrap();
    // println!("{}", res.header());

}