use crate::export::{check_run, handle_err1};
use crate::*;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::ptr::null_mut;
use std::slice;

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn Fingerprint_new(token: *const c_char) -> *mut Fingerprint {
    let token = unsafe { CStr::from_ptr(token) }.to_str().unwrap_or("");
    Box::into_raw(Box::new(Fingerprint::new_custom(token)))
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn Fingerprint_add_cipher_suite(fingerprint: *mut Fingerprint, suite: u16) {
    let fingerprint = unsafe { fingerprint.as_mut() };
    if let Some(fingerprint) = fingerprint {
        fingerprint.tls_mut().add_cipher_suite(suite.into());
    }
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn Fingerprint_add_ext(fingerprint: *mut Fingerprint, ext_typ: ExtensionType) {
    let fingerprint = unsafe { fingerprint.as_mut() };
    if let Some(fingerprint) = fingerprint {
        fingerprint.tls_mut().add_extension(match Extension::default_value(ext_typ) {
            None => Extension::Reserved { typ: ext_typ, value: Buf::default() },
            Some(extend) => extend,
        });
    }
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn Fingerprint_add_ext_alpn(fingerprint: *mut Fingerprint, ext_typ: u16, alpn: *const c_char) {
    let fingerprint = unsafe { fingerprint.as_mut() };
    if let Some(fingerprint) = fingerprint {
        let alpn = ALPN::from_slice(unsafe { CStr::from_ptr(alpn) }.to_bytes());
        let ext_typ = ExtensionType::new(ext_typ);
        match fingerprint.tls_mut().find_mut(ext_typ) {
            Some(Extension::ApplicationLayerProtocolNegotiation(alps)) => alps.push(alpn),
            Some(Extension::ApplicationSettings(alps)) => alps.push(alpn),
            Some(Extension::ApplicationSettingOld(alps)) => alps.push(alpn),
            _ => {
                let extend = match ext_typ {
                    ExtensionType::ApplicationLayerProtocolNegotiation => Extension::ApplicationLayerProtocolNegotiation(vec![alpn]),
                    ExtensionType::ApplicationSetting => Extension::ApplicationSettings(vec![alpn]),
                    ExtensionType::ApplicationSettingOld => Extension::ApplicationSettingOld(vec![alpn]),
                    _ => unreachable!()
                };
                fingerprint.tls_mut().add_extension(extend);
            }
        }
    }
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn Fingerprint_add_ext_version(fingerprint: *mut Fingerprint, ext_typ: ExtensionType, version: u16) {
    let fingerprint = unsafe { fingerprint.as_mut() };
    let version: Version = version.into();
    if let Some(fingerprint) = fingerprint {
        match fingerprint.tls_mut().find_mut(ext_typ) {
            Some(Extension::SupportedVersions(values)) => values.push(version),
            _ => fingerprint.tls_mut().add_extension(Extension::SupportedVersions(vec![version])),
        }
    }
}


#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn Fingerprint_add_ext_curve(fingerprint: *mut Fingerprint, ext_typ: ExtensionType, curve: NamedCurve) {
    let fingerprint = unsafe { fingerprint.as_mut() };
    if let Some(fingerprint) = fingerprint {
        match fingerprint.tls_mut().find_mut(ext_typ) {
            Some(Extension::SupportedGroups(values)) => values.push(curve),
            Some(Extension::KeyShare(values)) => values.push(KeyEntry::new(curve)),
            _ => match ext_typ {
                ExtensionType::SupportedGroup => fingerprint.tls_mut().add_extension(Extension::SupportedGroups(vec![curve])),
                ExtensionType::KeyShare => fingerprint.tls_mut().add_extension(Extension::KeyShare(vec![])),
                _ => unreachable!()
            },
        }
    }
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn Fingerprint_add_ext_compress(fingerprint: *mut Fingerprint, ext_typ: ExtensionType, method: CompressionMethod) {
    let fingerprint = unsafe { fingerprint.as_mut() };
    if let Some(fingerprint) = fingerprint {
        match fingerprint.tls_mut().find_mut(ext_typ) {
            Some(Extension::CompressionCertificate(values)) => values.push(method),
            _ => fingerprint.tls_mut().add_extension(Extension::CompressionCertificate(vec![method])),
        }
    }
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn Fingerprint_add_ext_psk_mode(fingerprint: *mut Fingerprint, ext_typ: ExtensionType, mode: PskMode) {
    let fingerprint = unsafe { fingerprint.as_mut() };
    if let Some(fingerprint) = fingerprint {
        match fingerprint.tls_mut().find_mut(ext_typ) {
            Some(Extension::PskKeyExchangeModes(values)) => values.push(mode),
            _ => fingerprint.tls_mut().add_extension(Extension::PskKeyExchangeModes(vec![mode])),
        }
    }
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn Fingerprint_add_ext_padding(fingerprint: *mut Fingerprint, ext_typ: ExtensionType, padding: usize) {
    let fingerprint = unsafe { fingerprint.as_mut() };
    if let Some(fingerprint) = fingerprint {
        match fingerprint.tls_mut().find_mut(ext_typ) {
            Some(Extension::Padding(values)) => *values = padding,
            _ => fingerprint.tls_mut().add_extension(Extension::Padding(padding)),
        }
    }
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn Fingerprint_add_ext_bytes(fingerprint: *mut Fingerprint, ext_typ: ExtensionType, bs: *const u8, len: usize) {
    let fingerprint = unsafe { fingerprint.as_mut() };
    let bs = unsafe { slice::from_raw_parts(bs, len) };
    if let Some(fingerprint) = fingerprint {
        fingerprint.tls_mut().add_extension(Extension::Reserved {
            typ: ext_typ,
            value: Buf::Vec(bs.to_vec()),
        });
    }
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn Fingerprint_add_ext_algorithm(fingerprint: *mut Fingerprint, ext_typ: ExtensionType, algorithm: SignatureAlgorithm) {
    let fingerprint = unsafe { fingerprint.as_mut() };
    if let Some(fingerprint) = fingerprint {
        match fingerprint.tls_mut().find_mut(ext_typ) {
            Some(Extension::SignatureAlgorithms(values)) => values.push(algorithm),
            _ => fingerprint.tls_mut().add_extension(Extension::SignatureAlgorithms(vec![algorithm])),
        }
    }
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn Fingerprint_add_ext_ec_point(fingerprint: *mut Fingerprint, ext_typ: ExtensionType, ec_point: u8) {
    let fingerprint = unsafe { fingerprint.as_mut() };
    let ec_point: EcPointFormat = ec_point.into();
    if let Some(fingerprint) = fingerprint {
        match fingerprint.tls_mut().find_mut(ext_typ) {
            Some(Extension::EcPointFormats(values)) => values.push(ec_point),
            _ => fingerprint.tls_mut().add_extension(Extension::EcPointFormats(vec![ec_point])),
        }
    }
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn Fingerprint_add_h2_setting(fingerprint: *mut Fingerprint, flag: u16, value: u32) {
    let fingerprint = unsafe { fingerprint.as_mut() };
    if let Some(fingerprint) = fingerprint {
        fingerprint.h2_mut().add_setting(match flag {
            1 => H2Setting::HeaderTableSize(value),
            2 => H2Setting::EnablePush(value),
            3 => H2Setting::MaxConcurrentStreams(value),
            4 => H2Setting::InitialWindowSize(value),
            5 => H2Setting::MaxFrameSize(value),
            6 => H2Setting::MaxHeaderListSize(value),
            _ => H2Setting::Reserved { flag, value }
        });
    }
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn Fingerprint_set_h2_window_size(fingerprint: *mut Fingerprint, size: u32) {
    let fingerprint = unsafe { fingerprint.as_mut() };
    if let Some(fingerprint) = fingerprint {
        fingerprint.h2_mut().set_window_size(size);
    }
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn Fingerprint_set_h2_priority(fingerprint: *mut Fingerprint, priority: bool, weight: u8) {
    let fingerprint = unsafe { fingerprint.as_mut() };
    if let Some(fingerprint) = fingerprint {
        fingerprint.h2_mut().set_priority(priority, weight);
    }
}


#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn Fingerprint_drop(fingerprint: *mut Fingerprint) {
    if fingerprint.is_null() { return; }
    let fingerprint = unsafe { Box::from_raw(fingerprint) };
    drop(fingerprint);
}


#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn Fingerprint_from_ja3(ja3: *const c_char, token: *const c_char, err: *mut *mut c_char) -> *mut Fingerprint {
    check_run(move || {
        let ja3 = unsafe { CStr::from_ptr(ja3) }.to_str()?;
        let token = unsafe { CStr::from_ptr(token) }.to_str()?;
        Ok(Box::into_raw(Box::new(Fingerprint::from_ja3(ja3, token)?)))
    }, |e| handle_err1(e, err, null_mut()))
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn Fingerprint_from_ja4(ja4: *const c_char, token: *const c_char, err: *mut *mut c_char) -> *mut Fingerprint {
    check_run(move || {
        let ja4 = unsafe { CStr::from_ptr(ja4) }.to_str()?;
        let token = unsafe { CStr::from_ptr(token) }.to_str()?;
        Ok(Box::into_raw(Box::new(Fingerprint::from_ja4(ja4, token)?)))
    }, |e| handle_err1(e, err, null_mut()))
}


#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn Fingerprint_from_client_hello(client_hello: *const u8, len: usize, token: *const c_char, err: *mut *mut c_char) -> *mut Fingerprint {
    check_run(move || {
        let client_hello = unsafe { slice::from_raw_parts(client_hello, len) }.to_vec();
        let token = unsafe { CStr::from_ptr(token) }.to_str()?;
        Ok(Box::into_raw(Box::new(Fingerprint::from_client_hello(Version::TLS_1_0, client_hello, token)?)))
    }, |e| handle_err1(e, err, null_mut()))
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn Fingerprint_random(token: *const c_char, err: *mut *mut c_char) -> *mut Fingerprint {
    check_run(move || {
        let token = unsafe { CStr::from_ptr(token) }.to_str()?;
        Ok(Box::into_raw(Box::new(Fingerprint::random(token))))
    }, |e| handle_err1(e, err, null_mut()))
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn Fingerprint_custom(custom: *const c_char, token: *const c_char, err: *mut *mut c_char) -> *mut Fingerprint {
    check_run(move || {
        if token.is_null() { return Err("token 不能为空".into()); }
        let custom = json::from_bytes(unsafe { CStr::from_ptr(custom) }.to_bytes())?;
        let token = unsafe { CStr::from_ptr(token) }.to_str()?;
        let mut extensions = vec![];
        for (key, value) in custom["extensions"].entries() {
            let typ = ExtensionType::new(key.parse::<u16>().or(Err("Invalid extend type"))?);
            match typ {
                ExtensionType::SignatureAlgorithms if !value.is_null() => {
                    let values: Vec<SignatureAlgorithm> = value.members().map(|x| SignatureAlgorithm::new(x.as_u16().unwrap_or(0))).collect();
                    extensions.push(Extension::SignatureAlgorithms(values));
                }
                ExtensionType::CompressionCertificate if !value.is_null() => {
                    let values: Vec<CompressionMethod> = value.members().map(|x| x.as_u16().unwrap_or(0).into()).collect();
                    extensions.push(Extension::CompressionCertificate(values));
                }
                ExtensionType::EcPointFormats if !value.is_null() => {
                    let values: Vec<EcPointFormat> = value.members().map(|x| x.as_u8().unwrap_or(0).into()).collect();
                    extensions.push(Extension::EcPointFormats(values));
                }
                ExtensionType::SupportedVersions if !value.is_null() => {
                    let values: Vec<Version> = value.members().map(|x| x.as_u16().unwrap_or(0).into()).collect();
                    extensions.push(Extension::SupportedVersions(values));
                }
                ExtensionType::SupportedGroup  if !value.is_null() => {
                    let values: Vec<NamedCurve> = value.members().map(|x| NamedCurve::new(x.as_u16().unwrap_or(0))).collect();
                    extensions.push(Extension::SupportedGroups(values));
                }
                ExtensionType::KeyShare if !value.is_null() => {
                    let values: Vec<KeyEntry> = value.members().map(|x| {
                        let curve = NamedCurve::new(x.as_u16().unwrap_or(0));
                        KeyEntry::new(curve)
                    }).collect();
                    extensions.push(Extension::KeyShare(values));
                }
                ExtensionType::ApplicationLayerProtocolNegotiation  if !value.is_null() => {
                    let values = value.members().map(|x| ALPN::from_slice(x.as_str().unwrap_or("").as_bytes())).collect();
                    extensions.push(Extension::ApplicationLayerProtocolNegotiation(values))
                }
                ExtensionType::ApplicationSetting if !value.is_null() => {
                    let values = value.members().map(|x| ALPN::from_slice(x.as_str().unwrap_or("").as_bytes())).collect();
                    extensions.push(Extension::ApplicationSettings(values))
                }
                ExtensionType::ApplicationSettingOld if !value.is_null() => {
                    let values = value.members().map(|x| ALPN::from_slice(x.as_str().unwrap_or("").as_bytes())).collect();
                    extensions.push(Extension::ApplicationSettingOld(values))
                }
                ExtensionType::Padding if !value.is_null() => {
                    let value = value.as_usize().unwrap_or(0);
                    extensions.push(Extension::Padding(value));
                }
                ExtensionType::PskKeyExchangeMode if !value.is_null() => {
                    let value = PskMode::new(value.as_u8().unwrap_or(0));
                    extensions.push(Extension::PskKeyExchangeModes(vec![value]));
                }
                _ => {
                    let default = Extension::default_value(typ);
                    match default {
                        None => {
                            let value = value.members().map(|x| x.as_u8().unwrap_or(0)).collect::<Vec<_>>();
                            extensions.push(Extension::Reserved { typ, value: Buf::Vec(value) });
                        }
                        Some(extend) => extensions.push(extend)
                    }
                }
            }
        }

        let tls = TlsFinger::Custom {
            record_version: Version::new(custom["record_version"].as_u16().unwrap_or(0x301)),
            message_version: Version::new(custom["message_version"].as_u16().unwrap_or(0x303)),
            suites: custom["suites"].members().map(|x| x.as_u16().unwrap_or(0).into()).collect(),
            extensions,
        };
        let mut h2 = H2Finger {
            setting: vec![],
            window_size: custom["window_size"].as_u32().or(Err("missing window_size"))?,
            weight: custom["weight"].as_u8().unwrap_or(0),
            priority: custom["priority"].as_bool().unwrap_or(false),
        };
        for (key, value) in custom["settings"].entries() {
            match key {
                "HeaderTableSize" => h2.setting.push(H2Setting::HeaderTableSize(value.as_u32()?)),
                "EnablePush" => h2.setting.push(H2Setting::EnablePush(value.as_u32()?)),
                "MaxConcurrentStreams" => h2.setting.push(H2Setting::MaxConcurrentStreams(value.as_u32()?)),
                "InitialWindowSize" => h2.setting.push(H2Setting::InitialWindowSize(value.as_u32()?)),
                "MaxFrameSize" => h2.setting.push(H2Setting::MaxFrameSize(value.as_u32()?)),
                "MaxHeaderListSize" => h2.setting.push(H2Setting::MaxHeaderListSize(value.as_u32()?)),
                "Reserved" => h2.setting.push(H2Setting::Reserved { flag: value["flag"].as_u16()?, value: value["value"].as_u32()? }),
                _ => return Err("unknown setting type".into()),
            }
        }
        let finger = Fingerprint::new_h2(tls, h2, token)?;
        Ok(Box::into_raw(Box::new(finger)))
    }, |e| handle_err1(e, err, null_mut()))
}


