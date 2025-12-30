use crate::error::HlsResult;
use super::{HPack, HPackTable};
use crate::packet::HeaderKey;

#[derive(Clone)]
pub struct HackEncode{
    table: HPackTable,
}

impl HackEncode {
    pub fn new() -> Self { HackEncode {
        table: HPackTable::new(),
    } }


    fn encode_len(&self, len: usize, bit_len: u32) -> Vec<u8> {
        let max_value = (2i32.pow(bit_len) - 1) as usize;
        if len < max_value { return vec![len as u8]; };
        let remain_value = len - max_value;
        let mut res = match remain_value {
            2097152.. => {
                let b1 = (remain_value / 2097152) as u8;
                let n2 = remain_value - 2097152 * b1 as usize;
                let b2 = (n2 / 16384) as u8;
                let n3 = n2 - 16384 * b2 as usize;
                let b3 = (n3 / 128) as u8;
                let b4 = n3 - 128 * b3 as usize;
                vec![b1, b2, b3, b4 as u8, max_value as u8]
            }
            16384..2097152 => {
                let b1 = (remain_value / 16384) as u8;
                let n2 = remain_value - 16384 * b1 as usize;
                let b2 = (n2 / 128) as u8;
                let b3 = n2 - 128 * b2 as usize;
                vec![b1, b2, b3 as u8, max_value as u8]
            }
            128..16384 => {
                let b1 = (remain_value / 128) as u8;
                let b2 = remain_value - 128 * b1 as usize;
                vec![b1, b2 as u8, max_value as u8]
            }
            ..128 => vec![remain_value as u8, max_value as u8]
        };
        res.reverse();
        for i in 1..res.len() - 1 {
            res[i] |= 0x80;
        }
        res
    }

    fn encode_once_filed(&mut self, name: &str, value: String) -> HlsResult<Vec<u8>> {
        let mut res = vec![];
        let packs = self.table.filter_by_name(name);
        match packs.len() {
            0 => {
                let mut eb = 0;
                eb |= 64;
                res.push(eb);
                let mut ehs = vec![];
                httlib_huffman::encode(name.as_bytes(), &mut ehs)?;
                let mut ebs = self.encode_len(ehs.len(), 7);
                ebs[0] |= 128;
                res.extend(ebs);
                res.extend(ehs);
                let mut ehs = vec![];
                httlib_huffman::encode(value.as_bytes(), &mut ehs)?;
                let mut ebs = self.encode_len(ehs.len(), 7);
                ebs[0] |= 128;
                res.extend(ebs);
                res.extend(ehs);
                let pack = HPack::new(name, value);
                self.table.insert(61, pack);
            }
            _ => {
                let pack = packs.iter().find(|x| x.value() == value);
                match pack {
                    Some(pack) => {
                        let pos = self.table.position(pack).unwrap();
                        // println!("111{} {}", pack, pos);
                        let mut ebs = self.encode_len(pos + 1, 7);
                        ebs[0] |= 128;
                        res.extend(ebs);
                    }
                    None => {
                        let pos = self.table.position(&packs[0]).unwrap();
                        let mut ebs = self.encode_len(pos + 1, 6);
                        ebs[0] |= 64;
                        res.extend(ebs);
                        let mut ehs = vec![];
                        httlib_huffman::encode(value.as_bytes(), &mut ehs)?;
                        let mut ebs = self.encode_len(ehs.len(), 7);
                        ebs[0] |= 128; //set huffman encode flag
                        res.extend(ebs);
                        res.extend(ehs);
                        let pack = packs[0].clone().with_value(value);
                        // println!("111{} {}", pack, value);
                        self.table.insert(61, pack);
                    }
                }
            }
        }
        Ok(res)
    }

    pub fn encode(&mut self, headers: Vec<HeaderKey>) -> HlsResult<Vec<u8>> {
        let mut res = vec![];
        for header in headers {
            let ebs = match header.name() {
                "cookie" => {
                    let mut res = vec![];
                    for cookie in header.cookies().unwrap_or(&vec![]) {
                        res.extend(self.encode_once_filed("cookie", cookie.as_req())?);
                    }
                    res
                }
                _ => self.encode_once_filed(&header.name().to_lowercase(), header.value().to_string())?
            };
            res.extend(ebs);
        }
        Ok(res)
    }
}
