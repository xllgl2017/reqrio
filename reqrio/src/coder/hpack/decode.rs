use crate::error::HlsResult;
use super::{HPack, HPackTable};

#[derive(Clone)]
pub(crate) struct HackDecode;

impl HackDecode {
    pub fn new() -> Self {
        HackDecode {}
    }

    fn decode_huffman(&self, context: &[u8], flag: u8) -> HlsResult<String> {
        if flag & 0x80 != 0x80 {
            return Ok(String::from_utf8(context.to_vec()).unwrap_or_else(|_| {
                let mut res = vec![];
                let _ = httlib_huffman::decode(context, &mut res, httlib_huffman::DecoderSpeed::FiveBits);
                String::from_utf8(res).unwrap()
            }));
        }
        let mut res = vec![];
        httlib_huffman::decode(context, &mut res, httlib_huffman::DecoderSpeed::FiveBits).unwrap_or_else(|_| {
            println!("2323={}", String::from_utf8_lossy(context));
        });
        Ok(String::from_utf8(res.clone()).unwrap_or_else(|e| {
            println!("{}", String::from_utf8_lossy(res.as_slice()));
            println!("{}", e.to_string());
            "error".to_string()
        }))
    }

    fn decode_fields(&mut self, context: &[u8], index: usize, name: bool, tables: &mut HPackTable) -> HlsResult<(HPack, usize)> {
        let mut res = HPack::new("", "");
        let (value_len, use_len) = self.decode_len(context, 0b1111111, 7);
        let decode = self.decode_huffman(&context[use_len..value_len + use_len], context[0])?;
        match name {
            true => res.set_name(decode),
            false => res.set_value(decode),
        }
        match tables.get(index) {
            None => {}
            Some(table) => {
                if !name { res.set_name(table.name()); }
                // match name {
                //     true => {
                //         res.0 = table.0;
                //     }
                //     false => {
                //         res.0 = table.0;
                //         res.1 = table.1.clone();
                //     }
                // }
            }
        }
        Ok((res.clone(), value_len + use_len))
    }

    fn decode_len(&self, context: &[u8], bit: u8, size: usize) -> (usize, usize) {
        let index = (context[0] & bit) as usize;
        if index < (2i32.pow(size as u32) - 1) as usize { return (index, 1); }
        if context[1] & 0x80 != 0x80 { return ((context[1] & 0b01111111) as usize + index, 2); }
        if context[2] & 0x80 != 0x80 {
            let len = ((context[2] & 0b01111111) as usize) * 128 + (context[1] & 0b01111111) as usize;
            return (len + index, 3);
        }
        if context[3] & 0x80 != 0x80 {
            let len = ((context[3] & 0b01111111) as usize) * 128 * 128 + ((context[2] & 0b01111111) as usize) * 128 + (context[1] & 0b01111111) as usize;
            return (len + index, 4);
        }
        panic!("hpack")
    }

    pub fn decode(&mut self, context: &[u8], tables: &mut HPackTable) -> HlsResult<Vec<HPack>> {
        let mut current = 0;
        let mut res = vec![];
        while current < context.len() {
            let b = context[current];
            if b & 0b10000000 == 0b10000000 {
                let (index, len) = self.decode_len(&context[current..], 0b1111111, 7);
                let table_len = tables.len();
                res.push(if index - 1 >= table_len { HPack::new(format!("none-{}", table_len), format!("none-{}", index)) } else {
                    tables.get(index - 1).unwrap().clone()
                });
                current += len;
            } else if b & 0b01000000 == 0b01000000 {
                let (index, len) = self.decode_len(&context[current..], 0b111111, 6);
                current += len;
                if index > 0 {
                    //save value
                    let (value, len) = self.decode_fields(&context[current..], index - 1, false, tables)?;
                    res.push(value.clone());
                    tables.insert(61, value);
                    current += len
                } else if index == 0 {
                    //save key and value
                    let table_len = tables.len();
                    let (mut name, len) = self.decode_fields(&context[current..], table_len, true, tables)?;
                    current += len;
                    let (value, len) = self.decode_fields(&context[current..], table_len, false, tables)?;
                    current += len;
                    name.set_value(value.value());
                    // name.2 = value.2.clone();
                    res.push(name.clone());
                    tables.insert(61, name);
                }
            } else if b & 0b00100000 == 0b00100000 {
                let (table_size, len) = self.decode_len(&context[current..], 0b00011111, 5);
                let mut current_table_size = tables.len();
                while current_table_size - 61 > table_size {
                    tables.remove(current_table_size - 1);
                    current_table_size = tables.len();
                }
                current += len;
            } else if b & 0b00010000 == 0b00010000 {
                let (index, len) = self.decode_len(&context[current..], 0b111111, 6);
                current += len;
                if index == 0 {
                    //unsaved key and value
                    let table_len = tables.len();
                    let (mut name, len) = self.decode_fields(&context[current..], table_len, true, tables)?;
                    current += len;
                    let (value, len) = self.decode_fields(&context[current..], table_len, false, tables)?;
                    current += len;
                    name.set_value(value.value());
                    // name.2 = value.2.clone();
                    res.push(name.clone());
                } else {
                    //unsaved value
                    let (value, len) = self.decode_fields(&context[current..], index - 1, false, tables)?;
                    res.push(value.clone());
                    current += len;
                }
            } else if b & 0b00000000 == 0b00000000 {
                let (index, len) = self.decode_len(&context[current..], 0b00001111, 4);
                current += len;
                if index != 0 {
                    //unsaved value
                    let (value, len) = self.decode_fields(&context[current..], index - 1, false, tables)?;
                    res.push(value);
                    current += len;
                } else {
                    //unsaved key and value
                    let table_len = tables.len();
                    let (mut name, len) = self.decode_fields(&context[current..], table_len, true, tables)?;
                    current += len;
                    let (value, len) = self.decode_fields(&context[current..], table_len, false, tables)?;
                    current += len;
                    name.set_value(value.value());
                    // name.2 = value.2.clone();
                    res.push(name.clone());
                }
            } else { panic!("oiuoiuou"); }
        }
        Ok(res)
    }
}