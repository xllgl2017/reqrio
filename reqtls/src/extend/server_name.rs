use crate::error::RlsResult;

#[derive(Debug, Clone, Copy)]
pub enum NameType {
    HostName = 0x0
}

impl NameType {
    pub fn from_u8(v: u8) -> Option<NameType> {
        match v {
            0x0 => Some(NameType::HostName),
            _ => None
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

#[derive(Debug)]
pub struct ServerName {
    list_len: u16,
    name_type: NameType,
    len: u16,
    value: String,
}

impl ServerName {
    pub fn new() -> ServerName {
        ServerName {
            list_len: 0,
            name_type: NameType::HostName,
            len: 0,
            value: "".to_string(),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> RlsResult<ServerName> {
        let mut res = ServerName::new();
        if bytes.len() == 0 { return Ok(res); }
        res.list_len = u16::from_be_bytes([bytes[0], bytes[1]].try_into()?);
        res.name_type = NameType::from_u8(bytes[2]).ok_or("ServerName Unknown")?;
        res.len = u16::from_be_bytes([bytes[3], bytes[4]].try_into()?);
        res.value = String::from_utf8(bytes[5..res.len as usize + 5].to_vec())?;
        Ok(res)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = vec![0, 0];
        res.push(self.name_type.as_u8());
        res.extend((self.value.len() as u16).to_be_bytes());
        res.extend(self.value.as_bytes());
        let len = (res.len() - 2) as u16;
        res[0..2].clone_from_slice(len.to_be_bytes().as_slice());
        res
    }

    pub fn set_value(&mut self, value: impl ToString) {
        self.value = value.to_string();
        self.len = self.value.len() as u16;
    }
}
