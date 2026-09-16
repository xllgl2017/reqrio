use crate::error::RlsResult;
use crate::{BufferError, Reader, Writer, ALPN};


#[derive(Clone)]
#[cfg_attr(debug_assertions, derive(Debug))]
pub struct ALPS {
    values: Vec<ALPN>,
}

impl ALPS {
    pub fn new(values: Vec<ALPN>) -> ALPS {
        ALPS {
            values
        }
    }
    pub fn from_reader(mut reader: Reader<'_>) -> RlsResult<ALPS> {
        reader.read_u16()?;
        Ok(ALPS {
            values: ALPN::from_reader(&mut reader)?
        })
    }

    pub fn len(&self) -> usize {
        self.values.iter().map(|x| x.len()).sum::<usize>() + 2
    }

    pub fn write_to(self, writer: &mut Writer) -> Result<(), BufferError> {
        writer.write_u16(self.len() as u16 - 2)?;
        for value in self.values {
            value.write_to(writer)?;
        }
        Ok(())
    }

    pub fn remove_h2_alpn(&mut self) {
        if self.values.len() <= 1 {
            self.values = vec![ALPN::HTTP11]
        } else {
            self.values = self.values.clone().into_iter().filter(|x| x != &ALPN::HTTP20).collect();
        }
    }

    pub fn add_h2_alpn(&mut self) {
        self.values.clear();
        self.values = vec![
            ALPN::HTTP20,
            ALPN::HTTP11,
        ]
    }

    pub fn add_alpn(&mut self, alpn: ALPN) {
        self.values.push(alpn);
    }

    pub fn values(&self) -> &Vec<ALPN> {
        &self.values
    }
}