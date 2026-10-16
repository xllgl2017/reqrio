use std::borrow::Cow;
use crate::pack::PackItem;
use std::collections::{HashMap, VecDeque};
use crate::error::HlsResult;
use crate::pack::qpack::QPackType;
use super::super::index::Index;

pub struct DynamicTable {
    index: usize,
    values: VecDeque<(usize, PackItem)>,
    max_size: usize,
    size: usize,
    ///Decoder 已经收到并处理到第x个动态表插入。
    increment: usize,
    ///我已经完成某个 Header Block的解码
    sec_reqs: HashMap<u64, Vec<usize>>,
}

impl DynamicTable {
    pub fn new(max_size: usize) -> Self {
        DynamicTable {
            index: 0,
            values: VecDeque::with_capacity(100),
            max_size,
            size: 0,
            increment: 0,
            sec_reqs: Default::default(),
        }
    }

    pub fn insert(&mut self, item: PackItem, sid: u64, refer: bool) -> Cow<'_, PackItem> {
        let pass = self.resize(item.item_size());
        if !pass { return Cow::Owned(item); }
        self.size += item.item_size();
        self.values.push_back((self.index, item));
        if refer { self.sec_reqs.entry(sid).or_default().push(self.index) }
        self.index += 1;
        Cow::Borrowed(&self.values[self.values.len() - 1].1)
    }

    fn resize(&mut self, item_size: usize) -> bool {
        debug_assert!(item_size < self.max_size);
        if self.size + item_size <= self.max_size { return true; }
        let mut pos = 0;
        while pos < self.values.len() {
            let Some((index, _)) = self.values.get(pos)else { break; };
            if self.increment <= *index { break; }
            let ref_index = self.sec_reqs.iter().any(|(_, value)| value.iter().any(|x| x == index));
            //查到有被引用的，后面的item不再检查
            if ref_index { break; }
            let Some((_, item)) = self.values.remove(pos)else {
                pos += 1;
                continue;
            };
            self.size -= item.item_size();
        }
        self.size + item_size <= self.max_size
    }

    pub fn index(&mut self, index: usize, sid: u64, refer: bool) -> Option<&PackItem> {
        let item = self.values.iter().find(|(i, _)| i == &index);
        if item.is_some() && refer {
            self.sec_reqs.entry(sid).or_default().push(index);
        }
        item.map(|(_, item)| item)
    }

    pub fn section_ack(&mut self, sid: u64) {
        self.sec_reqs.remove(&sid);
    }

    pub fn get_by_name_value(&mut self, name: &str, value: &str, sid: u64, refer: bool) -> Option<Index> {
        for i in 0..self.values.len() {
            let (index, item) = &self.values[self.values.len() - 1 - i];
            if item.name() == name && item.value() == value {
                if refer { self.sec_reqs.entry(sid).or_default().push(*index); }
                return Some(match *index >= self.increment {
                    true => Index::PostBase(*index),
                    false => Index::Indexed {
                        index: *index,
                        idx_dyn: true,
                    }
                });
            }
        }
        None
    }

    pub fn get_by_name(&self, name: &str, typ: QPackType) -> Option<(Index, &PackItem)> {
        for i in 0..self.values.len() {
            let (index, item) = &self.values[self.values.len() - 1 - i];
            if item.name() != name { continue; }
            return match typ {
                QPackType::Stream => match *index >= self.increment {
                    true => Some((Index::NamePostBase {
                        index: *index,
                        req_insert: false,
                    }, item)),
                    false => Some((Index::NamedIndexed {
                        req_insert: false,
                        idx_dyn: true,
                        index: *index,
                    }, item))
                },
                QPackType::StreamEncoder => Some((Index::IndexedName {
                    idx_dyn: true,
                    index: *index,
                }, item)),
                QPackType::StreamDecoder => unreachable!()
            };
        }
        None
    }

    pub fn update_table_size(&mut self, max_size: usize) {
        self.max_size = max_size;
        self.resize(0);
    }

    pub fn item_count(&self) -> usize {
        self.values.len()
    }

    // pub fn max_size(&self) -> usize {
    //     self.max_size
    // }

    pub fn set_increment(&mut self, increment: usize) {
        self.increment = increment;
    }

    pub fn cal_req_count(&self, enc: usize) -> HlsResult<usize> {
        if enc == 0 { return Ok(0); }
        let max_entries = self.max_size / 32;
        let full_range = 2 * max_entries;
        let max_value = self.item_count() + max_entries;
        let max_wrapped = (max_value / full_range) * full_range;
        let mut req_count = max_wrapped + enc - 1;
        if req_count > max_value {
            if req_count <= full_range { return Err("req_count<=full_range".into()); }
            req_count -= full_range;
        }
        if req_count == 0 { return Err("req_count=0".into()); }
        Ok(req_count)
    }

    pub fn duplicate(&mut self, index: usize) -> HlsResult<()> {
        let item = self.index(index, 0, false).ok_or("duplicate failed")?.clone();
        self.insert(item, 0, false);
        Ok(())
    }

    pub fn en_req_count(&self) -> usize {
        if self.values.is_empty() { return 0; }
        (self.values.len() % (2 * (self.max_size / 32))) + 1
    }
}

#[cfg(test)]
mod tests {
    use crate::pack::item::pack_item;
    use crate::pack::PackItem;
    use crate::pack::qpack::table::dynamic::DynamicTable;

    #[test]
    fn test_dynamic_table() {
        let mut table = DynamicTable::new(4096);
        table.insert(pack_item!(":authority", "www.example.com"), 0, false);
        assert_eq!(table.size, 57);
        assert_eq!(table.index, 1);
        let item = table.index(0, 0, true);
        assert!(item.is_some());
    }

    #[test]
    fn test_req_insert_count() {
        let mut table = DynamicTable::new(220);
        assert_eq!(table.cal_req_count(3).unwrap(), 2);
        table.insert(PackItem::new(":authority", "www.example.com"), 0, false);
        table.insert(PackItem::new(":authority", "www.example.com"), 0, false);
        assert_eq!(3, table.en_req_count())
    }
}