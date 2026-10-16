mod r#static;
mod dynamic;

use std::borrow::Cow;
use r#static::STATIC_TABLE;
use crate::pack::PackItem;
use dynamic::DynamicTable;
use super::index::Index;
use super::QPackType;

pub struct Table {
    static_table: &'static [PackItem; 99],
    dynamic_table: DynamicTable,
}

impl Table {
    pub fn new(max_size: usize) -> Table {
        Table {
            static_table: &STATIC_TABLE,
            dynamic_table: DynamicTable::new(max_size),
        }
    }

    pub fn insert(&mut self, item: PackItem, sid: u64, refer: bool) -> Cow<'_, PackItem> {
        self.dynamic_table.insert(item, sid, refer)
    }

    pub fn get(&mut self, index: usize, sid: u64, dyn_idx: bool, refer: bool) -> Option<&PackItem> {
        match dyn_idx {
            true => self.dynamic_table.index(index, sid, refer),
            false => self.static_table.get(index)
        }
    }

    pub fn get_by_name(&self, name: &str, typ: QPackType) -> Option<(Index, &PackItem)> {
        let static_index = self.static_table.iter().enumerate().find_map(|(index, item)| if item.name() == name {
            match typ {
                QPackType::Stream => Some((Index::NamedIndexed {
                    req_insert: false,
                    idx_dyn: false,
                    index,
                }, item)),
                QPackType::StreamEncoder => Some((Index::IndexedName {
                    idx_dyn: false,
                    index,
                }, item)),
                QPackType::StreamDecoder => unreachable!()
            }
        } else { None });
        if static_index.is_some() { return static_index; }
        self.dynamic_table.get_by_name(name, typ)
    }

    pub fn get_by_name_value(&mut self, name: &str, value: &str, sid: u64, refer: bool) -> Option<Index> {
        let index = self.static_table.iter().enumerate().find_map(|(index, item)| if item.name() == name && item.value() == value {
            Some(Index::Indexed {
                idx_dyn: false,
                index,
            })
        } else { None });
        if index.is_some() { return index; }
        self.dynamic_table.get_by_name_value(name, value, sid, refer)
    }

    pub fn update_table_size(&mut self, max_size: usize) {
        self.dynamic_table.update_table_size(max_size);
    }

    pub fn dynamic_table(&self) -> &DynamicTable {
        &self.dynamic_table
    }

    pub fn dynamic_table_mut(&mut self) -> &mut DynamicTable {
        &mut self.dynamic_table
    }
}


#[cfg(test)]
mod tests {
    use crate::pack::item::pack_item;
    use crate::pack::qpack::index::Index;
    use crate::pack::qpack::QPackType;
    use crate::pack::qpack::table::Table;

    #[test]
    fn test_qpack_table() {
        let mut table = Table::new(4096);
        let item = table.get(17, 0, false, true).unwrap();
        assert_eq!(item.name, ":method");
        assert_eq!(item.value, "GET");

        let (index, item) = table.get_by_name(":authority", QPackType::Stream).unwrap();
        assert_eq!(index, Index::NamedIndexed { req_insert: false, idx_dyn: false, index: 0 });
        let mut item = item.clone();
        item.set_value("www.example.com");
        table.insert(item, 0, true);
        table.dynamic_table_mut().set_increment(1);
        let item = table.get_by_name_value(":authority", "www.example.com", 0, false).unwrap();
        assert_eq!(item, Index::Indexed { idx_dyn: true, index: 0 });

        table.insert(pack_item!(":path","/sample/path"), 0, true);
        let item = table.get(1, 0, true, false).unwrap();
        assert_eq!(item.name, ":path");
        assert_eq!(item.value, "/sample/path");
    }
}