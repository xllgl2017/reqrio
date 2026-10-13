use std::ops::Index;
use crate::pack::PackItem;
use std::slice::Iter;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

pub struct DynamicTable {
    values: Vec<PackItem>,
    max_size: Arc<AtomicUsize>,
    size: usize,
}

impl Default for DynamicTable {
    fn default() -> Self {
        DynamicTable::new_size(4096)
    }
}

impl DynamicTable {
    pub fn new_size(max_size: usize) -> Self {
        DynamicTable {
            values: Vec::with_capacity(256),
            max_size: Arc::new(AtomicUsize::new(max_size)),
            size: 0,
        }
    }
    #[cfg(test)]
    pub fn size(&self) -> usize { self.size }

    ///动态表插入时应位于最前端
    ///
    /// 文档文档rfc7541-4.4
    pub fn insert(&mut self, item: PackItem) {
        self.size += item.item_size();
        self.values.insert(0, item);
        self.resize();
    }

    /// 动态表的索引应该减去静态表的长度
    ///
    /// 文档文档rfc7541-2.3.3
    pub fn get(&self, index: usize) -> Option<&PackItem> {
        let index = index - 61;
        self.values.get(index)
    }

    ///动态表的item遵循先入先出
    ///
    /// 文档文档rfc7541-4.3
    fn resize(&mut self) {
        while self.size > self.max_size.load(Ordering::SeqCst) {
            match self.values.pop() {
                None => self.size = 0,
                Some(item) => self.size -= item.item_size(),
            }
        }
    }

    pub fn update_table_size(&mut self, max_size: usize) {
        self.max_size.store(max_size, Ordering::SeqCst);
        self.resize();
    }

    pub fn max_size(&self)->&Arc<AtomicUsize> {
        &self.max_size
    }

    pub fn iter(&self) -> Iter<'_, PackItem> {
        self.values.iter()
    }
}

impl Index<usize> for DynamicTable {
    type Output = PackItem;
    fn index(&self, index: usize) -> &Self::Output {
        &self.values[index]
    }
}