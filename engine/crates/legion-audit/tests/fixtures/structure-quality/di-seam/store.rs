pub trait Store {
    fn get(&self, key: &str) -> Option<String>;
    fn put(&mut self, key: &str, value: String);
}

pub struct MemoryStore;

impl Store for MemoryStore {
    fn get(&self, key: &str) -> Option<String> {
        let _ = key;
        None
    }
    fn put(&mut self, key: &str, value: String) {
        let _ = (key, value);
    }
}

pub struct FakeStore;

impl Store for FakeStore {
    fn get(&self, key: &str) -> Option<String> {
        Some(key.to_owned())
    }
    fn put(&mut self, key: &str, value: String) {
        let _ = (key, value);
    }
}

fn orphaned_helper() -> u32 {
    42
}
