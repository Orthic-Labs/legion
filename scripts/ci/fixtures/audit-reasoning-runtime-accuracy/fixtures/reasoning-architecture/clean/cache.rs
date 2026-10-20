struct Cache { entries: std::collections::HashMap<String, String> }
impl Cache { fn get(&self, key: &str) -> Option<&str> { self.entries.get(key).map(String::as_str) } }
