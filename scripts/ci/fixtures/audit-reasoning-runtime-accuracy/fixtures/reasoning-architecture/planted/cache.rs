// Symbol index grows with project; get runs for each reference resolution.
struct Cache { entries: Vec<(String, String)> }
impl Cache { fn get(&self, key: &str) -> Option<&str> { self.entries.iter().find(|(k,_)| k == key).map(|(_,v)| v.as_str()) } }
