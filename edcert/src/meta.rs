use std::collections::BTreeMap;

pub struct Meta {
	values : BTreeMap<String, String>,
}

impl Meta {
	pub fn new() -> Meta {
		Meta {
			values : BTreeMap::new(),
		}
	}
	
	pub fn get(&self, key : &str) -> Option<&String> {
		self.values.get(key)
	}
	
	pub fn set(&mut self, key : &str, value : &str) {
		self.values.insert(key.to_string(), value.to_string());
	}
}