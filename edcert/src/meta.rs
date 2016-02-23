use std::collections::BTreeMap;
use rustc_serialize::json;
use rustc_serialize::Encodable;
use rustc_serialize::Encoder;

#[derive(Clone)]
pub struct Meta {
    values: BTreeMap<String, String>,
}

impl Meta {
    pub fn new() -> Meta {
        Meta { values: BTreeMap::new() }
    }

    pub fn key_exists(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    pub fn get(&self, key: &str) -> Option<&String> {
        self.values.get(key)
    }

    pub fn set(&mut self, key: &str, value: &str) {
        self.values.insert(key.to_string(), value.to_string());
    }

    pub fn fill_bytes(&self, bytes: &mut [u8]) {

        let mut next_position: usize = 0;

        for key in self.values.keys() {
            let key_bytes: &[u8] = key.as_bytes();
            let value_bytes: &[u8] = match self.values.get(key) {
                Some(value) => value.as_bytes(),
                None => panic!("lel"),
            };

            let key_size = key_bytes.len();
            let value_size = value_bytes.len();

            copy_bytes(bytes, key_bytes, next_position, 0, key_size);

            next_position += key_size;

            copy_bytes(bytes, value_bytes, next_position, 0, value_size);
        }
    }
}

impl Encodable for Meta {
	fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
		self.values.encode(s)
	}
}

/// This is a simple copy function. This should be replaced by memcpy or something...
fn copy_bytes(dest: &mut [u8], src: &[u8], start_dest: usize, start_src: usize, len: usize) {
    for i in 0..(len - 1) {
        dest[start_dest + i] = src[start_src + i];
    }
}
