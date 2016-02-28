use std::collections::BTreeMap;
use rustc_serialize::Encodable;
use rustc_serialize::Encoder;
use sodiumoxide::crypto::hash::sha512;

#[derive(Clone,RustcEncodable,RustcDecodable,Debug)]
pub struct Meta {
    values: BTreeMap<String, String>,
}

impl Meta {
    pub fn new_empty() -> Meta {
        Meta { values: BTreeMap::new() }
    }

    pub fn new(values: BTreeMap<String, String>) -> Meta {
        Meta { values: values }
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

	pub fn get_values(&mut self) -> &mut BTreeMap<String, String> {
		&mut self.values
	}

    pub fn fill_bytes(&self, bytes: &mut [u8]) {

        let mut hash = [0; 64];

        for key in self.values.keys() {
            let value = self.values.get(key).unwrap();
            add_hash(&mut hash, &sha512::hash(key.as_bytes()).0);
            add_hash(&mut hash, &sha512::hash(value.as_bytes()).0);
        }

        copy_bytes(bytes, &hash, 0, 0, hash.len())
    }
}

//impl Encodable for Meta {
//    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
//        self.values.encode(s)
//    }
//}



/// This is a simple copy function. This should be replaced by memcpy or something...
fn copy_bytes(dest: &mut [u8], src: &[u8], start_dest: usize, start_src: usize, len: usize) {
    for i in 0..(len - 1) {
        dest[start_dest + i] = src[start_src + i];
    }
}

fn add_hash(h1: &mut [u8], h2: &[u8]) {
    for i in 0..(h1.len()) {
        let a: u16 = ((h1[i] as u16) + (h2[i] as u16)) % 256;
        h1[i] = a as u8;
    }
}
