// The MIT License (MIT)
//
// Copyright (c) 2016 Marvin Böcker
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

//! This module contains the struct which holds the meta data of a Certificate.

use std::collections::BTreeMap;

/// This struct holds meta data for a Certificate. It is also capable of generating a hash, which
/// is based on SHA512. The hash is equal, regardless of the ordering of meta elements.
#[derive(Clone,RustcEncodable,RustcDecodable,Debug,PartialEq)]
pub struct Meta {
    values: BTreeMap<String, String>,
}

impl Meta {
    /// Creates a new Meta object, which can be used to store metadata for a certificate.
    pub fn new_empty() -> Meta {
        Meta { values: BTreeMap::new() }
    }

    /// Creates a new Meta object using the given BTreeMap.
    pub fn new(values: BTreeMap<String, String>) -> Meta {
        Meta { values: values }
    }

    /// This method returns true iff the key exists.
    pub fn key_exists(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// This method returns the value of key, if it exists. Otherwise it returns None.
    pub fn get(&self, key: &str) -> Option<&String> {
        self.values.get(key)
    }

    /// This method assigns a value to a given key.
    pub fn set(&mut self, key: &str, value: &str) {
        self.values.insert(key.to_string(), value.to_string());
    }

    /// This method returns a mutable reference to the tree object.
    pub fn values_mut(&mut self) -> &mut BTreeMap<String, String> {
        &mut self.values
    }

    /// This method returns a reference to the tree object.
    pub fn values(&self) -> &BTreeMap<String, String> {
        &self.values
    }

    /// This method fills the given byte vector with a "hash" which is created from all keys
    /// and values.
    pub fn fill_bytes(&self, bytes: &mut [u8]) {
        use sodiumoxide::crypto::hash::sha512;

        let mut hash = [0; 64];

        for key in self.values.keys() {
            let value = self.values.get(key).unwrap();
            add_hash(&mut hash, &sha512::hash(key.as_bytes()).0);
            add_hash(&mut hash, &sha512::hash(value.as_bytes()).0);
        }

        copy_bytes(bytes, &hash, 0, 0, hash.len())
    }
}

/// This is a simple copy function. This should be replaced by memcpy or something...
fn copy_bytes(dest: &mut [u8], src: &[u8], start_dest: usize, start_src: usize, len: usize) {
    for i in 0..(len - 1) {
        dest[start_dest + i] = src[start_src + i];
    }
}

/// This method adds h2 to h1.
fn add_hash(h1: &mut [u8], h2: &[u8]) {
    for i in 0..(h1.len()) {
        let a: u16 = ((h1[i] as u16) + (h2[i] as u16)) % 256;
        h1[i] = a as u8;
    }
}
