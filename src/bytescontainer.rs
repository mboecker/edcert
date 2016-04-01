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

use rustc_serialize::Encoder;
use rustc_serialize::Encodable;
use rustc_serialize::Decoder;
use rustc_serialize::Decodable;
use rustc_serialize::hex::FromHex;

#[derive(Clone,Debug,PartialEq)]
pub struct BytesContainer {
    bytes: Vec<u8>,
}

impl BytesContainer {
    pub fn new(bytes: Vec<u8>) -> BytesContainer {
        BytesContainer { bytes: bytes }
    }

    pub fn get<'a>(&'a self) -> &'a Vec<u8> {
        &self.bytes
    }

    // pub fn get_mut<'a>(&'a mut self) -> &'a mut Vec<u8> {
    //     &mut self.bytes
    // }

    pub fn to_bytestr(&self) -> String {
        let bytestr: Vec<String> = self.bytes.iter().map(|b| format!("{:02X}", b)).collect();
        bytestr.join("")
    }

    pub fn from_bytestr(bytestr: &str) -> Result<BytesContainer, ()> {
        if bytestr.is_empty() {
            return Ok(BytesContainer::new(vec![]));
        }
        match bytestr.from_hex() {
            Ok(vec) => Ok(BytesContainer::new(vec)),
            _ => Err(()),
        }
    }
}

impl Decodable for BytesContainer {
    fn decode<T: Decoder>(d: &mut T) -> Result<BytesContainer, T::Error> {
        let bytestr = try!(String::decode(d));
        match BytesContainer::from_bytestr(&bytestr) {
            Ok(bc) => Ok(bc),
            Err(_) => Err(d.error("Failed to parse hex string")),
        }
    }
}

impl Encodable for BytesContainer {
    fn encode<T: Encoder>(&self, d: &mut T) -> Result<(), T::Error> {
        self.to_bytestr().encode(d)
    }
}

impl Drop for BytesContainer {
    fn drop(&mut self) {
        for i in 0..self.bytes.len() {
            self.bytes[i] = 0;
        }
    }
}

#[test]
fn test_encoding() {
    use rustc_serialize::json;

    let bc = BytesContainer::new(vec![1, 2, 3, 100]);
    assert_eq!(json::encode(&bc).unwrap(), "\"01020364\"");
    let bc = BytesContainer::new(vec![]);
    assert_eq!(json::encode(&bc).unwrap(), "\"\"");
}

#[test]
fn test_decoding() {
    use rustc_serialize::json;

    let bytestr = "\"A099\"";
    let bc: BytesContainer = json::decode(bytestr).unwrap();
    assert_eq!(bc.get(), &vec![160, 153]);

    let bytestr = "\"\"";
    let bc: BytesContainer = json::decode(bytestr).unwrap();
    assert_eq!(bc.get(), &vec![]);
}

#[test]
fn test_memclear() {
    unsafe {
        // this will point to the vec of bytes
        let ptr: *const Vec<u8>;

        // init a vec and let it go out of scope
        {
            let a = vec![1, 2, 3];
            let bc = BytesContainer::new(a);

            // assign pointer
            ptr = bc.get();
        }

        // now the data should be cleared
        assert_eq!(*ptr, vec![0, 0, 0]);
    }
}
