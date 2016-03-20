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

use bytescontainer::BytesContainer;
use certificate::Certificate;
use rustc_serialize::Encodable;
use rustc_serialize::Encoder;
use rustc_serialize::Decoder;

#[derive(Clone,RustcDecodable,RustcEncodable,Debug)]
pub struct Signature {
    /// This is the actual signature generated with the certificate data and the parents private key
    /// It can be validated with the parents public key.
    hash: BytesContainer,

    /// If this is None, then the Certificate is signed with the master key.
    signed_by: Option<Box<Certificate>>,
}

impl Signature {
    /// Creates a new Signature with the given signature. It is assumed that the signature is
    /// computed usign the master key.
    pub fn new(signature: Vec<u8>) -> Signature {
        Signature {
            hash: BytesContainer::new(signature),
            signed_by: None,
        }
    }

    /// Creates a new Signature with the given parent and given signature.
    pub fn with_parent(parent: Box<Certificate>, signature: Vec<u8>) -> Signature {
        Signature {
            hash: BytesContainer::new(signature),
            signed_by: Some(parent),
        }
    }

    /// This method will return true iff the certificate has no parent certificate.
    /// It is then signed with the master key.
    pub fn is_signed_by_master(&self) -> bool {
        self.signed_by.is_none()
    }

    /// This method will return the parent Certificate, or None, if it is signed with the
    /// master key.
    pub fn get_parent(&self) -> Option<&Certificate> {
        if self.signed_by.is_none() {
            None
        } else {
            let parent: &Certificate = self.signed_by.as_ref().unwrap();
            Some(parent)
        }
    }

    /// This method will return the signature given by the parent.
    pub fn get_hash(&self) -> &Vec<u8> {
        &self.hash.get()
    }
}
