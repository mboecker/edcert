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

//! This module provides a validator, which analyzes the trust chain to validate a Certificate.

use validator::ValidationError;
use validator::Validator;
use validator::Validatable;
use bytescontainer::BytesContainer;
use revoker::Revoker;
use revoker::Revokable;

/// This is a simple Validator, which checks the trust chain for valid certificates. The top-most
/// Certificate must be signed with the right master private key.
#[derive(Clone,Debug,PartialEq)]
pub struct RootValidator<R: Revoker> {
    revoker: R,
    master_public_key: BytesContainer,
}

impl<R: Revoker> RootValidator<R> {
    /// Call this to create a CV with a revoke server.
    /// For every certificate the revoke server is asked if it is known.
    pub fn new(master_public_key: &[u8; 32], revoker: R) -> RootValidator<R> {
        let mut vec: Vec<u8> = Vec::new();
        vec.extend_from_slice(master_public_key);

        RootValidator {
            revoker: revoker,
            master_public_key: BytesContainer::new(vec),
        }
    }
}

impl<R: Revoker> Validator for RootValidator<R> {
    /// Checks the certificate if it is valid.
    /// If the CV knows a revoke server, that is queried as well.
    fn is_valid<V: Validatable + Revokable>(&self, cert: &V) -> Result<(), ValidationError> {
        // this returns an Error if it fails
        try!(cert.self_validate(self));

        // this returns an Error if it fails
        try!(self.revoker.is_revoked(cert));

        // if nothing fails, the certificate is valid!
        Ok(())
    }

    /// Checks if the signature is valid.
    fn is_signature_valid(&self, data: &[u8], signature: &[u8]) -> bool {
        use ed25519;
        ed25519::verify(data, signature, self.master_public_key.get())
    }
}
