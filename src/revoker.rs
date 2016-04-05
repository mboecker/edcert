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

//! This module provides a revoker, which can be used to check, if a certificate has been revoked.

use validator::Validatable;

/// This trait is used by a `CertificateValidator` to check, if a `Certificate` has been revoked.
pub trait Revoker {
    fn is_revoked<T: Validatable>(&self, &T) -> Result<(), &'static str>;
}

/// Use this in a Validator to *NOT* check `Certificate`s whether they have been revoked.
/// This is *not* recommended though. If a private key has been disclosed, the `Certificate` MUST be
/// revoked and invalidated, or else the whole system is endangered.
pub struct NoRevoker;

impl Revoker for NoRevoker {
    fn is_revoked<T>(&self, _: &T) -> Result<(), &'static str> {
        Ok(())
    }
}
