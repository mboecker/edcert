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

//! This module provides a revoker, which can be used to check if a certificate has been revoked.

use fingerprint::Fingerprint;

/// A type which indicates failure while checking for revokation.
#[derive(Debug, Hash, PartialEq, Eq)]
pub enum RevokeError {
    /// The certificate was revoked.
    Revoked,

    /// The revoke server was not availiable.
    ServerUnavailiable,
}

/// This trait must be implemented for types, which can be revoked.
pub trait Revokable: Fingerprint {
    /// This method can use the revoker to check if it has been revoked.
    ///
    /// **Don't call this method directly, it will be invoked by Revoker::is_revoked(_).**
    fn self_check_revoked<R: Revoker>(&self, revoker: &R) -> Result<(), RevokeError>;
}

/// This trait is used by a `Validator` to check, if a `Certificate` has been revoked.
pub trait Revoker {
    /// This method should return Ok, if the `Certificate` has not been revoked, and Err(_), if it
    /// has been.
    fn is_revoked<F: Revokable + Fingerprint>(&self, &F) -> Result<(), RevokeError>;
}

/// Use this in a Validator to *NOT* check `Certificate`s whether they have been revoked.
/// This is *not* recommended though. If a private key has been disclosed, the `Certificate` MUST be
/// revoked and invalidated, or else the whole system is endangered.
pub struct NoRevoker;

impl Revoker for NoRevoker {
    fn is_revoked<F: Revokable + Fingerprint>(&self, _: &F) -> Result<(), RevokeError> {
        Ok(())
    }
}
