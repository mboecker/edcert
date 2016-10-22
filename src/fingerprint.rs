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

//! This module contains the trait `Fingerprint`. It provides a fingerprint() method, which is
//! used in cryptographic context to identify some value. For example, a `Certificate` implements
//! `Fingerprint` and returns its public key on fingerprint(). On the other hand, secure
//! containers (like Letter<T> in edcert-letter) could return a hash of the contained value.

/// The fingerprint method should return a value that is unique to the implementing type.
pub trait Fingerprint {
    /// The fingerprint method should return a value that is unique to the implementing type.
    fn fingerprint(&self) -> Vec<u8>;
}

impl<T> Fingerprint for T
    where T: AsRef<[u8]>
{
    fn fingerprint(&self) -> Vec<u8> {
        self.as_ref().into()
    }
}
