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

//! This module contains the `Validator`, which can be used to validate `Certificate`s,
//! as well as some traits used by the struct.

use revoker::RevokeError;
use revoker::Revokable;

/// This type contains information about why a validation failed.
#[derive(Debug, Hash, PartialEq, Eq)]
pub enum ValidationError {
    /// Some signature is invalid.
    SignatureInvalid,

    /// The parent certificate is invalid.
    ParentInvalid,

    /// Something is expired.
    Expired,

    /// The certificate has been revoked.
    Revoked,

    /// Some other error happened while trying to validate. (eg. a server was not responding)
    Other,
}

impl From<RevokeError> for ValidationError {
    fn from(r: RevokeError) -> ValidationError {
        match r {
            RevokeError::Revoked => ValidationError::Revoked,
            _ => ValidationError::Other,
        }
    }
}

/// This trait must be implemented for types, which must be validated.
pub trait Validatable {
    /// This method is given a validator. It can access the master public key indirectly using the
    /// `Validator`.
    ///
    /// **Don't call this method directly, it will be called if you call Validator::is_valid(_).**
    fn self_validate<T: Validator>(&self, validator: &T) -> Result<(), ValidationError>;
}

/// This trait can be implemented to verify `Validatable`s with it.
pub trait Validator {
    /// This method is called with a certificate or a secure container, which should be validated.
    fn is_valid<V: Validatable + Revokable>(&self, cert: &V) -> Result<(), ValidationError>;

    /// This method will check if the given signature is a valid signature issued by the master
    /// key.
    fn is_signature_valid(&self, data: &[u8], signature: &[u8]) -> bool;
}

#[test]
fn test_validator() {
    use ed25519;
    use chrono::Timelike;
    use chrono::UTC;
    use chrono::duration::Duration;
    use meta::Meta;
    use certificate::Certificate;
    use root_validator::RootValidator;
    use revoker::NoRevoker;

    let (mpk, msk) = ed25519::generate_keypair();

    let cv = RootValidator::new(&mpk, NoRevoker);

    let meta = Meta::new_empty();
    let expires = UTC::now()
        .checked_add(Duration::days(90))
        .expect("Failed to add 90 days to expiration date.")
        .with_nanosecond(0)
        .unwrap();

    let mut cert = Certificate::generate_random(meta.clone(), expires.clone());

    cert.sign_with_master(&msk);

    assert_eq!(cv.is_valid(&cert).is_ok(), true);

    let cert_invalid = Certificate::generate_random(meta.clone(), expires.clone());

    assert_eq!(cv.is_valid(&cert_invalid).is_ok(), false);
}

#[test]
fn test_meta_can_sign() {
    use ed25519;
    use chrono::Timelike;
    use chrono::UTC;
    use chrono::duration::Duration;
    use meta::Meta;
    use certificate::Certificate;
    use root_validator::RootValidator;
    use revoker::NoRevoker;

    let (mpk, msk) = ed25519::generate_keypair();

    let cv = RootValidator::new(&mpk, NoRevoker);

    let mut meta = Meta::new_empty();
    let expires = UTC::now()
        .checked_add(Duration::days(90))
        .expect("Failed to add 90 days to expiration date.")
        .with_nanosecond(0)
        .unwrap();

    {
        let mut cert = Certificate::generate_random(meta.clone(), expires.clone());
        cert.sign_with_master(&msk);
        assert_eq!(cv.is_valid(&cert).is_ok(), true);

        let mut cert_child = Certificate::generate_random(meta.clone(), expires.clone());
        cert.sign_certificate(&mut cert_child).expect("Failed to sign certificate");
        assert_eq!(cv.is_valid(&cert_child).is_ok(), false);
    }

    {
        meta.set("use-for", "[\"edcert.sign\"]");

        let mut cert = Certificate::generate_random(meta.clone(), expires.clone());
        cert.sign_with_master(&msk);
        assert_eq!(cv.is_valid(&cert).is_ok(), true);

        let mut cert_child = Certificate::generate_random(meta.clone(), expires.clone());
        cert.sign_certificate(&mut cert_child).expect("Failed to sign certificate");
        assert_eq!(cv.is_valid(&cert_child).is_ok(), true);
    }
}
