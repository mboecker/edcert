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

//! This module contains the `CertificateValidator`, which can be used to validate `Certificate`s,
//! as well as some traits used by the struct.

/// This trait can be implemented to verify `Validatable`s with it.
pub trait Validator {
    fn is_valid<V: Validatable>(&self, cert: &V) -> Result<(), &'static str>;
    fn get_master_public_key(&self) -> &[u8];
}

/// This trait is implemented for types, which must be validated.
pub trait Validatable {
    /// This method is given validator. It can access the master public key using the
    /// CertificateValidator.
    fn is_valid<T: Validator>(&self, &T) -> Result<(), &'static str>;

    /// This method should return true iff the object can be revoked.
    /// That is true for a public key, but not for a signature.
    fn is_revokable(&self) -> bool;

    /// If is_revokable() returns true, you must implement this function. It must return a string
    /// which is unique to the keypair.
    fn get_key_id(&self) -> String;

    /// This method must be implemented for all certificates and must return a string with was
    /// created from all important information in the certificate, eg. public key, expiration date
    /// and meta data.
    fn get_certificate_id(&self) -> String;
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
