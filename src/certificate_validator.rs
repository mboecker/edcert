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

//! This module contains the CertificateValidator, which can be used to validate certificates, as
//! well as some traits used by the struct.

use bytescontainer::BytesContainer;

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

    /// If is_revokable() returns true, you must implement this function. It should return a
    /// representation by which the object can be identified by the revoke-list or revoke server.
    fn get_id(&self) -> String;
}

/// This trait is used by a CertificateValidator to check, if a Certificate has been revoked.
pub trait Revoker {
    fn is_revoked<T: Validatable>(&self, &T) -> Result<(), &'static str>;
}

/// This struct can be used to validate Certificates.
#[derive(Clone,Debug,PartialEq)]
pub struct CertificateValidator<R: Revoker> {
    revoker: R,
    master_public_key: BytesContainer,
}

impl<R: Revoker> CertificateValidator<R> {
    /// Call this to create a CV with a revoke server.
    /// For every certificate the revoke server is asked if it is known.
    pub fn new(master_public_key: &[u8; 32], revoker: R) -> CertificateValidator<R> {
        let mut vec: Vec<u8> = Vec::new();
        vec.extend_from_slice(master_public_key);

        CertificateValidator {
            revoker: revoker,
            master_public_key: BytesContainer::new(vec),
        }
    }

    /// This method calls the revoker to check the status of the certificate cert.
    pub fn is_revoked<V: Validatable>(&self, cert: &V) -> Result<(), &'static str> {
        self.revoker.is_revoked(cert)
    }
}

impl<R: Revoker> Validator for CertificateValidator<R> {
    /// Checks the certificate if it is valid.
    /// If the CV knows a revoke server, that is queried as well.
    fn is_valid<V: Validatable>(&self, cert: &V) -> Result<(), &'static str> {
        // this returns an Error if it fails
        try!(cert.is_valid(self));

        // this returns an Error if it fails
        try!(self.revoker.is_revoked(cert));

        // if nothing fails, the certificate is valid!
        Ok(())
    }

    fn get_master_public_key(&self) -> &[u8] {
        &self.master_public_key.get()[..]
    }
}

/// Use this in a CertificateValidator to *NOT* check Certificate whether they have been revoked.
/// This is *not* recommended though. If a private key has been disclosed, the certificate MUST be
/// revoked and invalidated, or else the whole system is endangered.
pub struct NoRevoker;

impl Revoker for NoRevoker {
    fn is_revoked<T>(&self, _: &T) -> Result<(), &'static str> {
        Ok(())
    }
}

#[test]
fn test_validator() {
    use ed25519;
    use chrono::Timelike;
    use chrono::UTC;
    use time::Duration;
    use meta::Meta;
    use certificate::Certificate;

    let (mpk, msk) = ed25519::generate_keypair();

    let cv = CertificateValidator::new(&mpk, NoRevoker);

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
    use time::Duration;
    use meta::Meta;
    use certificate::Certificate;

    let (mpk, msk) = ed25519::generate_keypair();

    let cv = CertificateValidator::new(&mpk, NoRevoker);

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
