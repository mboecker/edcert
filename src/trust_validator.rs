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

//! This module provides a validator, which analyzes the trust chain to validate a Certificate but
//! instead of a single master signature, it uses a set of trusted certificates for validation.

use validator::Validator;
use validator::Validatable;
use bytescontainer::BytesContainer;
use revoker::Revoker;

/// This is a simple Validator, which checks the trust chain for valid certificates. The top-most
/// Certificate must be signed with the right master private key.
#[derive(Clone,Debug,PartialEq)]
pub struct TrustValidator<R: Revoker> {
    revoker: R,
    trusted_certificates: Vec<String>,
    master_public_key: BytesContainer,
}

impl<R: Revoker> TrustValidator<R> {
    /// Call this to create a CV with a revoke server.
    /// For every certificate the revoke server is asked if it is known.
    pub fn new(master_public_key: &[u8; 32], revoker: R) -> TrustValidator<R> {
        let mut vec: Vec<u8> = Vec::new();
        vec.extend_from_slice(master_public_key);

        TrustValidator {
            revoker: revoker,
            master_public_key: BytesContainer::new(vec),
            trusted_certificates: Vec::new(),
        }
    }

    /// Call this to create a CV with a revoke server and the given set of trusted certificates.
    /// For every certificate the revoke server is asked if it is known.
    pub fn with_trusted_certificates(master_public_key: &[u8; 32],
                                     revoker: R,
                                     trusted_certificates: Vec<String>)
                                     -> TrustValidator<R> {
        let mut vec: Vec<u8> = Vec::new();
        vec.extend_from_slice(master_public_key);

        TrustValidator {
            revoker: revoker,
            master_public_key: BytesContainer::new(vec),
            trusted_certificates: trusted_certificates,
        }
    }

    /// This method trusts the give certificates.
    pub fn add_trusted_certificates<T: AsRef<[String]>>(&mut self, trusted_certificates: T) {
        self.trusted_certificates.extend_from_slice(trusted_certificates.as_ref());
    }

    /// This method calls the revoker to check the status of the certificate cert.
    pub fn is_revoked<V: Validatable>(&self, cert: &V) -> Result<(), &'static str> {
        self.revoker.is_revoked(cert)
    }
}

impl<R: Revoker> Validator for TrustValidator<R> {
    /// Checks the certificate if it is valid.
    /// If the CV knows a revoke server, that is queried as well.
    fn is_valid<V: Validatable>(&self, cert: &V) -> Result<(), &'static str> {
        // if the certificate is trusted, it is valid
        if self.trusted_certificates.contains(&cert.get_certificate_id()) {
            return Ok(());
        }

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

#[test]
fn test_trusted_certificates() {
    use meta::Meta;
    use certificate::Certificate;
    use revoker::NoRevoker;
    use chrono::datetime::DateTime;
    use chrono::UTC;

    let mut meta = Meta::new_empty();
    meta.set("use-for", r#"["edcert.sign"]"#);

    let cert: Certificate = Certificate::generate_random(meta,
                                                         DateTime::parse_from_rfc3339("2020-01-0\
                                                                                       1T00:00:0\
                                                                                       0+00:00")
                                                             .unwrap()
                                                             .with_timezone(&UTC));
    let mut child: Certificate = Certificate::generate_random(Meta::new_empty(),
                                                              DateTime::parse_from_rfc3339("2020\
                                                                                            -01-\
                                                                                            01T0\
                                                                                            0:00\
                                                                                            :00+\
                                                                                            00:0\
                                                                                            0")
                                                                  .unwrap()
                                                                  .with_timezone(&UTC));

    cert.sign_certificate(&mut child).unwrap();

    let trusted = vec![cert.get_certificate_id()];

    let cv = TrustValidator::with_trusted_certificates(&[0; 32], NoRevoker, trusted);

    match cv.is_valid(&child) {
        Err(x) => {
            println!("{:?}", x);
            panic!();
        }
        _ => {}
    };

    assert_eq!(cv.is_valid(&child).is_ok(), true);
}

#[test]
fn test_add_trusted_certificates() {
    use meta::Meta;
    use certificate::Certificate;
    use revoker::NoRevoker;
    use chrono::datetime::DateTime;
    use chrono::UTC;

    let meta = Meta::new_empty();

    let cert: Certificate = Certificate::generate_random(meta,
                                                         DateTime::parse_from_rfc3339("2020-01-0\
                                                                                       1T00:00:0\
                                                                                       0+00:00")
                                                             .unwrap()
                                                             .with_timezone(&UTC));

    let mut cv = TrustValidator::new(&[0; 32], NoRevoker);

    assert_eq!(cv.is_valid(&cert).is_ok(), false);

    cv.add_trusted_certificates(vec![cert.get_certificate_id()]);

    assert_eq!(cv.is_valid(&cert).is_ok(), true);
}

#[test]
fn test_trusted_certificates_fail() {
    use meta::Meta;
    use certificate::Certificate;
    use revoker::NoRevoker;
    use chrono::datetime::DateTime;
    use chrono::UTC;

    let mut meta = Meta::new_empty();
    meta.set("use-for", r#"["edcert.sign"]"#);

    let cert: Certificate = Certificate::generate_random(meta,
                                                         DateTime::parse_from_rfc3339("2020-01-0\
                                                                                       1T00:00:0\
                                                                                       0+00:00")
                                                             .unwrap()
                                                             .with_timezone(&UTC));
    let child: Certificate = Certificate::generate_random(Meta::new_empty(),
                                                          DateTime::parse_from_rfc3339("2020-01-\
                                                                                        01T00:00\
                                                                                        :00+00:0\
                                                                                        0")
                                                              .unwrap()
                                                              .with_timezone(&UTC));

    let trusted = vec![cert.get_certificate_id()];

    let cv = TrustValidator::with_trusted_certificates(&[0; 32], NoRevoker, trusted);

    assert_eq!(cv.is_valid(&child).is_ok(), false);
}
