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

use validator::ValidationError;
use validator::Validator;
use validator::Validatable;
use revoker::RevokeError;
use revoker::Revoker;
use revoker::Revokable;

/// This is a simple Validator, which checks the trust chain for valid certificates. The top-most
/// Certificate must be signed with the right master private key.
#[derive(Clone,Debug,PartialEq)]
pub struct TrustValidator<R: Revoker> {
    revoker: R,
    trusted_certificates: Vec<Vec<u8>>,
}

impl<R: Revoker> TrustValidator<R> {
    /// Call this to create a CV with a revoke server.
    /// For every certificate the revoke server is asked if it is known.
    pub fn new(revoker: R) -> TrustValidator<R> {
        TrustValidator {
            revoker: revoker,
            trusted_certificates: Vec::new(),
        }
    }

    /// Call this to create a CV with a revoke server and the given set of trusted certificates.
    /// For every certificate the revoke server is asked if it is known.
    pub fn with_trusted_certificates<T>(trusted_certificates: T, revoker: R) -> TrustValidator<R>
        where T: Into<Vec<Vec<u8>>>
    {
        TrustValidator {
            revoker: revoker,
            trusted_certificates: trusted_certificates.into(),
        }
    }

    /// This method trusts the give certificates.
    pub fn add_trusted_certificates<T>(&mut self, trusted_certificates: T)
        where T: IntoIterator<Item = Vec<u8>>
    {
        self.trusted_certificates.extend(trusted_certificates);
    }

    /// This method calls the revoker to check the status of the certificate cert.
    pub fn is_revoked<V: Revokable>(&self, cert: &V) -> Result<(), RevokeError> {
        self.revoker.is_revoked(cert)
    }
}

impl<R: Revoker> Validator for TrustValidator<R> {
    /// Checks the certificate if it is valid.
    /// If the CV knows a revoke server, that is queried as well.
    fn is_valid<V: Validatable + Revokable>(&self, cert: &V) -> Result<(), ValidationError> {
        // if the certificate is trusted, it is valid
        if self.trusted_certificates.contains(&cert.fingerprint()) {
            return Ok(());
        }

        // this returns an Error if it fails
        try!(cert.self_validate(self));

        // this returns an Error if it fails
        try!(self.revoker.is_revoked(cert));

        // if nothing fails, the certificate is valid!
        Ok(())
    }

    fn is_signature_valid(&self, _: &[u8], _: &[u8]) -> bool {
        // The TrustValidator is not using a single root public key, so no certificate signed by
        // a "root" key is valid.
        false
    }
}

#[test]
fn test_trusted_certificates() {
    use fingerprint::Fingerprint;
    use meta::Meta;
    use certificate::Certificate;
    use revoker::NoRevoker;
    use chrono::datetime::DateTime;
    use chrono::UTC;

    let mut meta = Meta::new_empty();
    meta.set("use-for", r#"["edcert.sign"]"#);

    let cert: Certificate =
        Certificate::generate_random(meta,
                                     DateTime::parse_from_rfc3339("2020-01-01T00:00:00+00:00")
                                         .unwrap()
                                         .with_timezone(&UTC));
    let mut child: Certificate =
        Certificate::generate_random(Meta::new_empty(),
                                     DateTime::parse_from_rfc3339("2020-01-01T00:00:00+00:00")
                                         .unwrap()
                                         .with_timezone(&UTC));

    cert.sign_certificate(&mut child).unwrap();

    let trusted = vec![cert.fingerprint()];

    let cv = TrustValidator::with_trusted_certificates(trusted, NoRevoker);

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
    use fingerprint::Fingerprint;
    use meta::Meta;
    use certificate::Certificate;
    use revoker::NoRevoker;
    use chrono::datetime::DateTime;
    use chrono::UTC;

    let meta = Meta::new_empty();

    let cert: Certificate =
        Certificate::generate_random(meta,
                                     DateTime::parse_from_rfc3339("2020-01-01T00:00:00+00:00")
                                         .unwrap()
                                         .with_timezone(&UTC));

    let mut cv = TrustValidator::new(NoRevoker);

    assert_eq!(cv.is_valid(&cert).is_ok(), false);

    cv.add_trusted_certificates(vec![cert.fingerprint()]);

    assert_eq!(cv.is_valid(&cert).is_ok(), true);
}

#[test]
fn test_trusted_certificates_fail() {
    use fingerprint::Fingerprint;
    use meta::Meta;
    use certificate::Certificate;
    use revoker::NoRevoker;
    use chrono::datetime::DateTime;
    use chrono::UTC;

    let mut meta = Meta::new_empty();
    meta.set("use-for", r#"["edcert.sign"]"#);

    let cert: Certificate =
        Certificate::generate_random(meta,
                                     DateTime::parse_from_rfc3339("2020-01-01T00:00:00+00:00")
                                         .unwrap()
                                         .with_timezone(&UTC));
    let child: Certificate =
        Certificate::generate_random(Meta::new_empty(),
                                     DateTime::parse_from_rfc3339("2020-01-01T00:00:00+00:00")
                                         .unwrap()
                                         .with_timezone(&UTC));

    let trusted = vec![cert.fingerprint()];

    let cv = TrustValidator::with_trusted_certificates(trusted, NoRevoker);

    assert_eq!(cv.is_valid(&child).is_ok(), false);
}
