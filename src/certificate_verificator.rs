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

pub trait Revoker<T> {
    fn is_revoked(&self, &T) -> Result<(), &'static str>;
}

pub struct CertificateVerificator<T: Revoker<Certificate>> {
    revoker: T,
    master_public_key: BytesContainer
}

impl<T: Revoker<Certificate>> CertificateVerificator<T> {
    /// Call this to create a CV with a revoke server.
    /// For every certificate the revoke server is asked if it is known.
    pub fn new(master_public_key: &[u8; 32], revoker: T) -> CertificateVerificator<T> {

        let mut vec: Vec<u8> = Vec::new();
        vec.extend_from_slice(master_public_key);

        CertificateVerificator {
            revoker: revoker,
            master_public_key: BytesContainer::new(vec)
        }
    }

    /// Checks the certificate if it is valid.
    /// If the CV knows a revoke server, that is queried as well.
    pub fn is_valid(&self, cert: &Certificate) -> Result<(), &'static str> {
        // this returns an Error if it fails
        try!(cert.is_valid(&self.master_public_key.get()[..]));

        // this returns an Error if it fails
        try!(self.revoker.is_revoked(cert));

        // if nothing fails, the certificate is valid!
        Ok(())
    }

    pub fn is_revoked(&self, cert: &Certificate) -> Result<(), &'static str> {
        self.revoker.is_revoked(cert)
    }
}

pub struct NoRevoker;

impl Revoker<Certificate> for NoRevoker {
    fn is_revoked(&self, _: &Certificate) -> Result<(), &'static str> {
        Ok(())
    }
}

#[test]
fn test_verificator() {
    use ed25519;
    use chrono::Timelike;
    use chrono::UTC;
    use time::Duration;
    use meta::Meta;

    let (mpk, msk) = ed25519::generate_keypair();

    let cv = CertificateVerificator::new(&mpk, NoRevoker);

    let meta = Meta::new_empty();
    let expires = UTC::now()
                      .checked_add(Duration::days(90))
                      .expect("Failed to add 90 days to expiration date.")
                      .with_nanosecond(0)
                      .unwrap();

    let mut cert = Certificate::generate_random(meta.clone(), expires.clone());

    cert.sign_with_master(&msk[..]);

    assert_eq!(cv.is_valid(&cert).is_ok(), true);

    let cert_invalid = Certificate::generate_random(meta.clone(), expires.clone());

    assert_eq!(cv.is_valid(&cert_invalid).is_ok(), false);
}
