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

extern crate chrono;
extern crate time;
extern crate rustc_serialize;
extern crate sodiumoxide;
extern crate lzma;
extern crate hyper;

mod bytescontainer;
pub mod ed25519;
pub mod meta;
pub mod signature;
pub mod certificate;
pub mod certificate_verificator;

#[test]
fn test_readme_example() {
    use chrono::Timelike;
    use chrono::UTC;
    use time::Duration;
    use meta::Meta;
    use certificate::Certificate;
    use certificate_verificator::CertificateVerificator;

    // create random master key
    let (mpk, msk) = ed25519::generate_keypair();

    // create random certificate
    let meta = Meta::new_empty();
    let expires = UTC::now()
                      .checked_add(Duration::days(90))
                      .expect("Failed to add 90 days to expiration date.")
                      .with_nanosecond(0)
                      .unwrap();
    let mut cert = Certificate::generate_random(meta, expires);

    // sign certificate with master key
    cert.sign_with_master(&msk);

    // the certificate is valid given the master public key
    assert_eq!(true, cert.is_valid(&mpk).is_ok());

    // but wait! if we want to validate more than one certificate with the same
    // public key, which is more than likely, we can use this
    let cv = CertificateVerificator::new(&mpk);

    // now we use the CV to validate certificates
    assert_eq!(true, cv.is_valid(&cert).is_ok());

    // now we sign data with it
    let data = [1; 42];

    // and sign the data with the certificate
    let signature = cert.sign(&data[..]).expect("This fails, if no private key is known to the certificate.");

    // the signature must be valid
    assert_eq!(true, cert.verify(&data[..], &signature[..]));
}
