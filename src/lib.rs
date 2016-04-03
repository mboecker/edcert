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

//! This crate is a simple digital signature crate and can be used to verify data integrity by
//! using public-key cryptography. It uses the "super-fast, super-secure" elliptic curve and
//! digital signature algorithm [Ed25519](https://ed25519.cr.yp.to/) (EdDSA).
//!
//! It provides the struct "Certificate", which holds the public key, metadata and a signature.
//!
//! # The basics
//! A Certificate can be signed by a master key, or another Certificate. The top-most Certificate
//! must be signed with the master key, or it will not be valid. For validation, the master public
//! key will be given. This way, a Certificate can only be valid, if it has been signed with a
//! trust chain, which top-most Certificate has been signed with the right private key.
//!
//! See also [here](https://en.wikipedia.org/wiki/EdDSA).
//!
//! ## Other crates
//!
//! To use the edcert ecosystem, there are a few other crates to make your life simpler:
//!
//! - [edcert-letter](https://crates.io/crates/edcert-letter), which provides a container for
//!    signed data, Letter&lt;T&gt;.
//! - [edcert-restrevoke](https://crates.io/crates/edcert-restrevoke), which provides a REST-based
//!   revokation system.
//! - [edcert-compressor](https://crates.io/crates/edcert-compressor), which provides methods to
//!   (de)compress Certificates using JSON/LZMA and manages loading/saving certificates for you.
//! - [edcert-tools](https://crates.io/crates/edcert-tools), which provides a binary for
//!   generation, signing, validation, etc using edcert (and all of the above).

extern crate chrono;
extern crate time;
extern crate rustc_serialize;
extern crate sodiumoxide;

mod bytescontainer;
pub mod ed25519;
pub mod meta;
pub mod signature;
pub mod certificate;
pub mod validator;
pub mod revoker;
pub mod root_validator;
pub mod trust_validator;

/// This is a simple copy function. This should be replaced by memcpy or something...
pub fn copy_bytes(dest: &mut [u8], src: &[u8], start_dest: usize, start_src: usize, len: usize) {
    for i in 0..len {
        dest[start_dest + i] = src[start_src + i];
    }
}

#[test]
fn test_readme_example() {
    use chrono::Timelike;
    use chrono::UTC;
    use time::Duration;
    use meta::Meta;
    use certificate::Certificate;
    use validator::Validatable;
    use validator::Validator;
    use root_validator::RootValidator;
    use trust_validator::TrustValidator;
    use revoker::NoRevoker;

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

    // we can use a RootValidator, which analyzes the trust chain.
    // in this case, the top-most certificate must be signed with the right private key for mpk.
    let cv = RootValidator::new(&mpk, NoRevoker);

    // now we use the CV to validate certificates
    assert_eq!(true, cv.is_valid(&cert).is_ok());

    // we could also use a TrustValidator. It's like RootValidator, but you can also give trusted
    // certificates. If the chain contains one of these, the upper certificates aren't checked
    // with the master public key. We can give any 32 byte key here, it doesn't matter.
    let mut tcv = TrustValidator::new(&[0; 32], NoRevoker);
    tcv.add_trusted_certificates(vec![cert.get_certificate_id()]);

    // even though we gave a wrong master key, this certificate is valid, because it is trusted.
    assert_eq!(true, tcv.is_valid(&cert).is_ok());

    // now we sign data with it
    let data = [1; 42];

    // and sign the data with the certificate
    let signature = cert.sign(&data)
                        .expect("This fails, if no private key is known to the certificate.");

    // the signature must be valid
    assert_eq!(true, cert.verify(&data, &signature));
}
