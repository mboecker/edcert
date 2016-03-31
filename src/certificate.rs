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
use meta::Meta;
use signature::Signature;
use rustc_serialize::Encodable;
use rustc_serialize::Encoder;
use rustc_serialize::Decoder;
use chrono;
use ed25519;
use certificate_validator::Validatable;

/// This is the length of a ed25519 signature.
pub const SIGNATURE_LEN: usize = 64 + CERTIFICATE_BYTE_LEN;

/// This is the length of a ed25519 private key.
pub use ed25519::PRIVATE_KEY_LEN;

/// This is the length of a ed25519 public key.
pub use ed25519::PUBLIC_KEY_LEN;

/// This is the length of a safehash of a certificate.
pub const CERTIFICATE_BYTE_LEN: usize =
    25 /* expires as string */ + 64 /* hash of meta */ + PUBLIC_KEY_LEN;

#[derive(Clone,RustcDecodable,RustcEncodable,Debug)]
pub struct Certificate {
    /// The meta element contains data associated with the certificate.
    /// Common data is "use-for" which contains a list of permissions.
    meta: Meta,

    /// the public key of this certificate.
    public_key: BytesContainer,

    /// the private key, if it is known.
    private_key: Option<BytesContainer>,

    /// a timestamp when this certificate expires.
    expires: String,

    /// a signature for trust-chaining certificates
    /// if the certificate is not signed yet, this is None
    signature: Option<Signature>,
}

impl Certificate {
    /// This method generates a random public/private keypair and a certificate for it.
    pub fn generate_random(meta: Meta, expires: chrono::DateTime<chrono::UTC>) -> Certificate {
        // generate a keypair. this returns two arrays
        let (pubslice, prvslice) = ed25519::generate_keypair();

        // convert the arrays to vectors
        let mut public_key = Vec::new();
        let mut private_key = Vec::new();

        public_key.extend_from_slice(&pubslice[..]);
        private_key.extend_from_slice(&prvslice[..]);

        // create the certificate
        Certificate {
            private_key: Some(BytesContainer::new(private_key)),
            public_key: BytesContainer::new(public_key),
            expires: expires.to_rfc3339(),
            meta: meta,
            signature: None,
        }
    }

    /// This method returns a mutable reference to the meta structure.
    pub fn meta_mut(&mut self) -> &mut Meta {
        &mut self.meta
    }

    /// This method returns a reference to the meta structure.
    pub fn meta(&self) -> &Meta {
        &self.meta
    }

    /// This method returns a reference to the public key.
    pub fn public_key(&self) -> &Vec<u8> {
        &self.public_key.get()
    }

    /// This method returns the private key, if it is known, or None if the certificate has been
    /// initialized without the private key.
    pub fn private_key<'a>(&'a self) -> Option<&'a Vec<u8>> {
        if self.has_private_key() {
            let vec = self.private_key.as_ref().unwrap().get();
            Some(vec)
        } else {
            None
        }
    }

    /// This method returns true, if the private key is saved in the certificate.
    pub fn has_private_key(&self) -> bool {
        self.private_key.is_some()
    }

    /// This method returns the expiration date as a RFC 3339 string.
    pub fn expiration_date(&self) -> &str {
        &self.expires
    }

    /// This method returns either the signature, or None.
    pub fn signature(&self) -> Option<&Signature> {
        self.signature.as_ref()
    }

    /// This method replaces the current private key of this certificate with the given one.
    pub fn set_private_key(&mut self, private_key: Vec<u8>) {
        self.private_key = Some(BytesContainer::new(private_key));
    }

    /// This method checks, if the "use-for" meta tag contains the use "edcert.sign"
    pub fn can_sign(&self) -> Result<(), &'static str> {
        use rustc_serialize::json;

        let meta = self.meta();

        println!("meta: {:?}", meta);

        match meta.get("use-for") {
            Some(use_for) => {
                let use_for: Vec<String> = match json::decode(use_for) {
                    Ok(x) => x,
                    Err(_) => {
                        return Err("Failed to parse content of meta value \"use-for\"");
                    }
                };

                for u in use_for {
                    println!("{} ?= edcert.sign?", u);
                    if u == "edcert.sign" {
                        return Ok(());
                    }
                }

                Err("This certificate is not allowed to sign certificates")
            }
            None => Err("The meta value \"use-for\" could not be found"),
        }
    }

    /// This method returns a "hash". This is used to validate the certificate.
    /// All relevant information of the certificate is used to produce the hash,
    /// including the public key, meta data and the expiration date.
    pub fn safehash(&self) -> [u8; CERTIFICATE_BYTE_LEN] {

        // create a array of this length
        let mut bytes = [0; CERTIFICATE_BYTE_LEN];

        // first 64 bytes are a sha512 hash of meta. the ordering of meta entries is irrelevant
        self.meta.fill_bytes(&mut bytes[0..64]);

        // next 25 bytes are string representation of the expiration string
        ::copy_bytes(&mut bytes[64..], self.expires.as_bytes(), 0, 0, 25);

        // finally, the public key is appended
        ::copy_bytes(&mut bytes[89..],
                     &self.public_key.get()[..],
                     0,
                     0,
                     PUBLIC_KEY_LEN);

        bytes
    }

    /// This method returns the parent certificate of this certificate, if it exists.
    pub fn parent(&self) -> Option<&Certificate> {
        if self.is_signed() {
            let sig = &self.signature.as_ref().unwrap();
            sig.parent()
        } else {
            None
        }
    }

    /// This method returns true, if a signature exists (is not None). This doesn't validate the
    /// signature.
    pub fn is_signed(&self) -> bool {
        self.signature.is_some()
    }

    /// This method signs the given data and returns the signature.
    pub fn sign(&self, data: &[u8]) -> Option<Vec<u8>> {
        if self.has_private_key() {
            let signature = ed25519::sign(data, self.private_key().unwrap());
            Some(signature)
        } else {
            None
        }
    }

    /// This method signs this certificate with the given private master key.
    pub fn sign_with_master(&mut self, master_private_key: &[u8]) {
        let bytes = self.safehash();
        let hash = ed25519::sign(&bytes[..], master_private_key);
        self.signature = Some(Signature::new(hash));
    }

    /// This method signs another certificate with the private key of this certificate.
    pub fn sign_certificate(&self, other: &mut Certificate) -> Result<(), &'static str> {
        if self.has_private_key() {
            let child_bytes = other.safehash();
            let signature_bytes = self.sign(&child_bytes).unwrap().to_vec();
            let parent = Box::new(self.clone());
            let signature = Signature::with_parent(parent, signature_bytes);

            other.signature = Some(signature);

            Ok(())
        } else {
            Err("This certificate has no private key")
        }
    }

    /// This method checks, if this certificates expiration date is now or in the past.
    pub fn is_expired(&self) -> bool {

        // try to parse the string of this certificate
        let expires = match chrono::DateTime::parse_from_rfc3339(&self.expires) {
            Err(_) => return true,
            Ok(expires) => expires.with_timezone(&chrono::UTC),
        };

        // if the parsing is ok, then this must be true for the certificate to be expired
        expires <= chrono::UTC::now()
    }

    /// This method verifies that the given signature is valid for the given data.
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        let result = ed25519::verify(data, signature, self.public_key());
        result
    }
}

impl Validatable for Certificate {
    fn is_valid(&self, master_pk: &[u8]) -> Result<(), &'static str> {
        if !self.is_signed() {
            Err("This certificate isn't signed, so it can't be valid.")
        } else {

            // get a hash unique to this certificate
            let bytes: &[u8] = &self.safehash()[..];

            // get the signature
            let signature = self.signature.as_ref().unwrap();

            // if it is signed by the master key
            if signature.is_signed_by_master() {

                // get the signature hash
                let hash = signature.hash();

                // verify it for the safehash, master public key and the signature
                let r = ed25519::verify(bytes, hash, master_pk);

                // if it is valid
                if r {

                    // check if the certificate is expired
                    if self.is_expired() {
                        Err("This certificate is expired")
                    } else {
                        Ok(())
                    }

                } else {

                    // else the signature isn't from the master key
                    Err("Failed to verify master signature")
                }

            } else {

                // if it is not signed by the master key, get the parent
                let parent: &Certificate = signature.parent().unwrap();

                // verify the signature of the parent
                let sign_real = parent.verify(bytes, &signature.hash());

                // verify that the parent is valid
                let parent_real = parent.is_valid(&master_pk).is_ok();

                // can parent sign other certificates?
                let parent_can_sign = parent.can_sign().is_ok();

                // if the signature is valid
                if sign_real {

                    // and the parent certificate is valid
                    if parent_real {

                        // and the parent can sign
                        if parent_can_sign {

                            // and the certificate is not expired
                            if !self.is_expired() {
                                Ok(())
                            } else {
                                Err("The certificate is expired")
                            }

                        } else {
                            Err("The parent isn't allowed to sign certificates.")
                        }

                    } else {
                        Err("The parent is invalid.")
                    }
                } else {
                    Err("The signature of the parent isn invalid.")
                }
            }
        }
    }


    fn is_revokable(&self) -> bool {
        true
    }

    fn get_id(&self) -> String {
        self.public_key.to_bytestr()
    }
}

#[test]
fn test_generate_certificate() {
    use chrono::Timelike;
    use chrono::UTC;
    use time::Duration;

    let meta = Meta::new_empty();
    let expires = UTC::now()
                      .checked_add(Duration::days(90))
                      .expect("Failed to add a day to expiration date.")
                      .with_nanosecond(0)
                      .unwrap();

    let a = Certificate::generate_random(meta, expires);

    let meta = Meta::new_empty();

    let b = Certificate::generate_random(meta, expires);

    assert!(a.public_key() != b.public_key());
}

// #[test]
// fn test_revoke() {
//     use chrono::Timelike;
//     use chrono::UTC;
//     use time::Duration;
//
//     let meta = Meta::new_empty();
//     let expires = UTC::now()
//                       .checked_add(Duration::days(90))
//                       .expect("Failed to add 90 days to expiration date.")
//                       .with_nanosecond(0)
//                       .unwrap();
//     let cert = Certificate::generate_random(meta, expires);
//
//     cert.is_revoked("http://localhost/api.php").is_err();
// }
