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

//! This module contains a wrapper around the libsodium implementation of ed25519.
//! It reduces the size of signatures to 64 byte.

use sodiumoxide;
use sodiumoxide::crypto::sign::ed25519;

/// This is the length of a ed25519 private key.
pub const PRIVATE_KEY_LEN: usize = 64;

/// This is the length of a ed25519 public key.
pub const PUBLIC_KEY_LEN: usize = 32;

/// This is the length of a ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

static mut inited: bool = false;

/// This method generates a random ed25519 keypair from a cryptographically secure source
/// (on unix this is /dev/urandom). Returns (public_key, private_key).
pub fn generate_keypair() -> ([u8; PUBLIC_KEY_LEN], [u8; PRIVATE_KEY_LEN]) {

    unsafe {

        // we cann do this simple unsafe "lazy init",
        // because it would be OK to call init() twice.

        if !inited {
            inited = true;
            sodiumoxide::init();
        }
    }

    let (pk, sk) = ed25519::gen_keypair();

    let public_key = pk.0;
    let private_key = sk.0;

    assert_eq!(PUBLIC_KEY_LEN, public_key.len());
    assert_eq!(PRIVATE_KEY_LEN, private_key.len());

    (public_key, private_key)
}

/// This method takes a data vector and a private key and computes the signature which can be
/// verified using the public key.
pub fn sign(data: &[u8], private_key: &[u8]) -> Vec<u8> {
    assert_eq!(private_key.len(), PRIVATE_KEY_LEN);

    let sk = ed25519::SecretKey::from_slice(private_key);
    let sk = sk.as_ref().unwrap();

    let s = ed25519::sign(data, &sk);

    let mut v = Vec::new();
    v.extend_from_slice(&s[0..64]);
    v
}

/// This method takes a data vector, a signature and a public key and returns true, if the
/// signature has been created using the correct private key.
pub fn verify(data: &[u8], signature: &[u8], public_key: &[u8]) -> bool {

    let pk = ed25519::PublicKey::from_slice(public_key);
    let pk = pk.as_ref().unwrap();

    let mut vi = Vec::with_capacity(SIGNATURE_LEN + data.len());
    vi.extend_from_slice(&signature);
    vi.extend_from_slice(data);

    let r = ed25519::verify(&vi, &pk);

    if r.is_err() {
        false
    } else {
        let bytes = r.unwrap();
        bytes == data
    }
}

#[test]
fn test_ed25519_simple() {
    let (pk, sk) = generate_keypair();

    let msg = &[0; 128][..];
    let mut sig = sign(msg, &sk);

    println!("signature: {:?}", sig);
    println!("");

    sig[0] = ((sig[0] as u16 + 1) % 256) as u8;

    assert_eq!(verify(msg, &sig, &pk), false);

    sig[0] = ((sig[0] as u16 + 255) % 256) as u8;

    assert_eq!(verify(msg, &sig, &pk), true);
}

#[test]
fn test_ed25519_shortmsg() {
    let (pk, sk) = generate_keypair();

    let msg = &[0; 32][..];
    let mut sig = sign(msg, &sk);

    println!("signature: {:?}", sig);
    println!("");

    sig[0] = ((sig[0] as u16 + 1) % 256) as u8;

    assert_eq!(verify(msg, &sig, &pk), false);

    sig[0] = ((sig[0] as u16 + 255) % 256) as u8;

    assert_eq!(verify(msg, &sig, &pk), true);
}

#[test]
fn test_testvectors() {
    use rustc_serialize::json;
    use bytescontainer::BytesContainer;

    let decode = |t| {
        let t = json::decode::<BytesContainer>(&format!("\"{}\"", t)).unwrap();
        t.get().clone()
    };

    // test vectors from
    // https://github.com/cryptosphere/rbnacl/blob/master/lib/rbnacl/test_vectors.rb

    let prv = decode("b18e1d0045995ec3d010c387ccfeb984d783af8fbb0f40fa7db126d889f6dadd77f48b59cae\
                      da77751ed138b0ec667ff50f8768c25d48309a8f386a2bad187fb");
                      
    let pbl = decode("77f48b59caeda77751ed138b0ec667ff50f8768c25d48309a8f386a2bad187fb");

    let msg = decode("916c7d1d268fc0e77c1bef238432573c39be577bbea099893\
                      6add2b50a653171ce18a542b0b7f96c1691a3be6031522894a8\
                      634183eda38798a0c5d5d79fbd01dd04a8646d71873b77b2219\
                      98a81922d8105f892316369d5224c9983372d2313c6b1f4556e\
                      a26ba49d46e8b561e0fc76633ac9766e68e21fba7edca93c4c7\
                      460376d7f3ac22ff372c18f613f2ae2e856af40");

    let sig = decode("6bd710a368c1249923fc7a1610747403040f0cc30815a00f9ff548a896bbda0b4eb2ca19ebc\
                      f917f0f34200a9edbad3901b64ab09cc5ef7b9bcc3c40c0ff7509");

    let sig_my = sign(&msg, &prv);

    // both signatures must be equal
    assert_eq!(&sig_my, &sig);

    // the signature must be valid
    assert_eq!(true, verify(&msg, &sig_my, &pbl));
}
