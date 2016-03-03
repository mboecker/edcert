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

use sodiumoxide::crypto::sign::ed25519;

/// This is the length of a ed25519 private key.
pub const PRIVATE_KEY_LEN: usize = 64;

/// This is the length of a ed25519 public key.
pub const PUBLIC_KEY_LEN: usize = 32;

/// This method generates a random ed25519 keypair from a cryptographically secure source
/// (on unix this is /dev/urandom).
pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {

    let (pk, sk) = ed25519::gen_keypair();

    let private_key = bytes_to_vec(&sk.0);
    let public_key = bytes_to_vec(&pk.0);

    assert_eq!(64, private_key.len());
    assert_eq!(32, public_key.len());

    (public_key, private_key)
}

/// This method takes a data vector and a private key and computes the signature which can be
/// verified using the public key.
pub fn sign(data: &[u8], private_key: &Vec<u8>) -> Vec<u8> {

    assert_eq!(64, private_key.len());

    let sk = ed25519::SecretKey(vec_to_bytes64(private_key));

    let s = ed25519::sign(data, &sk);

    s
}

/// This method takes a data vector, a signature and a public key and returns true, if the
/// signature has been created using the correct private key.
pub fn verify(data: &[u8], signature: &[u8], public_key: &Vec<u8>) -> bool {
    let b = vec_to_bytes32(public_key);
    let pk = ed25519::PublicKey::from_slice(&b);
    let pk = pk.as_ref().unwrap();

    let r = ed25519::verify(&signature, &pk);

    if r.is_err() {
        false
    } else {
        let bytes = r.unwrap();
        bytes == data
    }
}

fn bytes_to_vec(a: &[u8]) -> Vec<u8> {
    Vec::from(a)
}

fn vec_to_bytes64(a: &Vec<u8>) -> [u8; 64] {

    let mut r = [0; 64];
    let mut i = 0;

    for b in a {
        //        if i >= 64 {
        //            break;
        //        }

        r[i] = b.clone();
        i += 1;
    }

    r
}

fn vec_to_bytes32(a: &Vec<u8>) -> [u8; 32] {

    let mut r = [0; 32];
    let mut i = 0;

    for b in a {
        //        if i >= 32 {
        //            break;
        //        }
        r[i] = b.clone();
        i += 1;
    }

    r
}

#[test]
fn test_ed25519_simple() {
    let (pk, sk) = generate_keypair();

    println!("public: {:?}, private: {:?}", pk, sk);
    println!("");

    let msg = [0; 128];
    let mut sig = sign(&msg, &sk);

    println!("signature: {:?}", sig);
    println!("");

    sig[0] = ((sig[0] as u16 + 1) % 256) as u8;

    assert_eq!(verify(&msg, &sig, &pk), false);

    sig[0] = ((sig[0] as u16 - 1) % 256) as u8;

    assert_eq!(verify(&msg, &sig, &pk), true);
}

#[test]
fn test_ed25519_shortmsg() {
    let (pk, sk) = generate_keypair();

    println!("public: {:?}, private: {:?}", pk, sk);
    println!("");

    let msg = [0; 32];
    let mut sig = sign(&msg, &sk);

    println!("signature: {:?}", sig);
    println!("");

    sig[0] = ((sig[0] as u16 + 1) % 256) as u8;

    assert_eq!(verify(&msg, &sig, &pk), false);

    sig[0] = ((sig[0] as u16 - 1) % 256) as u8;

    assert_eq!(verify(&msg, &sig, &pk), true);
}
