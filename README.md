[![Build Status](https://travis-ci.org/zombiemuffin/edcert.svg?branch=master)](https://travis-ci.org/zombiemuffin/edcert)

Hi and welcome on the git page of my crate "edcert".

Edcert is a simple library for certification and authentication of data.

# How it works

1. You create a master keypair. This will be used to sign the highest certificate.
2. You create a root certificate. Sign this with the master key.
3. You can now create other certificates and use certificates to sign each other.
4. Transmit your certificates in a json-encoded format over the network.
5. Sign and verify data with the certificates using the ".sign" and ".verify" methods.

The design uses the "super-secure, super-fast" elliptic curve [Ed25519],
which you can learn more about here

For cryptography it uses the [sodiumoxide] library, which is based on [NaCl],
the well known cryptography libraray by Dan Bernstein et al.

# Example

```rust
use chrono::Timelike;
use chrono::UTC;
use time::Duration;

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

// now we sign data with it
let data = [1; 42];

// and sign the data with the certificate
let signature = cert.sign(&data[..]).expect("This fails, if no private key is known to the certificate.");

// the signature must be valid
assert_eq!(true, cert.verify(&data[..], &signature[..]));
```

# License

MIT

[Ed25519]: https://ed25519.cr.yp.to/
[sodiumoxide]: http://dnaq.github.io/sodiumoxide/sodiumoxide/index.html
[NaCl]: https://nacl.cr.yp.to/
