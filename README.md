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
use chrono::duration::Duration;
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
tcv.add_trusted_certificates(vec![cert.get_id()]);

// even though we gave a wrong master key, this certificate is valid, because it is trusted.
assert_eq!(true, tcv.is_valid(&cert).is_ok());

// now we sign data with it
let data = [1; 42];

// and sign the data with the certificate
let signature = cert.sign(&data)
                    .expect("This fails, if no private key is known to the certificate.");

// the signature must be valid
assert_eq!(true, cert.verify(&data, &signature));
```

# To-Do:

There are always things to work on in cryptographic projects. Here are just some
of these:

- Add safe memory zeroing (using the `secrets` crate)
- Add self-signed certificates*

\*: If you identify a certificate via a fingerprint that is say his public key,
anyone could send you a version of that certificate with whatever expiry date
they wish. If you have that certificate in your trust store, you won't notice,
because you only check if the fingerprint is known.

To prevent this, we will only allow self-signed certificates in trust-stores
and check if the signature is valid, because an attacker cannot recreate the
signature.


# License

MIT

That means you can use this code in open source projects and/or commercial
projects without any problems. Please read the license file "LICENSE" for
details

[Ed25519]: https://ed25519.cr.yp.to/
[sodiumoxide]: http://dnaq.github.io/sodiumoxide/sodiumoxide/index.html
[NaCl]: https://nacl.cr.yp.to/
