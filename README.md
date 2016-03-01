Hi and welcome on the git page of my crate "edcert".

Edcert is a simple library for certification and authentication of data.

## How it works

1. You create a master keypair. This will be used to sign the highest certificate.
2. You create a root certificate. Sign this with the master key.
3. You can now create other certificates and use certificates to sign each other.
4. Transmit your certificates in a json-encoded format over the network.
5. Sign and verify data with the certificates using the ".sign" and ".verify" methods.

The design uses the "super-secure, superfast" elliptic curve Ed25519, which you can learn more about here: https://ed25519.cr.yp.to/

## License

MIT
