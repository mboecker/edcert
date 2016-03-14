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
use meta::Meta;

struct CertificateVerificator {
    revokeserver: Option<String>,
    master_public_key: BytesContainer
}

impl CertificateVerificator {
    pub fn new(master_public_key: &[u8; 32]) -> CertificateVerificator {

        let mut vec: Vec<u8> = Vec::new();
        vec.extend_from_slice(master_public_key);

        CertificateVerificator {
            revokeserver: None,
            master_public_key: BytesContainer::new(vec)
        }
    }

    pub fn with_revokeserver(revokeserver: &str, master_public_key: &[u8; 32]) -> CertificateVerificator {

        let mut vec: Vec<u8> = Vec::new();
        vec.extend_from_slice(master_public_key);

        CertificateVerificator {
            revokeserver: Some(revokeserver.to_string()),
            master_public_key: BytesContainer::new(vec)
        }
    }

    pub fn is_valid(&self, cert: &Certificate) -> bool {
        let mut r = true;
        r = r && cert.is_valid(&self.master_public_key.get()[..]).is_ok();
        if self.revokeserver.is_some() {
            r = r && cert.is_revoked(self.revokeserver.as_ref().unwrap()).is_ok();
        }
        r
    }
}

#[test]
fn test_verificator() {
    use ed25519;
    use chrono::Timelike;
    use chrono::UTC;
    use time::Duration;

    let (mpk, msk) = ed25519::generate_keypair();

    let cv = CertificateVerificator::with_revokeserver("http://localhost/api.php", &mpk);

    let meta = Meta::new_empty();
    let expires = UTC::now()
                      .checked_add(Duration::days(90))
                      .expect("Failed to add 90 days to expiration date.")
                      .with_nanosecond(0)
                      .unwrap();

    let mut cert = Certificate::generate_random(meta, expires);

    cert.sign_with_master(&msk[..]);

    assert!(cv.is_valid(&cert));
}
