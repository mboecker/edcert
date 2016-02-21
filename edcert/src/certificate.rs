extern crate chrono;
extern crate crypto;

use meta::Meta;
use signature::Signature;

/// This is the amount of bytes a single ed25519 signature takes up
pub const SIGNATURE_LEN: usize = 64;

/// This is the amount of bytes a single ed25519 key takes up. This is for both public and private keys.
pub const KEY_LEN: usize = 32;

pub struct Certificate<'a> {
    /// The meta element contains data associated with the certificate
    /// Common data is "use-for" which contains a list of permissions
    meta: Meta,

    /// the public key of this certificate
    public_key: [u8; KEY_LEN],

    /// the private key, if it is known
    private_key: Option<[u8; KEY_LEN]>,

    /// a timestamp when this certificate expires
    expires: chrono::DateTime<chrono::UTC>,

    /// a signature for trust-chaining certificates
    /// if the certificate is not signed yet, this is None
    signature: Option<Signature<'a>>,
}

impl<'a> Certificate<'a> {
    pub fn new(public_key: [u8; KEY_LEN],
               expires: chrono::DateTime<chrono::UTC>)
               -> Certificate<'a> {
        Certificate {
            meta: Meta::new(),
            signature: None,
            public_key: public_key,
            private_key: None,
            expires: expires,
        }
    }

    pub fn get_meta(&mut self) -> &mut Meta {
        &mut self.meta
    }

    pub fn get_publickey(&self) -> [u8; KEY_LEN] {
        self.public_key
    }

    /// This method returns the private key, if it is known, or None if the certificate has been initialized without the private key
    pub fn get_privatekey(&self) -> Option<[u8; KEY_LEN]> {
        self.private_key
    }

    /// This method returns true, if the private key is saved in the certificate
    pub fn is_privatekey_known(&self) -> bool {
        self.private_key.is_some()
    }

    /// This method signs the given data and returns the signature
    pub fn sign(&self, data: &[u8]) -> [u8; SIGNATURE_LEN] {
        let signature = [0; SIGNATURE_LEN];
        
        
        
        signature
    }

    /// This method verifies that the given signature is valid for the given data 
    pub fn verify(&self, data: &[u8], data_len: usize, signature: [u8; SIGNATURE_LEN]) -> bool {
        // open_sign(data, data_len, self.public_key, signature) == 0
        true
    }

    /// This method verifies that this certificate is valid by analyzing the trust chain
    pub fn is_valid(&self) -> bool {
        true
    }
    
    pub fn generate_random(meta : &Meta, expires : ) -> Certificate{
    	
    	let private_key : [u8; KEY_LEN];
    	let public_key : [u8; KEY_LEN];
    	
    	Certificate {
    		private_key : private_key,
    		public_key : public_key,
    		expires
    	}
    }
}
