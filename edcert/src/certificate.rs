extern crate rand;
extern crate sodiumoxide;

use meta::Meta;
use signature::Signature;
use rustc_serialize::json;
use rustc_serialize::Encodable;
use rustc_serialize::Encoder;
use self::rand::Rng;
use chrono;
use self::sodiumoxide::crypto::sign::ed25519;

/// This is the amount of bytes a single ed25519 signature takes up
pub const SIGNATURE_LEN: usize = 64;

/// This is the amount of bytes a single key takes up.
pub const PRIVATE_KEY_LEN: usize = 64;
pub const PUBLIC_KEY_LEN: usize = 32;

pub const CERTIFICATE_BYTE_LEN: usize = 25 /* expires as string */ + 8 /* hash of meta */ + PUBLIC_KEY_LEN /* public key len */;

#[derive(Clone)]
pub struct Certificate {
    /// The meta element contains data associated with the certificate
    /// Common data is "use-for" which contains a list of permissions
    meta: Meta,

    /// the public key of this certificate
    public_key: Vec<u8>,

    /// the private key, if it is known
    private_key: Option<Vec<u8>>,

    /// a timestamp when this certificate expires
    expires: chrono::DateTime<chrono::UTC>,

    /// a signature for trust-chaining certificates
    /// if the certificate is not signed yet, this is None
    signature: Option<Signature>,
}

impl Certificate {
//    pub fn new(public_key: Vec<u8>,
//               expires: chrono::DateTime<chrono::UTC>)
//               -> Certificate {
//        Certificate {
//            meta: Meta::new(),
//            signature: None,
//            public_key: public_key,
//            private_key: None,
//            expires: expires,
//        }
//    }

    pub fn get_meta(&mut self) -> &mut Meta {
        &mut self.meta
    }

    pub fn get_public_key(&self) -> &Vec<u8> {
		&self.public_key
    }

    /// This method returns the private key, if it is known, or None if the certificate has been initialized without the private key
    pub fn get_private_key(&self) -> &Option<Vec<u8>> {
		&self.private_key
    }

    /// This method returns true, if the private key is saved in the certificate
    pub fn has_private_key(&self) -> bool {
        self.private_key.is_some()
    }
    
    pub fn is_signed(&self) -> bool {
    	self.signature.is_some()
    }
    
    pub fn to_bytes(&self) -> [u8; CERTIFICATE_BYTE_LEN] {
    	[0; CERTIFICATE_BYTE_LEN]
    }

    /// This method signs the given data and returns the signature
    pub fn sign(&self, data: &[u8]) -> Option<Vec<u8>> {
    	if self.has_private_key() {
		    let sk = ed25519::SecretKey ( vec_to_bytes64(&self.private_key.as_ref().unwrap()));
			let mut signature = ed25519::sign(data, &sk);
		    unsafe { signature.set_len(8*8); }
		    Some(signature)
    	}
    	else
    	{
    		None
    	}
    }

    /// This method verifies that the given signature is valid for the given data 
    pub fn verify(&self, data: &[u8], data_len: usize, signature: [u8; SIGNATURE_LEN]) -> bool {
        // open_sign(data, data_len, self.public_key, signature) == 0
        
        let pk = ed25519::PublicKey ( vec_to_bytes32(&self.public_key.as_ref()));
        
        let result = ed25519::verify(data, &pk);
        
        println!("{:?}", result);
        
        true
    }

    /// This method verifies that this certificate is valid by analyzing the trust chain
    pub fn is_valid(&self) -> bool {
    	if !self.is_signed() {
    		false
    	}
    	else
    	{
	        let bytes : [u8; CERTIFICATE_BYTE_LEN] = [0; CERTIFICATE_BYTE_LEN];
	        
			let signature = self.signature.as_ref().expect("lel");
	        
	        if signature.get_parent().is_none() {
	        	false
	        } else {
	        	let parent : &Certificate = signature.get_parent().unwrap();
	        	let sign_real = parent.verify(&bytes, CERTIFICATE_BYTE_LEN, vec_to_bytes64(&signature.get_hash()));
	        	
	        	sign_real
	        }
    	}
    }

    /// This method generates a random public/private keypair and a certificate for it
    pub fn generate_random(meta: Meta, expires: chrono::DateTime<chrono::UTC>) -> Certificate {

		let (public_key, private_key) = ed25519::gen_keypair();

        Certificate {
            private_key: Some(bytes_to_vec(&private_key.0)),
            public_key: bytes_to_vec(&public_key.0),
            expires: expires,
            meta: meta,
            signature: None,
        }
    }

    /// Saves this certificate into a folder: one file for the certificate and one file for the private key
    pub fn save(&self, folder: &str) {

        use std::fs::File;
        use std::fs::DirBuilder;
        use std::io::Write;

        let folder: String = folder.to_string();
        
        DirBuilder::new().create(&folder).expect("Failed to create folder");

        if self.has_private_key() {
            let mut private_keyfile: File = File::create(folder.clone() + "/private.key")
                                                .expect("Failed to create private key file.");

			let bytes : &[u8] = self.private_key.as_ref().unwrap();

            private_keyfile.write_all(bytes).expect("Failed to write private key file.");
        }

	let folder: String = folder.to_string();

		let mut certificate_file : File = File::create(folder + "/certificate.json").expect("Failed to create certificate file.");
	
		certificate_file.write(json::encode(self).expect("Failed to encode certificate").as_bytes()).expect("Failed to write certificate file.");
    }
    
    pub fn sign_certificate(&self, other : &mut Certificate) -> Result<(), &'static str> {
    	
    	if self.has_private_key() {
    		let child_bytes = other.to_bytes();
    		let signature_bytes = self.sign(&child_bytes).unwrap().to_vec();
    		let parent = Box::new(self.clone());
    		let signature = Signature::new(parent, signature_bytes);
    		
    		other.signature = Some(signature);
    		
    		Ok(()) 
    	}
    	else
    	{
    		Err("This certificate has no private key")
    	}
    }
}

impl Encodable for Certificate {
	fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
		s.emit_struct("Certificate", 1, |s| {
				try!(s.emit_struct_field("meta", 0, |s| self.meta.encode(s)));
				try!(s.emit_struct_field("expires", 1, |s| self.expires.to_rfc3339().encode(s)));
				try!(s.emit_struct_field("public_key", 1, |s| bytes_to_longs(&self.public_key).encode(s)));
				if self.signature.is_some() {
					try!(s.emit_struct_field("signature", 1, |s| self.signature.encode(s)));
				}
				Ok(())
			})
	}
}

fn bytes_to_longs(a : &Vec<u8>) -> Vec<u64> {
	let aptr : *const u8 = a.as_ptr();
	let bptr = aptr as *mut u64;
	unsafe {
		Vec::from_raw_parts(bptr, a.len() / 8, a.len() / 8)
	}
}

fn bytes_to_vec(a : &[u8]) -> Vec<u8> {
	Vec::from(a)
}

fn vec_to_bytes64(a: &Vec<u8>) -> [u8; 64] {
	
	let mut r = [0; 64];
	let mut i = 0;
	
	for b in a {
		r[i] = b.clone();
		i+=1;
	}
	
	r
}

fn vec_to_bytes32(a: &Vec<u8>) -> [u8; 32] {
	
	let mut r = [0; 32];
	let mut i = 0;
	
	for b in a {
		r[i] = b.clone();
		i+=1;
	}
	
	r
}