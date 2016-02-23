use certificate;
use certificate::Certificate;
use rustc_serialize::json;
use rustc_serialize::Encodable;
use rustc_serialize::Encoder;

#[derive(Clone)]
pub struct Signature {
    /// This is the actual signature generated with the certificate data and the parents private key
    /// It can be validated with the parents public key
    hash: Vec<u8>,

    /// If this is None, then the Certificate is signed with the master key
    signed_by: Option<Box<Certificate>>
}

impl Signature {
	pub fn new(parent : Box<Certificate>, signature : Vec<u8>) -> Signature {
		Signature {
			hash : signature,
			signed_by : Some(parent)
		}
	}
	
    /// This method will return true iff the certificate has no parent certificate
    /// It is then signed with the master key
    pub fn is_signed_by_master(&self) -> bool {
        self.get_parent().is_none()
    }

    /// This method will return the parent Certificate, or None, if it is signed with the master key
    pub fn get_parent(&self) -> Option<&Certificate> {
    	if self.signed_by.is_none() {
        	let parent : &Certificate = self.signed_by.as_ref().unwrap();
        	Some(parent)
    	}
    	else
    	{
    		None
    	}
    }
    
    /// This method will return the signature given by the parent
    pub fn get_hash(&self) -> &Vec<u8> {
    	&self.hash
    }
}

impl Encodable for Signature {
	fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
		s.emit_struct("Signature", 1, |s| {
				try!(s.emit_struct_field("hash", 0, |s| bytes_to_longs(&self.hash).encode(s)));
				if !self.is_signed_by_master() {
					try!(s.emit_struct_field("signed-by", 1, |s| self.signed_by.encode(s)));
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
