use certificate::Certificate;
use rustc_serialize::Encodable;
use rustc_serialize::Encoder;
use rustc_serialize::Decoder;

#[derive(Clone,RustcDecodable,RustcEncodable,Debug)]
pub struct Signature {
    /// This is the actual signature generated with the certificate data and the parents private key
    /// It can be validated with the parents public key
    hash: Vec<u8>,

    /// If this is None, then the Certificate is signed with the master key
    signed_by: Option<Box<Certificate>>,
}

impl Signature {
    pub fn new(parent: Box<Certificate>, signature: Vec<u8>) -> Signature {
        Signature {
            hash: signature,
            signed_by: Some(parent),
        }
    }

    pub fn new_without_parent(signature: Vec<u8>) -> Signature {
        Signature {
            hash: signature,
            signed_by: None,
        }
    }

    /// This method will return true iff the certificate has no parent certificate
    /// It is then signed with the master key
    pub fn is_signed_by_master(&self) -> bool {

        self.signed_by.is_none()
    }

    /// This method will return the parent Certificate, or None, if it is signed with the master key
    pub fn get_parent(&self) -> Option<&Certificate> {
        if self.signed_by.is_none() {
            None
        } else {
            let parent: &Certificate = self.signed_by.as_ref().unwrap();
            Some(parent)
        }
    }

    /// This method will return the signature given by the parent
    pub fn get_hash(&self) -> &Vec<u8> {
        &self.hash
    }
}