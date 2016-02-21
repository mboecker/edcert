use certificate;
use certificate::Certificate;

pub struct Signature<'a> {
    /// This is the actual signature generated with the certificate data and the parents private key
    /// It can be validated with the parents public key
    signature: [u8; certificate::SIGNATURE_LEN],

    /// If this is None, then the Certificate is signed with the master key
    signed_by: Option<&'a Certificate<'a>>,
}

impl<'a> Signature<'a> {
    /// This method will return true iff the certificate has no parent certificate
    /// It is then signed with the master key
    pub fn is_signed_by_master(&self) -> bool {
        self.signed_by.is_none()
    }

    /// This method will return the parent Certificate, or None, if it is signed with the master key
    pub fn get_parent(&self) -> Option<&'a Certificate> {
        self.signed_by
    }
}
