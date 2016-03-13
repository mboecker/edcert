use rustc_serialize::Encoder;
use rustc_serialize::Encodable;
use rustc_serialize::Decoder;
use rustc_serialize::Decodable;
use rustc_serialize::hex::FromHex;

#[derive(Clone,Debug)]
pub struct BytesContainer {
    bytes: Vec<u8>,
}

impl BytesContainer {
    pub fn new(bytes: Vec<u8>) -> BytesContainer {
        BytesContainer { bytes: bytes }
    }

    pub fn get<'a>(&'a self) -> &'a Vec<u8> {
        &self.bytes
    }

    pub fn get_mut<'a>(&'a mut self) -> &'a mut Vec<u8> {
        &mut self.bytes
    }

    pub fn to_bytestr(&self) -> String {
        let bytestr: Vec<String> = self.bytes.iter().map(|b| format!("{:02X}", b)).collect();
        bytestr.join("")
    }

    pub fn from_bytestr(bytestr: &str) -> Result<BytesContainer, ()> {
        println!("lese 2");

        match bytestr.from_hex() {
            Ok(vec) => Ok(BytesContainer::new(vec)),
            _ => Err(()),
        }
    }
}

impl Decodable for BytesContainer {
    fn decode<T: Decoder>(d: &mut T) -> Result<BytesContainer, T::Error> {
        let bytestr = try!(String::decode(d));
        match BytesContainer::from_bytestr(&bytestr) {
            Ok(bc) => Ok(bc),
            Err(_) => Err(d.error("Failed to parse hex string")),
        }
    }
}

impl Encodable for BytesContainer {
    fn encode<T: Encoder>(&self, d: &mut T) -> Result<(), T::Error> {
        self.to_bytestr().encode(d)
    }
}
