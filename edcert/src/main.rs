extern crate chrono;
extern crate time;
extern crate crypto;
extern crate rustc_serialize;
extern crate rand;
extern crate sodiumoxide;
extern crate lzma;

pub mod ed25519;
pub mod meta;
pub mod signature;
pub mod certificate;

use certificate::Certificate;

fn main() {
	let stdin = std::io::stdin();
	let mut buf = String::new();
	stdin.read_line(&mut buf);

	if buf.starts_with("info") {
		info();
	}
	else
	{
		help();
	}
}

fn info() {
//	let stdin = std::io::stdin();
//	
//	println!("Master Public Key?");
//	
//	let master_pk = std::fs::File::open("master_pk.key").expect("Failed to open master public key file");
//	
//	println!("Zertifikat?");
//	
//	let mut buf = String::new();
//	stdin.read_line(&mut buf);
//	
//	let buf = buf.trim();
//	
//	let mut certificate = Certificate::load(&*buf).unwrap();
//	
//	println!("Metadaten:");
//	
//	for a in certificate.get_meta().get_values() {
//		println!("{}: {}", a.0, a.1);
//	}
//	
//	println!("Läuft ab: {0}", certificate.get_expires());
//	
//	if certificate.is_valid(master_pk) {
//		
//	}
}

fn help() {
	
}