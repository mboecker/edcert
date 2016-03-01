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
	let mut line = String::new();
	stdin.read_line(&mut line).expect("Failed to read line");

	let line = line.trim();

	if line == "gen-master" {

		use std::io::Write;

		println!("Generiere master keypair");

		let (pubkey, prvkey) = ed25519::generate_keypair();

		std::fs::DirBuilder::new().create("master").expect("Failed to create folder 'master'");

		let mut prvfile = std::fs::File::create("master/master.prv").expect("Failed to create private keyfile");
		let mut pubfile = std::fs::File::create("master/master.pub").expect("Failed to create public keyfile");

		pubfile.write_all(&*pubkey).expect("Failed to write public key");
		prvfile.write_all(&*prvkey).expect("Failed to write public key");
	} else if line == "gen-cert" {

	}

	println!("Beende");
}

fn info(master_pk : Vec<u8>, cert : &Certificate) {

	use std::collections::BTreeMap;

	println!("Metadaten:");

	let values : &BTreeMap<String, String> = cert.get_meta().get_values();

	for a in values {
		println!("{}: {}", a.0, a.1);
	}

	println!("Läuft ab: {0}", cert.get_expires());

	let reason = cert.is_valid(&master_pk);

	match reason {
		Ok(_) => {
			println!("Zertifikat ist gültig!");
		},
		Err(string) => {
			println!("Zertifikat ungültig: {}", string);
		}
	}
}
