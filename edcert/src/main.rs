extern crate chrono;
extern crate time;
extern crate crypto;
extern crate rustc_serialize;
extern crate rand;
extern crate sodiumoxide;

mod signature;
mod certificate;
mod meta;

use certificate::Certificate;
use chrono::UTC;
use chrono::Timelike;
use time::Duration;

fn main() {
	let mut meta_parent = meta::Meta::new();
    meta_parent.set("name", "Amke Root Certificate");
    meta_parent.set("use-for", "[amke.certificate-signing]");
    let meta_parent = meta_parent;

    let mut meta_child = meta::Meta::new();
    meta_child.set("name", "Amke Rombie Root Certificate");
    meta_child.set("use-for", "[amke.certificate-signing, amke.rombie.*]");
    let meta_child = meta_child;

    let expires = UTC::now()
                      .checked_add(Duration::days(90))
                      .expect("Fehler: Ein Tag konnte nicht auf heute addiert werden.")
                      .with_nanosecond(0).unwrap();

    let mut child = Certificate::generate_random(meta_child, expires);
	let parent = Certificate::generate_random(meta_parent, expires);
	
	parent.sign_certificate(&mut child).expect("Failed to sign child!");

    let time_str = UTC::now().to_rfc3339();
	
	println!("Ist Kind valid? {:?}", child.is_valid());
	
    child.save(&time_str);
}
