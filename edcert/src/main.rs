mod signature;
mod certificate;
mod meta;

extern crate chrono;

use certificate::Certificate;

fn main() {
    let mut c: Certificate = Certificate::new([0; certificate::KEY_LEN], chrono::UTC::now());
    c.get_meta();
}
