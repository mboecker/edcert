use meta::Meta;

pub struct Certificate {
	meta : Meta,
}
	
impl Certificate {
	fn new() -> Certificate {
		Certificate {
			meta : Meta::new()
		}
	}
}