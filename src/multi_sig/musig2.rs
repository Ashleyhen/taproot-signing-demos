use bitcoin::{XOnlyPublicKey, secp256k1::{PublicKey, Parity} };


pub fn aggregate_pub_k(x:Vec<PublicKey>)->PublicKey{
	return x.iter().map(|f|f.clone()).reduce(|a,b|
		a.combine(&b).unwrap()
	).unwrap();
}