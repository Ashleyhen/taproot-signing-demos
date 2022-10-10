use bitcoin::{secp256k1::{Secp256k1, All, PublicKey, Scalar, SecretKey, Parity}, XOnlyPublicKey};
use bitcoin_hashes::{sha256, HashEngine, Hash, hex::ToHex};

use crate::schnorr_signing::schnorr_sig::KeySet;

pub fn sign(secp:&Secp256k1<All>,msg:&Scalar,key_set:&KeySet,aggregate_pub_k:&XOnlyPublicKey)->Vec<u8>{
	let random_keyset=KeySet::new(&secp);
	let r_xonly=random_keyset.public_key.x_only_public_key().0;
	let mut engine = sha256::HashEngine::default();
	engine.input(&r_xonly.serialize());
	engine.input(&aggregate_pub_k.serialize());
	engine.input(&msg.to_be_bytes());
    let h_p_scalar = Scalar::from_be_bytes(sha256::Hash::from_engine(engine).into_inner()).unwrap();
	let secret_scalar=Scalar::from_be_bytes(key_set.secret_key.secret_bytes()).unwrap();
	let last_half=random_keyset.secret_key.add_tweak(&h_p_scalar).unwrap().mul_tweak(&secret_scalar).unwrap();

	let mut signature=r_xonly.serialize().to_vec();
	signature.extend_from_slice(&last_half.secret_bytes());
	return signature
}

pub fn aggregate_sig(secp:&Secp256k1<All>,msg:&Scalar,aggregate_pub_k:&PublicKey,alice_sig:&Vec<u8>, bob_sig:&Vec<u8>)->Vec<u8>{
	
	// random half ..32
	let r_xonly=XOnlyPublicKey::from_slice(&alice_sig[..32]).unwrap()
	.add_tweak(secp,&Scalar::from_be_bytes(bob_sig[..32].try_into().unwrap()).unwrap()).unwrap().0;

	let mut engine = sha256::HashEngine::default();
	engine.input(&r_xonly.serialize());
	engine.input(&aggregate_pub_k.x_only_public_key().0.serialize());
	engine.input(&msg.to_be_bytes());
    let h_p_scalar = Scalar::from_be_bytes(sha256::Hash::from_engine(engine).into_inner()).unwrap();

	let alice_scalar=SecretKey::from_slice(alice_sig[..32].try_into().unwrap()).unwrap();
	let bob_scalar=Scalar::from_be_bytes(bob_sig[..32].try_into().unwrap()).unwrap();
	;

	let last_half=
	aggregate_pub_k
	.mul_tweak(&secp,&h_p_scalar).unwrap()
	.add_exp_tweak(&secp,&Scalar::from_be_bytes(alice_scalar.add_tweak(&bob_scalar).unwrap().secret_bytes()).unwrap()).unwrap();

	// let bob_signature=bob_pub_k.mul_tweak(&secp,&h_p_scalar).unwrap().add_exp_tweak(&secp,&bob_scalar).unwrap();
	// sig half

	// let last_half=alice_signature.combine(&bob_signature).unwrap().x_only_public_key().0;
	let mut signature =r_xonly.serialize().to_vec();
	signature.extend_from_slice(&last_half.x_only_public_key().0.serialize());

	return signature;
}

pub fn aggregate_sig_2(secp:&Secp256k1<All>,alice_sig:&Vec<u8>, bob_sig:&Vec<u8>)->Vec<u8>{

	let mut signature=XOnlyPublicKey::from_slice(&alice_sig[..32]).unwrap()
	.add_tweak(&secp,&Scalar::from_be_bytes(bob_sig[..32].try_into().unwrap()).unwrap()).unwrap().0.serialize().to_vec() ;

	let last_half=SecretKey::from_slice(&alice_sig[32..]).unwrap()
	.add_tweak( &Scalar::from_be_bytes(bob_sig[32..].try_into().unwrap()).unwrap()).unwrap();
	signature.extend_from_slice(&PublicKey::from_secret_key(&secp, &last_half).x_only_public_key().0.serialize());
	return signature;
}

#[test]
pub fn test(){

	let msg=Scalar::random();
	let secp=Secp256k1::<All>::new();
	let alice_pub_k=KeySet::new(&secp);
	// let bob_pub_k=KeySet::new(&secp);
	let r_keyset=KeySet::new(&secp);

	let aggregate_pub_k =alice_pub_k.public_key.combine(&alice_pub_k.public_key).unwrap();
	// assert_eq!(aggregate_pub_k,bob_pub_k.public_key.combine(&alice_pub_k.public_key).unwrap());

	let a_z=Scalar::random();
	let b_z=Scalar::random();
	let z=SecretKey::from_slice(&a_z.to_be_bytes()).unwrap().add_tweak(&b_z).unwrap();
	let r=PublicKey::from_secret_key(&secp, &z).x_only_public_key().0;

	// let alice_sig=alice_pub_k.schnorr_sig_x_only(&msg,&a_z,&r, &aggregate_pub_k.x_only_public_key().0);
	// let bob_sig=alice_pub_k.schnorr_sig_x_only(&msg,&a_z,&r, &aggregate_pub_k.x_only_public_key().0);

	let alice_sig=alice_pub_k.schnorr_sig_x_only(&msg);
	// let bob_sig=alice_pub_k.schnorr_sig(&msg);

	let final_signature=aggregate_sig_2(&secp,&alice_sig,&alice_sig);

	let final_sig=aggregate_sig(&secp,&msg,&aggregate_pub_k,&alice_sig,&alice_sig);


	let is_valid=KeySet::verify(&final_signature, &msg.to_be_bytes().to_vec(), &aggregate_pub_k.x_only_public_key().0);
	let is_valid_2=KeySet::verify(&final_sig, &msg.to_be_bytes().to_vec(), &aggregate_pub_k.x_only_public_key().0);
	// dbg!(final_sig.to_hex());
	
	// let is_valid=KeySet::verify(&final_signature, &msg.to_be_bytes().to_vec(), &aggregate_pub_k.x_only_public_key().0);
	assert!(is_valid)




}
impl KeySet{
	    pub fn schnorr_sig_x_only(&self, msg: &Scalar) -> Vec<u8> {
			let secp = self.secp.clone();

			let aux = Scalar::random();
			let random_keyset = KeySet::from_slice(&secp, &aux.to_be_bytes());
	
			let pk_r = random_keyset.public_key.x_only_public_key().0;
	
			let mut engine = sha256::HashEngine::default();
			engine.input(&pk_r.serialize());
			engine.input(&self.public_key.x_only_public_key().0.serialize());
			engine.input(&msg.to_be_bytes());
	
			let h_p_scalar =
				Scalar::from_be_bytes(sha256::Hash::from_engine(engine).into_inner()).unwrap();
			// x*H(R|P|m)+r=s
			let r_scalar = Scalar::from_be_bytes(random_keyset.secret_key.secret_bytes()).unwrap();
			let last_half = self
				.secret_key
				.mul_tweak(&h_p_scalar)
				.unwrap()
				.add_tweak(&r_scalar)
				.unwrap()
				.secret_bytes();
			let mut signature = pk_r.serialize().to_vec();
			signature.extend_from_slice(&last_half);
			return signature;
    }

}