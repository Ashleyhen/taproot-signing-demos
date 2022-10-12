use bitcoin::{secp256k1::{Secp256k1, All, PublicKey, Scalar, SecretKey, Parity}, XOnlyPublicKey};
use bitcoin_hashes::{sha256, HashEngine, Hash, hex::ToHex};

use crate::schnorr_signing::schnorr_sig::KeySet;

// pub fn sign(secp:&Secp256k1<All>,msg:&Scalar,key_set:&KeySet,aggregate_pub_k:&XOnlyPublicKey)->Vec<u8>{
// 	let random_keyset=KeySet::new(&secp);
// 	let r_xonly=random_keyset.public_key.x_only_public_key().0;
// 	let mut engine = sha256::HashEngine::default();
// 	engine.input(&r_xonly.serialize());
// 	engine.input(&aggregate_pub_k.serialize());
// 	engine.input(&msg.to_be_bytes());
//     let h_p_scalar = Scalar::from_be_bytes(sha256::Hash::from_engine(engine).into_inner()).unwrap();
// 	let secret_scalar=Scalar::from_be_bytes(key_set.secret_key.secret_bytes()).unwrap();
// 	let last_half=random_keyset.secret_key.add_tweak(&h_p_scalar).unwrap().mul_tweak(&secret_scalar).unwrap();

// 	let mut signature=r_xonly.serialize().to_vec();
// 	signature.extend_from_slice(&last_half.secret_bytes());
// 	return signature
// }

pub fn aggregate_sig_2(secp:&Secp256k1<All>,msg:&Scalar,aggregate_pub_k:&PublicKey,alice_sig:&Vec<u8>, bob_sig:&Vec<u8>)->Vec<u8>{
	
	// random half ..32

	let r_xonly=PublicKey::from_x_only_public_key(XOnlyPublicKey::from_slice(&alice_sig[..32]).unwrap(), Parity::Even)
	.combine(&PublicKey::from_x_only_public_key(XOnlyPublicKey::from_slice(&bob_sig[..32]).unwrap(), Parity::Even)).unwrap().x_only_public_key().0;

	let mut engine = sha256::HashEngine::default();
	engine.input(&r_xonly.serialize());
	engine.input(&aggregate_pub_k.x_only_public_key().0.serialize());
	engine.input(&msg.to_be_bytes());
    let h_p_scalar = Scalar::from_be_bytes(sha256::Hash::from_engine(engine).into_inner()).unwrap();

	let alice_scalar=SecretKey::from_slice(alice_sig[..32].try_into().unwrap()).unwrap();
	let bob_scalar=Scalar::from_be_bytes(bob_sig[..32].try_into().unwrap()).unwrap();
	
	let last_half=
	aggregate_pub_k
	.mul_tweak(&secp,&h_p_scalar).unwrap()
	.add_exp_tweak(&secp,&Scalar::from_be_bytes(alice_scalar.add_tweak(&bob_scalar).unwrap().secret_bytes()).unwrap()).unwrap();

	// let bob_signature=bob_pub_k.mul_tweak(&secp,&h_p_scalar).unwrap().add_exp_tweak(&secp,&bob_scalar).unwrap();

	// sig half

	// let last_half=alice_signature.combine(&bob_signature).unwrap().x_only_public_key().0;
;
	let mut signature =r_xonly.serialize().to_vec();
	signature.extend_from_slice(&PublicKey::from_secret_key(secp,&SecretKey::from_slice(&h_p_scalar.to_be_bytes()).unwrap()).x_only_public_key().0
	.add_tweak(&secp,&h_p_scalar).unwrap().0.serialize());

	return signature;
}

pub fn combine_sig(secp:&Secp256k1<All>,alice_sig:&Vec<u8>, bob_sig:&Vec<u8>)->Vec<u8>{

	let mut signature=XOnlyPublicKey::from_slice(&alice_sig[..32]).unwrap()
	.add_tweak(&secp,&Scalar::from_be_bytes(bob_sig[..32].try_into().unwrap()).unwrap()).unwrap().0.serialize().to_vec() ;

	let last_half=SecretKey::from_slice(&alice_sig[32..]).unwrap()
	.add_tweak( &Scalar::from_be_bytes(bob_sig[32..].try_into().unwrap()).unwrap()).unwrap();
	signature.extend_from_slice(&last_half.secret_bytes());
	return signature;
}

#[test]
pub fn test(){

	let msg=Scalar::random();
	let secp=Secp256k1::<All>::new();
	let alice_pub_k=KeySet::new(&secp);
	let bob_pub_k=KeySet::new(&secp);


	let aggregate_pub_k =alice_pub_k.public_key.combine(&bob_pub_k.public_key).unwrap();
	// assert_eq!(aggregate_pub_k,bob_pub_k.public_key.combine(&alice_pub_k.public_key).unwrap());
	let a_z=KeySet::new(&secp);
	let b_z=KeySet::new(&secp);

	let z= PublicKey::from_secret_key(&secp,&SecretKey::from_slice(&a_z.secret_key.secret_bytes()).unwrap())
	.combine(&PublicKey::from_secret_key(&secp,&SecretKey::from_slice(&b_z.secret_key.secret_bytes()).unwrap())).unwrap().x_only_public_key().0;

	// let alice_sig=alice_pub_k.schnorr_sig_x_only(&msg,&a_z,&r, &aggregate_pub_k.x_only_public_key().0);
	// let bob_sig=alice_pub_k.schnorr_sig_x_only(&msg,&a_z,&r, &aggregate_pub_k.x_only_public_key().0);

	let alice_sig=alice_pub_k.schnorr_sig_x_only(&msg,&aggregate_pub_k.x_only_public_key().0,&Scalar::from_be_bytes(a_z.secret_key.secret_bytes()).unwrap(),&z);
	let bob_sig=bob_pub_k.schnorr_sig_x_only(&msg,&aggregate_pub_k.x_only_public_key().0,&Scalar::from_be_bytes(b_z.secret_key.secret_bytes()).unwrap(),&z);
	// let bob_sig=alice_pub_k.schnorr_sig(&msg);

	// let alice_partial_verification=KeySet::partial_verification(
	// 	&alice_sig, 
	// 	&msg.to_be_bytes().to_vec(), 
	// 	&alice_pub_k.public_key.x_only_public_key().0,
	// 	&aggregate_pub_k.x_only_public_key().0, 
	// 	&shared_random_k
	// );
	// assert!(alice_partial_verification);
	
	// let bob_partial_verification=KeySet::partial_verification(
	// 	&bob_sig, 
	// 	&msg.to_be_bytes().to_vec(), 
	// 	&bob_pub_k.public_key.x_only_public_key().0,
	// 	&aggregate_pub_k.x_only_public_key().0, 
	// 	&shared_random_k
	// );
	
	// assert!(bob_partial_verification);
	
	
	let sig=combine_sig(&secp,&alice_sig,&bob_sig);
	let sig_2=aggregate_sig_2(&secp,&msg,&aggregate_pub_k,&alice_sig,&bob_sig);

	let check=XOnlyPublicKey::from_slice(&sig_2[32..]).unwrap();
	let final_sig=PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&sig[32..]).unwrap()).x_only_public_key().0;


	assert_eq!(final_sig,check );
	// let final_verification=KeySet::verify(&sig, &msg.to_be_bytes().to_vec(), &aggregate_pub_k.x_only_public_key().0);

// let final_verification=KeySet::partial_verification(
// 		&sig_2, 
// 		&msg.to_be_bytes().to_vec(), 
// 		&aggregate_pub_k.x_only_public_key().0,
// 		&aggregate_pub_k.x_only_public_key().0, 
// 		&shared_random_k
// 	);

// dbg!(shared_random_k.to_hex());
// dbg!(sig.to_hex());
	// dbg!(sig_2.to_hex());
	// assert!(final_verification);
	
	// let is_valid=KeySet::aggregate_verify(&alice_sig, &msg.to_be_bytes().to_vec(), &alice_pub_k.public_key.x_only_public_key().0,&aggregate_pub_k.x_only_public_key().0);

	// let final_signature=aggregate_sig_2(&secp,&alice_sig,&alice_sig);

	// let final_sig=aggregate_sig(&secp,&msg,&aggregate_pub_k,&alice_sig,&alice_sig);


	// let is_valid_2=KeySet::verify(&final_sig, &msg.to_be_bytes().to_vec(), &aggregate_pub_k.x_only_public_key().0);
	// dbg!(final_sig.to_hex());
	
	// let is_valid=KeySet::verify(&final_signature, &msg.to_be_bytes().to_vec(), &aggregate_pub_k.x_only_public_key().0);




}
impl KeySet{
	    pub fn schnorr_sig_x_only(&self, msg: &Scalar, p:&XOnlyPublicKey,z:&Scalar,r:&XOnlyPublicKey) -> Vec<u8> {
			let secp = self.secp.clone();

			let random_keyset = KeySet::from_slice(&secp, &z.to_be_bytes());
	
			let mut engine = sha256::HashEngine::default();
			engine.input(&r.serialize());
			engine.input(&p.serialize());
			engine.input(&msg.to_be_bytes());
	
			let h_p_scalar =
				Scalar::from_be_bytes(sha256::Hash::from_engine(engine).into_inner()).unwrap();
			// x*H(R|P|m)+r=s
			dbg!(h_p_scalar.to_be_bytes().to_vec().to_hex());
			let temp=SecretKey::from_slice(&h_p_scalar.to_be_bytes()).unwrap();
			

			let r_scalar = Scalar::from_be_bytes(random_keyset.secret_key.secret_bytes()).unwrap();


			let last_half = self
				.secret_key
				.mul_tweak(&h_p_scalar)
				.unwrap()
				.add_tweak(&r_scalar)
				.unwrap()
				.secret_bytes();
				// dbg!(PublicKey::from_secret_key(&secp, &self.secret_key.mul_tweak(&h_p_scalar).unwrap()).x_only_public_key().0);
		// dbg!(r.serialize().to_hex());
			let mut signature = random_keyset.public_key.x_only_public_key().0.serialize().to_vec();
			signature.extend_from_slice(& temp.secret_bytes());
			return signature;
    }

    // pub fn partial_verification(sig: &[u8], msg: &Vec<u8>, x_only: &XOnlyPublicKey, aggreate_k:&XOnlyPublicKey, r:&XOnlyPublicKey) -> bool {
    //     let secp = Secp256k1::new();

    //     let pk_r: [u8; 32] = sig[..32].try_into().unwrap();

    //     let mut engine = sha256::HashEngine::default();
    //     engine.input(&r.serialize());
    //     engine.input(&aggreate_k.serialize());
    //     engine.input(&msg);

    //     let h_p_scalar =
    //         Scalar::from_be_bytes(sha256::Hash::from_engine(engine).into_inner()).unwrap();
	// 			// dbg!(SecretKey::from_slice(&h_p_scalar.to_be_bytes()).unwrap().secret_bytes().to_hex());
    //     let public_r = XOnlyPublicKey::from_slice(&pk_r).unwrap();

    //     let aux = public_r.public_key(bitcoin::secp256k1::Parity::Even);
    //     // Gx*H(R|P|m)+Gr=Gs => P*H(R|P|m)+R=S

    //     let public_key = x_only.public_key(bitcoin::secp256k1::Parity::Even);


    //     let our_last_half = public_key
    //         .mul_tweak(&secp, &h_p_scalar)
    //         .unwrap()
    //         .combine(&aux)
    //         .unwrap()
    //         .x_only_public_key()
    //         .0
    //         .serialize();
			
	// 	// dbg!(h_p_scalar.to_be_bytes().to_hex());
	// 	// dbg!(public_key.mul_tweak(&secp, &h_p_scalar).unwrap().x_only_public_key().0);

    //     let mut our_signature = pk_r.to_vec();
    //     our_signature.extend_from_slice(&our_last_half);

    //     let there_last_half = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&sig[32..]).unwrap())
    //         .x_only_public_key()
    //         .0
    //         .serialize();
			
    //     let mut there_signature = pk_r.to_vec();
    //     there_signature.extend_from_slice(&there_last_half);
    //     let result = our_signature.eq(&there_signature);

    //     if (!result) {
    //         println!("my hex: {}", our_last_half.to_hex());
    //         println!("There hex: {}", there_last_half.to_hex());
    //     }
    //     return result;
    // }
    
}