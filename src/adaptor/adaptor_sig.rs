use bitcoin::{
    secp256k1::{All, PublicKey, Scalar, Secp256k1, SecretKey},
    XOnlyPublicKey,
};
use bitcoin_hashes::{sha256, Hash, HashEngine};
use sha2::digest::crypto_common::Key;

use crate::schnorr_signing::schnorr_sig::KeySet;

#[test]
pub fn test_musig() {
    let msg = Scalar::random();

    let secp = Secp256k1::<All>::new();

    let alice_k = KeySet::new(&secp);

    let bob_k = KeySet::get_even_secret(&secp, &alice_k.public_key);

    let aggregate_x_only = alice_k
        .public_key
        .combine(&bob_k.public_key)
        .unwrap()
        .x_only_public_key()
        .0;

    let b_z = KeySet::new(&secp);

    let a_z = KeySet::get_even_secret(&secp, &b_z.public_key);

    let r = a_z
        .public_key
        .combine(&b_z.public_key)
        .unwrap()
        .x_only_public_key()
        .0;


    let secret_scalar_mapping = |secret_key: &SecretKey| {
        Scalar::from_be_bytes(secret_key.secret_bytes().try_into().unwrap()).unwrap()
    };
	
    let t =KeySet::get_even_secret(&secp, &a_z.public_key);

	let tweak=secret_scalar_mapping(&t.secret_key);


    let alice_pre_sign = alice_k.partial_sig(
        &msg,
        &aggregate_x_only,
        &secret_scalar_mapping(&a_z.secret_key.add_tweak(&tweak).unwrap()),
        &r,
    );

    let bob_pre_sign = bob_k.partial_sig(
        &msg,
        &aggregate_x_only,
        &secret_scalar_mapping(&b_z.secret_key),
        &r,
    );

	let is_alice_valid = KeySet::partial_verification(
        &secp,
        &alice_pre_sign,
        &msg,
        &alice_k.public_key.x_only_public_key().0,
        &aggregate_x_only,
        &r,
    );


    let is_bob_valid = KeySet::partial_verification(
        &secp,
        &bob_pre_sign,
        &msg,
        &bob_k.public_key.x_only_public_key().0,
        &aggregate_x_only,
        &r,
    );

    assert!(is_bob_valid);

    assert!(is_alice_valid);

	let alice_sig=a_z.keyset_as_aux_for_sig(alice_pre_sign[32..].try_into().unwrap());

    let aggregate_sig = KeySet::aggregate_sign(&secp, &alice_sig, &bob_pre_sign);

    let alice_sig = alice_k.extract_sig_without_t(&t.secret_key, &aggregate_sig);

    // alice takes her coins
    let can_alice_take_her_k=KeySet::verify(&secp,&alice_sig, &msg, &aggregate_x_only);

	assert!(can_alice_take_her_k);

    let complete = KeySet::reveal_tweak( &aggregate_sig,&alice_sig,);

    assert_eq!(complete.display_secret(), t.secret_key.display_secret());

    let bob_sig=&KeySet::compute_last_sig(&complete,&aggregate_sig);
    
    let can_bob_take_his_k=KeySet::verify(&secp,bob_sig, &msg, &aggregate_x_only);

	assert!(can_bob_take_his_k);

}

impl KeySet {
    fn compute_last_sig(complete:&SecretKey, bobs_musig:&Vec<u8>)->Vec<u8>{
        let mut sig = bobs_musig[..32].to_vec(); 
        sig.extend_from_slice(&complete.negate().add_tweak(&Scalar::from_be_bytes(bobs_musig[32..].try_into().unwrap()).unwrap()).unwrap().secret_bytes().to_vec());
        return sig;
    }
    fn extract_sig_without_t(&self, tweak: &SecretKey, signature: &Vec<u8>) -> Vec<u8> {
        let sig = Scalar::from_be_bytes(signature[32..].to_vec().try_into().unwrap()).unwrap();
        let last_part = tweak.negate().add_tweak(&sig).unwrap();
        let mut complete_sig = signature[..32].to_vec();
        complete_sig.extend_from_slice(&last_part.secret_bytes());
        return complete_sig;
    }

    fn reveal_tweak(pre_sig: &Vec<u8>, sig: &Vec<u8>) -> SecretKey {
        return SecretKey::from_slice(&sig[32..].to_vec())
            .unwrap()
            .negate()
            .add_tweak(&Scalar::from_be_bytes(pre_sig[32..].to_vec().try_into().unwrap()).unwrap())
            .unwrap();
    }
	fn keyset_as_aux_for_sig(&self, sig:[u8;32])->Vec<u8>{
		let mut full_sig = PublicKey::from_secret_key(&self.secp, &self.secret_key).x_only_public_key().0.serialize().to_vec();
        full_sig.extend_from_slice(&sig.to_vec());
        return full_sig;
	}
}
