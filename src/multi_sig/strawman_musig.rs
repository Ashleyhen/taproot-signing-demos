use std::str::FromStr;

use bitcoin::{
    secp256k1::{All, Parity, PublicKey, Scalar, Secp256k1, SecretKey},
    XOnlyPublicKey,
};
use bitcoin_hashes::{hex::ToHex, sha256, Hash, HashEngine};

use crate::schnorr_signing::schnorr_sig::KeySet;

pub fn aggregate_aux(alice_sig: &Vec<u8>, bob_sig: &Vec<u8>) -> PublicKey {
    return PublicKey::from_x_only_public_key(
        XOnlyPublicKey::from_slice(&alice_sig[..32]).unwrap(),
        Parity::Even,
    )
    .combine(&PublicKey::from_x_only_public_key(
        XOnlyPublicKey::from_slice(&bob_sig[..32]).unwrap(),
        Parity::Even,
    ))
    .unwrap();
}

impl KeySet {
    pub fn schnorr_sig_x_only(
        &self,
        msg: &Scalar,
        p: &XOnlyPublicKey,
        z: &Scalar,
        r: &XOnlyPublicKey,
    ) -> Vec<u8> {
        let secp = self.secp.clone();

        let random_keyset = KeySet::from_slice(&secp, &z.to_be_bytes());

        let mut engine = sha256::HashEngine::default();
        engine.input(&r.serialize());
        engine.input(&p.serialize());
        engine.input(&msg.to_be_bytes());

        let h_p_scalar =
            Scalar::from_be_bytes(sha256::Hash::from_engine(engine).into_inner()).unwrap();
        // x*H(R|P|m)+r=s
        let last_half = self
            .secret_key
            .mul_tweak(&h_p_scalar)
            .unwrap()
            .add_tweak(&Scalar::from_be_bytes(random_keyset.secret_key.secret_bytes()).unwrap())
            .unwrap();

        let mut signature = random_keyset
            .public_key
            .x_only_public_key()
            .0
            .serialize()
            .to_vec();

        signature.extend_from_slice(&last_half.secret_bytes());
        return signature;
    }

    pub fn partial_verification(
        secp: &Secp256k1<All>,
        sig: &[u8],
        msg: &Scalar,
        signer_x_only: &XOnlyPublicKey,
        aggreate_k: &XOnlyPublicKey,
        shared_random_pub_k: &XOnlyPublicKey,
    ) -> bool {
        let pk_r: [u8; 32] = sig[..32].try_into().unwrap();

        let mut engine = sha256::HashEngine::default();
        engine.input(&shared_random_pub_k.serialize());
        engine.input(&aggreate_k.serialize());
        engine.input(&msg.to_be_bytes());

        let h_p_scalar =
            Scalar::from_be_bytes(sha256::Hash::from_engine(engine).into_inner()).unwrap();

        let aux = XOnlyPublicKey::from_slice(&pk_r)
            .unwrap()
            .public_key(bitcoin::secp256k1::Parity::Even);

        let our_last_half = signer_x_only
            .public_key(bitcoin::secp256k1::Parity::Even)
            .mul_tweak(&secp, &h_p_scalar)
            .unwrap()
            .combine(&aux)
            .unwrap()
            .x_only_public_key()
            .0
            .serialize();

        let mut our_signature = pk_r.to_vec();
        our_signature.extend_from_slice(&our_last_half);

        let there_last_half =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&sig[32..]).unwrap())
                .x_only_public_key()
                .0
                .serialize();

        let mut there_signature = pk_r.to_vec();
        there_signature.extend_from_slice(&there_last_half);
        let result = our_signature.eq(&there_signature);

        if (!result) {
            println!("my hex: {}", our_last_half.to_hex());
            println!("There hex: {}", there_last_half.to_hex());
        }
        return result;
    }
}

#[test]
pub fn musig() {
    let msg = Scalar::random();

    let secp = Secp256k1::<All>::new();

    let alice_pub_k = KeySet::new(&secp);

    let bob_pub_k = KeySet::get_even_secret(&secp, &alice_pub_k.public_key);

    let aggregate_x_only = alice_pub_k
        .public_key
        .combine(&bob_pub_k.public_key)
        .unwrap()
        .x_only_public_key()
        .0;

    let a_z = KeySet::new(&secp);

    let b_z = KeySet::get_even_secret(&secp, &a_z.public_key);

    let z = a_z
        .public_key
        .combine(&b_z.public_key)
        .unwrap()
        .x_only_public_key()
        .0;

    let alice_sig = alice_pub_k.schnorr_sig_x_only(
        &msg,
        &aggregate_x_only,
        &Scalar::from_be_bytes(a_z.secret_key.secret_bytes()).unwrap(),
        &z,
    );

    let alice_paritial_verify = KeySet::partial_verification(
        &secp,
        &alice_sig,
        &msg,
        &alice_pub_k.public_key.x_only_public_key().0,
        &aggregate_x_only,
        &z,
    );

    assert!(alice_paritial_verify);

    let bob_sig = bob_pub_k.schnorr_sig_x_only(
        &msg,
        &aggregate_x_only,
        &Scalar::from_be_bytes(b_z.secret_key.secret_bytes()).unwrap(),
        &z,
    );

    let bob_paritial_verify = KeySet::partial_verification(
        &secp,
        &bob_sig,
        &msg,
        &bob_pub_k.public_key.x_only_public_key().0,
        &aggregate_x_only,
        &z,
    );

    assert!(bob_paritial_verify);

    let sig = KeySet::aggregate_sign(&secp, &alice_sig, &bob_sig);

    let is_valid = KeySet::verify(&secp, &sig, &msg, &aggregate_x_only);

    assert!(is_valid);
}
