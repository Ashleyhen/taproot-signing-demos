use bitcoin::secp256k1::{All, Scalar, Secp256k1};

use crate::schnorr_signing::schnorr_sig::KeySet;

pub mod strawman_musig;
pub mod tr_musig;

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

    let alice_sig = alice_pub_k.partial_sig(
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

    let bob_sig = bob_pub_k.partial_sig(
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

    let sig = KeySet::aggregate_sign(&alice_sig, &bob_sig);

    let is_valid = KeySet::verify(&secp, &sig, &msg, &aggregate_x_only);

    assert!(is_valid);
}
