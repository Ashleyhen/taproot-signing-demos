mod adaptor;
mod multi_sig;
mod schnorr_signing;
use bitcoin::{
    secp256k1::{All, Parity, PublicKey, Scalar, Secp256k1, SecretKey},
    XOnlyPublicKey,
};
use bitcoin_hashes::{hex::ToHex, sha256, Hash, HashEngine};
use schnorr_signing::schnorr_sig::KeySet;

fn main() {
    let secp = Secp256k1::new();
    let msg = Scalar::ONE;

    let alices_keys = KeySet::new(&secp);
    let bobs_keys = KeySet::get_even_secret(&secp, &alices_keys.public_key);

    let aggregate_x_only = alices_keys
        .public_key
        .combine(&bobs_keys.public_key)
        .unwrap()
        .x_only_public_key()
        .0;

    let a_z = KeySet::new(&secp);

    let b_z = KeySet::get_even_secret(&secp, &a_z.public_key);

    let r = a_z
        .public_key
        .combine(&b_z.public_key)
        .unwrap()
        .x_only_public_key()
        .0;

    let alice_sig = alices_keys.partial_sig(
        &msg,
        &aggregate_x_only,
        &Scalar::from_be_bytes(a_z.secret_key.secret_bytes()).unwrap(),
        &r,
    );
    let bob_sig = bobs_keys.partial_sig(
        &msg,
        &aggregate_x_only,
        &Scalar::from_be_bytes(b_z.secret_key.secret_bytes()).unwrap(),
        &r,
    );
    let sig = KeySet::aggregate_sign(&alice_sig, &bob_sig);

    let is_valid = KeySet::verify(&secp, &sig, &msg, &aggregate_x_only);

    println!("is this a valid signature:? {}", is_valid);
}
