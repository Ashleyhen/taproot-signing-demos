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
    let key_set = KeySet::new(&secp);
    let msg = Scalar::ONE;
    let signature = key_set.schnorr_sig(&msg);

    KeySet::verify(&signature, &msg, &key_set.public_key.x_only_public_key().0);
    model();
}
fn model() {
    let bob = 0;
    let alice = 1;

    let secp = Secp256k1::new();
    let sk = vec![
        SecretKey::from_slice(&Scalar::random().to_be_bytes()).unwrap(),
        SecretKey::from_slice(&Scalar::random().to_be_bytes()).unwrap(),
    ];
    let pks = sk
        .iter()
        .map(|s| PublicKey::from_secret_key(&secp, &s))
        .collect::<Vec<PublicKey>>();
    let pk = pks[0].combine(&pks[1]).unwrap();

    let random_scalar = Scalar::random();
    let sk_r = SecretKey::from_slice(&random_scalar.to_be_bytes()).unwrap();
    let pk_r = PublicKey::from_secret_key(&secp, &sk_r);
    let msg = Scalar::ONE;
    let mut engine = sha256::HashEngine::default();
    engine.input(&pk_r.x_only_public_key().0.serialize());
    engine.input(&pk.x_only_public_key().0.serialize());
    engine.input(&msg.to_be_bytes());
    let h_p_scalar = Scalar::from_be_bytes(sha256::Hash::from_engine(engine).into_inner()).unwrap();

    let last_half: Vec<XOnlyPublicKey> = sk
        .iter()
        .map(|secret| {
            secret
                .mul_tweak(&h_p_scalar)
                .unwrap()
                .add_tweak(&random_scalar)
                .unwrap()
        })
        .map(|signer_a| {
            PublicKey::from_secret_key(&secp, &signer_a)
                .x_only_public_key()
                .0
        })
        .collect();

    let last_half_verification: Vec<XOnlyPublicKey> = pks
        .iter()
        .map(|p| {
            p.mul_tweak(&secp, &h_p_scalar)
                .unwrap()
                .combine(&pk_r)
                .unwrap()
                .x_only_public_key()
                .0
        })
        .collect();

    let mut signature = pk_r.x_only_public_key().0.serialize().to_vec();
    let mut signature_verification = pk_r.x_only_public_key().0.serialize().to_vec();

    signature.extend_from_slice(&last_half[0].serialize());
    signature_verification.extend_from_slice(&last_half_verification[0].serialize());

    println!("hex: {}", last_half[0].serialize().to_hex());
    println!("hex: {}", last_half_verification[0].serialize().to_hex());

    let s = last_half[0]
        .add_tweak(
            &secp,
            &Scalar::from_be_bytes(last_half[0].serialize()).unwrap(),
        )
        .unwrap()
        .0;

    dbg!(s.serialize().to_hex());
    // (z1 + z2)*G + hash(r||P||m)*(k1 + k2)*G
    let public_k = PublicKey::from_secret_key(
        &secp,
        &sk[0]
            .add_tweak(&Scalar::from_be_bytes(sk[0].secret_bytes()).unwrap())
            .unwrap(),
    );
    let combine = public_k
        .mul_tweak(&secp, &h_p_scalar)
        .unwrap()
        .add_exp_tweak(
            &secp,
            &Scalar::from_be_bytes(pk_r.x_only_public_key().0.serialize()).unwrap(),
        )
        .unwrap();
    dbg!(combine.x_only_public_key().0.serialize().to_hex());
}
