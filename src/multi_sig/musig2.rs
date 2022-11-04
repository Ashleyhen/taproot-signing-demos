use bitcoin::{
    secp256k1::{Parity, PublicKey, Scalar, Secp256k1},
    XOnlyPublicKey,
};
use bitcoin_hashes::{sha256, Hash, HashEngine};

pub fn aggregate_pub_k(x: &Vec<PublicKey>) -> PublicKey {
    return x
        .iter()
        .map(|f| f.clone())
        .reduce(|a, b| a.combine(&b).unwrap())
        .unwrap();
}

fn key_agg_coef(l: &XOnlyPublicKey, x: &XOnlyPublicKey) -> Scalar {
    let mut engine = sha256::HashEngine::default();
    engine.input(&l.serialize());
    engine.input(&x.serialize());
    let h_p_scalar = Scalar::from_be_bytes(sha256::Hash::from_engine(engine).into_inner()).unwrap();
    return h_p_scalar;
}

pub fn key_agg(x_vec: &Vec<PublicKey>) -> PublicKey {
    let secp = Secp256k1::new();
    return x_vec
        .iter()
        .map(|f| {
            f.add_exp_tweak(
                &secp,
                &key_agg_coef(
                    &aggregate_pub_k(x_vec).x_only_public_key().0,
                    &f.x_only_public_key().0,
                ),
            )
            .unwrap()
        })
        .reduce(|a, b| a.combine(&b).unwrap())
        .unwrap();
    // let a =;

    // let l=;
}
