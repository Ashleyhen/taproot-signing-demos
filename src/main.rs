mod schnorr_signing;

use bitcoin::secp256k1::{All, Parity, PublicKey, Scalar, Secp256k1, SecretKey};
use bitcoin_hashes::{hex::ToHex, sha256, Hash, HashEngine};
use schnorr_signing::schnorr_sig::KeySet;

fn main() {
    let secp = Secp256k1::new();

    // let key_set=KeySet::new(&secp);
    let key_set = KeySet::new(&secp);
    let msg = Scalar::ONE;
    let aux = Scalar::random();
    let signature = key_set.schnorr_sig(msg);

    KeySet::verify(
        &signature,
        &msg.to_be_bytes().to_vec(),
        &key_set.public_key.x_only_public_key().0,
    );
    // model();
}
