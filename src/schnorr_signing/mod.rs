use bitcoin::secp256k1::{Scalar, Secp256k1};

use self::schnorr_sig::KeySet;

pub mod schnorr_sig;

#[test]
fn test_single_schnorr_sig() {
    for i in 0..5 {
        let secp = Secp256k1::new();
        let secret = Scalar::random();
        let key_set = KeySet::from_slice(&secp, &secret.to_be_bytes());
        let msg = Scalar::ONE;
        let signature = key_set.schnorr_sig(msg);

        let is_success = KeySet::verify(
            &secp,
            &signature,
            &msg,
            &key_set.public_key.x_only_public_key().0,
        );
        assert!(is_success)
    }
}
