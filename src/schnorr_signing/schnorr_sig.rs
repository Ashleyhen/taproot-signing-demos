use bitcoin::secp256k1::{All, PublicKey, Scalar, Secp256k1, SecretKey};

use bitcoin::{secp256k1::Parity, util::key::KeyPair, XOnlyPublicKey};
use bitcoin_hashes::{
    hex::{self, FromHex, ToHex},
    sha256, Hash, HashEngine,
};
pub struct KeySet {
    pub secp: Secp256k1<All>,
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
}
impl KeySet {
    pub fn new(secp: &Secp256k1<All>) -> Self {
        let data = Scalar::random().to_be_bytes();
        return KeySet::from_slice(&secp, &data);
    }

    pub fn from_slice(secp: &Secp256k1<All>, data: &[u8]) -> Self {
        let secret_key = SecretKey::from_slice(&data.to_vec()).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        if public_key.x_only_public_key().1 == Parity::Odd {
            return KeySet {
                secp: secp.clone(),
                secret_key: secret_key.negate(),
                public_key: public_key.negate(&secp),
            };
        } else {
            return KeySet {
                secp: secp.clone(),
                secret_key: secret_key,
                public_key: public_key,
            };
        };
    }

    pub fn schnorr_sig(&self, msg: Scalar) -> Vec<u8> {
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

    pub fn verify(
        secp: &Secp256k1<All>,
        sig: &[u8],
        msg: &Scalar,
        x_only: &XOnlyPublicKey,
    ) -> bool {
        let pub_k = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&sig[32..]).unwrap());

        let last_half_sig = pub_k.x_only_public_key().0;

        let parity = Parity::Even;

        let r_pub_check = XOnlyPublicKey::from_slice(&sig[..32]).unwrap();

        let check_sig = KeySet::check_sig(secp, &msg, &x_only, &r_pub_check);

        let last_half_check = XOnlyPublicKey::from_slice(&check_sig[32..])
            .unwrap()
            .public_key(parity);

        let mut final_signature = sig[..32].to_vec();
        final_signature.extend_from_slice(&last_half_sig.serialize());

        let mut check_signature = sig[..32].to_vec();
        check_signature.extend_from_slice(&last_half_check.x_only_public_key().0.serialize());

        assert_eq!(final_signature.to_hex(), check_signature.to_hex());

        return final_signature.eq(&check_signature);
    }

    fn check_sig(
        secp: &Secp256k1<All>,
        msg: &Scalar,
        p: &XOnlyPublicKey,
        r_xonly: &XOnlyPublicKey,
    ) -> Vec<u8> {
        let mut engine = sha256::HashEngine::default();
        engine.input(&r_xonly.serialize());
        engine.input(&p.serialize());
        engine.input(&msg.to_be_bytes());
        let h_p_scalar =
            Scalar::from_be_bytes(sha256::Hash::from_engine(engine).into_inner()).unwrap();

        let challenge = p
            .public_key(Parity::Even)
            .mul_tweak(&secp, &h_p_scalar)
            .unwrap()
            .combine(&r_xonly.public_key(Parity::Even))
            .unwrap();

        let mut signature = r_xonly.serialize().to_vec();
        signature.extend_from_slice(&challenge.x_only_public_key().0.serialize());

        return signature;
    }

    pub fn get_even_secret(secp: &Secp256k1<All>, public_k: &PublicKey) -> KeySet {
        let b_z = KeySet::new(&secp);

        let shared_secret = public_k
            .add_exp_tweak(
                &secp,
                &Scalar::from_be_bytes(b_z.secret_key.secret_bytes()).unwrap(),
            )
            .unwrap();

        if (shared_secret.x_only_public_key().1.eq(&Parity::Odd)) {
            return KeySet::get_even_secret(&secp, public_k);
        }

        return b_z;
    }

    pub fn aggregate_sign(
        secp: &Secp256k1<All>,
        alice_sig: &Vec<u8>,
        bob_sig: &Vec<u8>,
    ) -> Vec<u8> {
        let x_only = &XOnlyPublicKey::from_slice(&alice_sig[..32])
            .unwrap()
            .public_key(Parity::Even)
            .combine(
                &XOnlyPublicKey::from_slice(&bob_sig[..32])
                    .unwrap()
                    .public_key(Parity::Even),
            )
            .unwrap()
            .x_only_public_key()
            .0;

        let mut signature = x_only.serialize().to_vec();

        let last_half = SecretKey::from_slice(&alice_sig[32..])
            .unwrap()
            .add_tweak(&Scalar::from_be_bytes(bob_sig[32..].try_into().unwrap()).unwrap())
            .unwrap();
        signature.extend_from_slice(
            &KeySet::from_slice(&secp, &last_half.secret_bytes())
                .secret_key
                .secret_bytes(),
        );
        return signature;
    }
}

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
