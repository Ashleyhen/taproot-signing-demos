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
            secret_key: secret_key.negate() ,
            public_key: public_key.negate(&secp),
        };

        } else {
            return KeySet {
            secp: secp.clone(),
            secret_key:secret_key,
            public_key: public_key,
        };
        };
        ;
    }

    pub fn schnorr_sig(&self, msg: &Scalar) -> Vec<u8> {
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

    pub fn verify(sig: &[u8], msg: &Scalar, x_only: &XOnlyPublicKey) -> bool {
        let secp = Secp256k1::new();

        let pk_r: [u8; 32] = sig[..32].try_into().unwrap();
        let s = SecretKey::from_slice(&sig[32..]).unwrap();

        let mut engine = sha256::HashEngine::default();
        engine.input(&pk_r);
        engine.input(&x_only.serialize());
        engine.input(&msg.to_be_bytes());

        let h_p_scalar =
            Scalar::from_be_bytes(sha256::Hash::from_engine(engine).into_inner()).unwrap();
        let public_r = XOnlyPublicKey::from_slice(&pk_r).unwrap();

        let aux = public_r.public_key(bitcoin::secp256k1::Parity::Even);
        // Gx*H(R|P|m)+Gr=Gs => P*H(R|P|m)+R=S

        let public_key = x_only.public_key(bitcoin::secp256k1::Parity::Even);

        // secp.sign_schnorr(msg, keypair)
        let our_last_half = public_key
            .mul_tweak(&secp, &h_p_scalar)
            .unwrap()
            .combine(&aux)
            .unwrap()
            .x_only_public_key()
            .0
            .serialize();
        let mut our_signature = pk_r.to_vec();
        our_signature.extend_from_slice(&our_last_half);

        let there_last_half = PublicKey::from_secret_key(&secp, &s)
            .x_only_public_key()
            .0
            .serialize();
        let mut there_signature = pk_r.to_vec();
        there_signature.extend_from_slice(&there_last_half);
        let result = our_signature.eq(&there_signature);
        if (!result) {
            println!("my hex: {}", our_signature.to_hex());
            println!("There hex: {}", there_signature.to_hex());
        }
        return result;
    }
}

fn model() {
    let secp = Secp256k1::new();
    let data_scalar = Scalar::random().to_be_bytes();
    let sk = SecretKey::from_slice(&data_scalar).unwrap();
    let pk = PublicKey::from_secret_key(&secp, &sk);
    let random_scalar = Scalar::random();
    let sk_r = SecretKey::from_slice(&random_scalar.to_be_bytes()).unwrap();
    let pk_r = PublicKey::from_secret_key(&secp, &sk_r);
    let msg = Scalar::ONE;
    let mut engine = sha256::HashEngine::default();
    engine.input(&pk_r.x_only_public_key().0.serialize());
    engine.input(&pk.x_only_public_key().0.serialize());
    engine.input(&msg.to_be_bytes());
    let h_p_scalar = Scalar::from_be_bytes(sha256::Hash::from_engine(engine).into_inner()).unwrap();
    let signer_a = sk
        .mul_tweak(&h_p_scalar)
        .unwrap()
        .add_tweak(&random_scalar)
        .unwrap();
    let mut signature = pk_r.x_only_public_key().0.serialize().to_vec();
    let signing_pk = PublicKey::from_secret_key(&secp, &signer_a);
    signature.extend_from_slice(&signing_pk.x_only_public_key().0.serialize());
    let signer_b = pk
        .mul_tweak(&secp, &h_p_scalar)
        .unwrap()
        .combine(&pk_r)
        .unwrap()
        .x_only_public_key()
        .0
        .serialize()
        .to_vec();
    let mut signature_2 = pk_r.x_only_public_key().0.serialize().to_vec();
    signature_2.extend_from_slice(&signer_b);
    println!("hex: {}", signature.to_hex());
    println!("hex: {}", signature_2.to_hex())
}

#[test]
fn test_single_schnorr_sig() {
    for _ in 0..5 {
        let secp = Secp256k1::new();
        let secret = Scalar::random();
        let key_set = KeySet::from_slice(&secp, &secret.to_be_bytes());
        let msg = Scalar::ONE;
        let signature = key_set.schnorr_sig(&msg);

        let is_success =
            KeySet::verify(&signature, &msg, &key_set.public_key.x_only_public_key().0);
        assert!(is_success)
    }
}
