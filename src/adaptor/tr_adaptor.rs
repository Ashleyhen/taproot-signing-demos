use bitcoin::{
    schnorr::{TapTweak, TweakedKeyPair},
    secp256k1::{schnorr::Signature, Message, Parity, PublicKey, Scalar, Secp256k1, SecretKey},
    KeyPair, SchnorrSig, XOnlyPublicKey,
};
use bitcoin_hashes::{hex::ToHex, Hash, HashEngine};

fn secp() -> Secp256k1<bitcoin::secp256k1::All> {
    Secp256k1::new()
}

const PARITY: Parity = Parity::Even;

pub fn new_secret_k() -> SecretKey {
    SecretKey::from_slice(&Scalar::random().to_be_bytes()).unwrap()
}

fn tagged_hash(tag: &str, args: Vec<Vec<u8>>) -> [u8; 32] {
    // SHA256(SHA256(tag) || SHA256(tag) || x).
    let mut engine_tag = bitcoin::hashes::sha256::Hash::engine();
    engine_tag.input(tag.as_bytes());
    let sha_256_tag = bitcoin::hashes::sha256::Hash::from_engine(engine_tag).into_inner();

    let mut sha_256 = bitcoin::hashes::sha256::Hash::engine();
    sha_256.input(&sha_256_tag.to_vec());
    sha_256.input(&sha_256_tag.to_vec());
    for x in args {
        sha_256.input(&x);
    }
    return bitcoin::hashes::sha256::Hash::from_engine(sha_256).into_inner();
}

pub fn tap_tweak(key_pair: &KeyPair, merkle_root: Option<Vec<u8>>) -> TweakedKeyPair {
    // q=p+H(P|c)
    let x_only = key_pair.x_only_public_key().0;

    let mut args = vec![x_only.serialize().to_vec()];
    if merkle_root.is_some() {
        args.push(merkle_root.unwrap().clone());
    }

    let tap_tweak_hash = Scalar::from_be_bytes(tagged_hash("TapTweakHash", args)).unwrap();

    // tap_tweak_hash
    let tweak_pair = key_pair
        .secret_key()
        .add_tweak(&tap_tweak_hash)
        .unwrap()
        .keypair(&secp())
        .dangerous_assume_tweaked();
    return tweak_pair;
}

pub fn Verify(pk: &XOnlyPublicKey, m: &Vec<u8>, sig: &Vec<u8>) -> bool {
    let r = XOnlyPublicKey::from_slice(&sig[..32]).unwrap();
    let s = SecretKey::from_slice(&sig[32..64]).unwrap();
    let e = Scalar::from_be_bytes(tagged_hash(
        &"BIP0340/challenge".to_owned(),
        vec![r.serialize().to_vec(), pk.serialize().to_vec(), m.to_vec()],
    ))
    .unwrap();

    let our_sig = pk
        .public_key(PARITY)
        .mul_tweak(&secp(), &e)
        .unwrap()
        .combine(&r.public_key(PARITY))
        .unwrap()
        .x_only_public_key()
        .0
        .serialize();
    let their_sig = s.public_key(&secp()).x_only_public_key().0.serialize();
    return our_sig == their_sig;
}

pub fn xor_private_tweak_and_aux(d: &Vec<u8>, auxilary: &Vec<u8>) -> Vec<u8> {
    return d
        .iter()
        .zip(tagged_hash(&"BIP0340/aux".to_owned(), vec![auxilary.to_vec()]).iter())
        .map(|(&x1, &x2)| x1 ^ x2)
        .collect();
}

pub fn calculate_nonce(t: &Vec<u8>, x_only: &XOnlyPublicKey, m: &Vec<u8>) -> [u8; 32] {
    return tagged_hash(
        "BIP0340/nonce",
        vec![t.to_vec(), x_only.serialize().to_vec(), m.to_vec()],
    );
}

pub fn calculate_challenge(
    shared_r: &XOnlyPublicKey,
    x_only: &XOnlyPublicKey,
    m: &Vec<u8>,
) -> [u8; 32] {
    return tagged_hash(
        &"BIP0340/challenge".to_owned(),
        vec![
            shared_r.serialize().to_vec(),
            x_only.serialize().to_vec(),
            m[..].to_vec(),
        ],
    );
}

pub fn partial_sig(aux: &SecretKey, challenge: &Vec<u8>, tweaked_secret: &[u8; 32]) -> Signature {
    let our_sig = SecretKey::from_slice(&challenge)
        .unwrap()
        .mul_tweak(&Scalar::from_be_bytes(tweaked_secret.clone()).unwrap())
        .unwrap()
        .add_tweak(&Scalar::from_be_bytes(aux.secret_bytes()).unwrap())
        .unwrap();

    let mut our_signature = aux.x_only_public_key(&secp()).0.serialize().to_vec();

    our_signature.extend(our_sig.secret_bytes());

    return Signature::from_slice(&our_signature[..]).unwrap();
}

pub fn sign(message: &Vec<u8>, key_pair: &KeyPair, aux: &SecretKey) -> SchnorrSig {
    let primary_secret = even_secret(&key_pair.secret_key());

    let x_only = primary_secret.x_only_public_key(&secp()).0;
    let d = primary_secret.secret_bytes().to_vec();

    let t = d
        .iter()
        .zip(tagged_hash(&"BIP0340/aux".to_owned(), vec![aux.secret_bytes().to_vec()]).iter())
        .map(|(&x1, &x2)| x1 ^ x2)
        .collect();

    let rand = tagged_hash(
        "BIP0340/nonce",
        vec![t, x_only.serialize().to_vec(), message[..].to_vec()],
    );
    let our_r = SecretKey::from_slice(&rand)
        .unwrap()
        .x_only_public_key(&secp())
        .0;
    let k = even_secret(&SecretKey::from_slice(&rand).unwrap());

    let e = tagged_hash(
        &"BIP0340/challenge".to_owned(),
        vec![
            our_r.serialize().to_vec(),
            x_only.serialize().to_vec(),
            message[..].to_vec(),
        ],
    );
    let our_sig = SecretKey::from_slice(&e)
        .unwrap()
        .mul_tweak(&Scalar::from_be_bytes(d.try_into().unwrap()).unwrap())
        .unwrap()
        .add_tweak(&Scalar::from_be_bytes(k.secret_bytes()).unwrap())
        .unwrap();

    let mut our_signature = our_r.serialize().to_vec();

    our_signature.extend(our_sig.secret_bytes());
    our_signature.push(0x81 as u8);

    return SchnorrSig::from_slice(&our_signature[..]).unwrap();
}

pub fn aggregate_sign(sig: &[Signature; 2]) -> Vec<u8> {
    let x_only = &XOnlyPublicKey::from_slice(&sig[0][..32])
        .unwrap()
        .public_key(PARITY)
        .combine(
            &XOnlyPublicKey::from_slice(&sig[1][..32])
                .unwrap()
                .public_key(PARITY),
        )
        .unwrap()
        .x_only_public_key()
        .0;

    let mut signature = x_only.serialize().to_vec();

    let last_half = SecretKey::from_slice(&sig[0][32..])
        .unwrap()
        .add_tweak(&Scalar::from_be_bytes(sig[1][32..].try_into().unwrap()).unwrap())
        .unwrap();

    signature.extend_from_slice(&last_half.secret_bytes());
    return signature;
}
fn extract_sig_without_t(tweak: &SecretKey, signature: &Vec<u8>) -> Vec<u8> {
    let sig = Scalar::from_be_bytes(signature[32..].to_vec().try_into().unwrap()).unwrap();
    let last_part = tweak.negate().add_tweak(&sig).unwrap();
    let mut complete_sig = signature[..32].to_vec();
    complete_sig.extend_from_slice(&last_part.secret_bytes());
    return complete_sig;
}

fn keyset_as_aux_for_sig(r: SecretKey, sig: [u8; 32]) -> Signature {
    let mut full_sig = PublicKey::from_secret_key(&secp(), &r)
        .x_only_public_key()
        .0
        .serialize()
        .to_vec();
    full_sig.extend_from_slice(&sig.to_vec());

    return Signature::from_slice(&full_sig).unwrap();
}

pub fn calculate_signature(pk: &XOnlyPublicKey, challenge: &[u8; 32], aux: &Vec<u8>) -> [u8; 33] {
    return pk
        .public_key(PARITY)
        .mul_tweak(&secp(), &Scalar::from_be_bytes(challenge.clone()).unwrap())
        .unwrap()
        .combine(
            &XOnlyPublicKey::from_slice(&aux[..32])
                .unwrap()
                .public_key(PARITY),
        )
        .unwrap()
        .serialize();
}
#[derive(Clone, Copy)]
pub struct Signer {
    primary_secret: SecretKey,
    secondary_secret: SecretKey,
}

impl Signer {
    pub fn get_even_aux(d: SecretKey, message: &Vec<u8>, a: SecretKey) -> Signer {
        let t = xor_private_tweak_and_aux(&d.secret_bytes().to_vec(), &a.secret_bytes().to_vec());

        let r = SecretKey::from_slice(&calculate_nonce(
            &t,
            &d.public_key(&secp()).x_only_public_key().0,
            &message.to_vec(),
        ))
        .unwrap();

        if r.x_only_public_key(&secp()).1.eq(&Parity::Even) {
            return Signer {
                primary_secret: a,
                secondary_secret: r,
            };
        }

        return Signer {
            primary_secret: a,
            secondary_secret: r.negate(),
        };
    }

    pub fn get_even_secret(x: SecretKey) -> Signer {
        let d = SecretKey::from_slice(
            &tap_tweak(&x.keypair(&secp()), None)
                .to_inner()
                .secret_bytes(),
        )
        .unwrap();
        if d.x_only_public_key(&secp()).1.eq(&PARITY) {
            return Signer {
                primary_secret: x,
                secondary_secret: d,
            };
        }
        return Signer {
            primary_secret: x,
            secondary_secret: d.negate(),
        };
    }

    pub fn compute_even_aux(&self, their_pub_k: &PublicKey) -> Signer {
        let pub_k = self
            .secondary_secret
            .public_key(&secp())
            .combine(&their_pub_k)
            .unwrap();
        if pub_k.x_only_public_key().1.eq(&PARITY) {
            return self.clone();
        }
        let signer = Self::get_even_secret(new_secret_k());
        return signer.compute_even_aux(their_pub_k);
    }

    pub fn even_shared_aux(&self, their_pub_k: &PublicKey, message: &Vec<u8>) -> Signer {
        let shared_pub_k = self
            .secondary_secret
            .public_key(&secp())
            .combine(&their_pub_k)
            .unwrap();

        if shared_pub_k.x_only_public_key().1.eq(&PARITY) {
            return self.clone();
        }

        let aux_signer = Self::get_even_aux(
            self.primary_secret,
            message,
            SecretKey::from_slice(&Scalar::random().to_be_bytes()).unwrap(),
        );
        return aux_signer.even_shared_aux(their_pub_k, message);
    }
}
struct Checks {}

impl Checks {
    pub fn single_sig_check(
        rand: &SecretKey,
        message: &Vec<u8>,
        tweaked_secret: &[u8; 32],
    ) -> bool {
        let key_pair = KeyPair::from_seckey_slice(&secp(), tweaked_secret).unwrap();
        let sig = sign(message, &key_pair, rand);
        return Verify(
            &key_pair.public_key().x_only_public_key().0,
            message,
            &sig.sig[..].to_vec(),
        );
    }

    pub fn verify_with_challenge(pk: &XOnlyPublicKey, e: &Scalar, sig: &Vec<u8>) -> bool {
        let r = XOnlyPublicKey::from_slice(&sig[..32]).unwrap();
        let s = SecretKey::from_slice(&sig[32..]).unwrap();

        let our_sig = pk
            .public_key(PARITY)
            .mul_tweak(&secp(), &e)
            .unwrap()
            .combine(&r.public_key(PARITY))
            .unwrap()
            .serialize();

        let their_sig = s.public_key(&secp()).serialize();
        assert_eq!(
            our_sig,
            their_sig,
            "\n{}  \n{}",
            our_sig.to_hex(),
            their_sig.to_hex()
        );

        return our_sig == their_sig;
    }
}

#[test]
pub fn test() {
    let init_scret =
        Signer::get_even_secret(SecretKey::from_slice(&Scalar::random().to_be_bytes()).unwrap());
    let x = [
        init_scret,
        init_scret.compute_even_aux(&init_scret.secondary_secret.public_key(&secp())),
    ];

    let d = [x[0].secondary_secret, x[1].secondary_secret];

    let shared_p = d[0]
        .public_key(&secp())
        .combine(&d[1].public_key(&secp()))
        .unwrap();

    let message = Scalar::ONE.to_be_bytes().to_vec();
    let init_aux = Signer::get_even_aux(
        d[0],
        &message,
        SecretKey::from_slice(&Scalar::random().to_be_bytes()).unwrap(),
    );

    let a = [
        init_aux,
        Signer::get_even_aux(
            d[1],
            &message,
            SecretKey::from_slice(&Scalar::random().to_be_bytes()).unwrap(),
        )
        .even_shared_aux(&init_aux.secondary_secret.public_key(&secp()), &message),
    ];

    let r = [a[0].secondary_secret, a[1].secondary_secret];

    let aux = vec![
        a[0].secondary_secret.public_key(&secp()),
        a[1].secondary_secret.public_key(&secp()),
    ];

    let shared_aux = aux[0].combine(&aux[1]).unwrap();

    let decrypted_secret = compute_even_secret(new_secret_k(), &shared_aux);

    let e = calculate_challenge(
        &shared_aux.x_only_public_key().0,
        &shared_p.x_only_public_key().0,
        &message,
    );

    let pre_sig = partial_sig(
        &r[0]
            .add_tweak(&Scalar::from_be_bytes(decrypted_secret.secret_bytes()).unwrap())
            .unwrap(),
        &e.to_vec(),
        &d[0].secret_bytes(),
    );

    let sig = [
        keyset_as_aux_for_sig(r[0], pre_sig[32..].try_into().unwrap()),
        partial_sig(&r[1], &e.to_vec(), &d[1].secret_bytes()),
    ];

    Checks::single_sig_check(
        &r[0],
        &message,
        &SecretKey::from_slice(&d[0].secret_bytes())
            .unwrap()
            .secret_bytes(),
    );
    Checks::single_sig_check(
        &r[1],
        &message,
        &SecretKey::from_slice(&d[1].secret_bytes())
            .unwrap()
            .secret_bytes(),
    );

    let signature = Signature::from_slice(&aggregate_sign(&sig)).unwrap();

    let final_sig = Signature::from_slice(&extract_sig_without_t(
        &decrypted_secret,
        &signature[..].to_vec(),
    ))
    .unwrap();

    secp()
        .verify_schnorr(
            &final_sig,
            &Message::from_slice(&message).unwrap(),
            &shared_p.x_only_public_key().0,
        )
        .unwrap();
}

fn reveal_tweak(pre_sig: &Vec<u8>, sig: &Vec<u8>) -> SecretKey {
    return SecretKey::from_slice(&sig[32..].to_vec())
        .unwrap()
        .negate()
        .add_tweak(&Scalar::from_be_bytes(pre_sig[32..].to_vec().try_into().unwrap()).unwrap())
        .unwrap();
}

pub fn even_secret(secret: &SecretKey) -> SecretKey {
    if secret.x_only_public_key(&secp()).1.eq(&PARITY) {
        return secret.clone();
    }
    return secret.negate();
}

pub fn compute_even_secret(secret: SecretKey, their_pub_k: &PublicKey) -> SecretKey {
    if secret
        .public_key(&secp())
        .combine(their_pub_k)
        .unwrap()
        .x_only_public_key()
        .1
        .eq(&PARITY)
    {
        return secret;
    }

    return compute_even_secret(new_secret_k(), their_pub_k);
}
