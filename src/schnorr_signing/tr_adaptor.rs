use bitcoin::{
    schnorr::{TapTweak, TweakedKeyPair, TweakedPublicKey},
    secp256k1::{schnorr::Signature, Message, Scalar, Secp256k1, SecretKey, All},
    util::taproot::TapTweakHash,
    KeyPair, XOnlyPublicKey, SchnorrSig,
};
use bitcoin_hashes::{hex::ToHex, Hash, HashEngine};

fn secp() -> Secp256k1<bitcoin::secp256k1::All> {
    Secp256k1::new()
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

fn calculate_r(
    shared_key: TweakedPublicKey,
    auxilary: &SecretKey,
    message: Message,
    key_pair: &KeyPair,
) -> XOnlyPublicKey {
    let commitment = Scalar::random().to_be_bytes();
    let q = tap_tweak(&key_pair, Some(commitment.to_vec()));

    let t = calculate_aux_hash(&q.to_inner().secret_key(), &auxilary);
    let secret_r = calculate_nonce_hash(t, &shared_key.to_inner(), message);

    let r = SecretKey::from_slice(&secret_r)
        .unwrap()
        .public_key(&secp())
        .x_only_public_key()
        .0;
    return r;
}

fn calculate_nonce_hash(
    xor_auxilary: Vec<u8>,
    x_only: &XOnlyPublicKey,
    message: Message,
) -> Vec<u8> {
    return tagged_hash(
        "BIP0340/nonce",
        vec![
            xor_auxilary,
            x_only.serialize().to_vec(),
            message[..].to_vec(),
        ],
    )
    .to_vec();
}

fn calculate_aux_hash(secret: &SecretKey, auxilary: &SecretKey) -> Vec<u8> {
    return secret
        .secret_bytes()
        .iter()
        .zip(
            tagged_hash(
                &"BIP0340/aux".to_owned(),
                vec![auxilary.secret_bytes().to_vec()],
            )
            .iter(),
        )
        .map(|(&x1, &x2)| x1 ^ x2)
        .collect();
}

pub fn tap_tweak(key_pair: &KeyPair, merkle_root: Option<Vec<u8>>) -> TweakedKeyPair {
    // q=p+H(P|c)
    let x_only = key_pair.x_only_public_key().0;

    let mut args=vec![x_only.serialize().to_vec()];
    if merkle_root.is_some() {
        args.push(merkle_root.unwrap().clone());
    }

    let tap_tweak_hash = Scalar::from_be_bytes(tagged_hash("TapTweakHash",args )).unwrap();

    // tap_tweak_hash
    let secret_key = key_pair.secret_key();
    let tweak_pair = secret_key
        .add_tweak(&tap_tweak_hash)
        .unwrap()
        .keypair(&secp())
        .dangerous_assume_tweaked();
    return tweak_pair;
}

pub fn even_secret(secret: &SecretKey) -> SecretKey {
    if secret
        .x_only_public_key(&secp())
        .1
        .eq(&bitcoin::secp256k1::Parity::Even)
    {
        return secret.clone();
    }
    return secret.negate();
}

pub fn Verify(pk: &XOnlyPublicKey, m: &Vec<u8>, sig: &Vec<u8>) -> bool {
    let r = XOnlyPublicKey::from_slice(&sig[..32]).unwrap();
    let s = SecretKey::from_slice(&sig[32..]).unwrap();
    let e = Scalar::from_be_bytes(tagged_hash(
        &"BIP0340/challenge".to_owned(),
        vec![r.serialize().to_vec(), pk.serialize().to_vec(), m.to_vec()],
    ))
    .unwrap();

    let our_sig = pk
        .public_key(bitcoin::secp256k1::Parity::Even)
        .mul_tweak(&secp(), &e)
        .unwrap()
        .combine(&r.public_key(bitcoin::secp256k1::Parity::Even))
        .unwrap()
        .serialize();

    let their_sig = s.public_key(&secp()).serialize();
    dbg!(our_sig.to_vec().to_hex());
    dbg!(their_sig.to_vec().to_hex());
    return our_sig == their_sig;
}

pub fn sign(message: &Vec<u8>, key_pair: &KeyPair) -> SchnorrSig {
    let secret_key = even_secret(&key_pair.secret_key());
    let auxilary = Scalar::random();

    let x_only = secret_key.x_only_public_key(&secp()).0;
    let d = secret_key.secret_bytes().to_vec();

    let t = d
        .iter()
        .zip(
            tagged_hash(
                &"BIP0340/aux".to_owned(),
                vec![auxilary.to_be_bytes().to_vec()],
            )
            .iter(),
        )
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
#[test]
pub fn test() {
    let x = SecretKey::from_slice(&Scalar::random().to_be_bytes()).unwrap();
    let commitment=Scalar::random().to_be_bytes().to_vec();
    let d=tap_tweak(&x.keypair(&secp()), Some(commitment));
    let message=Scalar::ONE.to_be_bytes().to_vec();
    let schnorr_sig=sign(&message, &d.to_inner());
    assert!(Verify(&d.to_inner().x_only_public_key().0, &message, &schnorr_sig.sig[..].to_vec()));
}
