use bitcoin::{
    psbt::serialize::Serialize,
    schnorr::{TapTweak, TweakedKeyPair, TweakedPublicKey},
    secp256k1::{schnorr::Signature, All, Message, Parity, Scalar, Secp256k1, SecretKey, PublicKey},
    util::taproot::TapTweakHash,
    KeyPair, SchnorrSig, XOnlyPublicKey,
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

    let mut args = vec![x_only.serialize().to_vec()];
    if merkle_root.is_some() {
        args.push(merkle_root.unwrap().clone());
    }

    let tap_tweak_hash = Scalar::from_be_bytes(tagged_hash("TapTweakHash", args)).unwrap();

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
    let s = SecretKey::from_slice(&sig[32..64]).unwrap();

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
        .unwrap().x_only_public_key().0
        .serialize();

    let their_sig = s.public_key(&secp()).x_only_public_key().0.serialize();
    assert_eq!(
        our_sig,
        their_sig,
        "\n{}  \n{}",
        our_sig.to_hex(),
        their_sig.to_hex()
    );

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

pub fn partial_sig(
    rand: &Vec<u8>,
    challenge: &Vec<u8>,
    tweaked_secret: &[u8; 32],
) -> Signature {
let aux=SecretKey::from_slice(&rand).unwrap();
     let our_sig=SecretKey::from_slice(&challenge)
        .unwrap()
        .mul_tweak(&Scalar::from_be_bytes(tweaked_secret.clone()).unwrap())
        .unwrap()
        .add_tweak(
            &Scalar::from_be_bytes(even_secret(&aux).secret_bytes()).unwrap()
        )
        .unwrap();

    let mut our_signature = aux.x_only_public_key(&secp()).0.serialize().to_vec();

    our_signature.extend(our_sig.secret_bytes());
    // our_signature.push(0x81 as u8);

    return Signature::from_slice(&our_signature[..]).unwrap();
}

pub fn sign(message: &Vec<u8>, key_pair: &KeyPair,aux: &Vec<u8>) -> SchnorrSig {
    let secret_key = even_secret(&key_pair.secret_key());

    let x_only = secret_key.x_only_public_key(&secp()).0;
    let d = secret_key.secret_bytes().to_vec();

    let t = d
        .iter()
        .zip(
            tagged_hash(
                &"BIP0340/aux".to_owned(),
                vec![aux.to_vec()],
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

pub fn aggregate_sign(sig: &[Signature; 2]) -> Vec<u8> {
    let x_only = &XOnlyPublicKey::from_slice(&sig[0][..32])
        .unwrap()
        .public_key(Parity::Even)
        .combine(
            &XOnlyPublicKey::from_slice(&sig[1][..32])
                .unwrap()
                .public_key(Parity::Even),
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



pub fn calculate_signature(pk: &XOnlyPublicKey, challenge: &[u8; 32], aux: &Vec<u8>) -> [u8; 33] {
    return pk
        .public_key(bitcoin::secp256k1::Parity::Even)
        .mul_tweak(&secp(), &Scalar::from_be_bytes(challenge.clone()).unwrap())
        .unwrap()
        .combine(
            &XOnlyPublicKey::from_slice(&aux[..32])
                .unwrap()
                .public_key(bitcoin::secp256k1::Parity::Even),
        )
        .unwrap()
        .serialize();
}

#[test]
pub fn test() {
    let x = [
        SecretKey::from_slice(&Scalar::random().to_be_bytes()).unwrap(),
        SecretKey::from_slice(&Scalar::random().to_be_bytes()).unwrap(),
    ];

    let commitment = [
        &Scalar::random().to_be_bytes().to_vec(),
        &Scalar::random().to_be_bytes().to_vec(),
    ];

    let _d = [
        tap_tweak(&x[0].keypair(&secp()), Some(commitment[0].to_vec())),
        tap_tweak(&x[1].keypair(&secp()), Some(commitment[1].to_vec())),
    ];

    let d = vec![
        even_secret(&SecretKey::from_slice(&_d[0].to_inner().secret_bytes()).unwrap()),
        even_secret(&SecretKey::from_slice(&_d[1].to_inner().secret_bytes()).unwrap()),
    ];

    let shared_p = d[0]
        .public_key(&secp())
        .combine(&d[1].public_key(&secp()))
        .unwrap();
    // mock

    let message = Scalar::ONE.to_be_bytes().to_vec();

    let a = [
        &Scalar::random().to_be_bytes().to_vec(),
        &Scalar::random().to_be_bytes().to_vec(),
    ];

    let t = vec![
        xor_private_tweak_and_aux(&d[0].secret_bytes().to_vec(), a[0]),
        xor_private_tweak_and_aux(&d[1].secret_bytes().to_vec(), a[1]),
    ];

    let r = [
        calculate_nonce(&t[0], &d[0].public_key(&secp()).x_only_public_key().0, &message),
        calculate_nonce(&t[1], &d[1].public_key(&secp()).x_only_public_key().0, &message),
    ];

        let aux = vec![
        SecretKey::from_slice(&r[0]).unwrap().public_key(&secp()),
        SecretKey::from_slice(&r[1]).unwrap().public_key(&secp()),
    ];

    let shared_aux = aux[0].combine(&aux[1]).unwrap();

    let e =calculate_challenge(&shared_aux.x_only_public_key().0, &shared_p.x_only_public_key().0, &message);

    let sig = [
        partial_sig(
            &r[0].to_vec(),
            &e.to_vec(),
            &d[0].secret_bytes(),
        ),
        partial_sig(
            &r[1].to_vec(),
            &e.to_vec(),
            &d[1].secret_bytes(),
        )
    ];

    Checks::single_sig_check(&r[0].to_vec(),&message,&SecretKey::from_slice(&d[0].secret_bytes()).unwrap().secret_bytes());
    Checks::single_sig_check(&r[1].to_vec(),&message,&SecretKey::from_slice(&d[1].secret_bytes()).unwrap().secret_bytes());

    Checks::verify_with_challenge(&d[0].public_key(&secp()).x_only_public_key().0, &Scalar::from_be_bytes(e).unwrap(), &sig[0][..].to_vec());
    Checks::verify_with_challenge(&d[1].public_key(&secp()).x_only_public_key().0, &Scalar::from_be_bytes(e).unwrap(), &sig[1][..].to_vec());


let final_sig=aggregate_sign(&sig);

Verify(&shared_p.x_only_public_key().0, &message, &final_sig);



//   rand: &Vec<u8>,
//     message: &Vec<u8>,
//     tweaked_secret: &[u8; 32],
//     sig: &Vec<u8>,
    

    // let shared_sig = aggregate_sign(&s);

    // advanced_verification(&shared_p,  &shared_sig);

    // let is_successful = Verify(&shared_p.x_only_public_key().0, &message.try_into().unwrap(), &shared_sig);
    // println!("Is verifcation successful ?  {}", is_successful);
}


struct Checks{}

impl Checks{
    pub fn single_sig_check(
        rand: &Vec<u8>,
        message: &Vec<u8>,
        tweaked_secret: &[u8; 32],
    ) -> bool {
        let key_pair=KeyPair::from_seckey_slice(&secp(), tweaked_secret).unwrap();
        let sig=sign(message, &key_pair,rand);
        return Verify(&key_pair.public_key().x_only_public_key().0, message, &sig.sig[..].to_vec());
    }


    pub fn verify_with_challenge(pk: &XOnlyPublicKey,e:&Scalar,  sig: &Vec<u8>,) -> bool {
        let r = XOnlyPublicKey::from_slice(&sig[..32]).unwrap();
        let s = SecretKey::from_slice(&sig[32..]).unwrap();

        let our_sig = pk
            .public_key(bitcoin::secp256k1::Parity::Even)
            .mul_tweak(&secp(), &e)
            .unwrap()
            .combine(&r.public_key(bitcoin::secp256k1::Parity::Even))
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
