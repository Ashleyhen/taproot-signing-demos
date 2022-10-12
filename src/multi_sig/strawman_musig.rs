use std::str::FromStr;

use bitcoin::{
    secp256k1::{All, Parity, PublicKey, Scalar, Secp256k1, SecretKey},
    XOnlyPublicKey,
};
use bitcoin_hashes::{hex::ToHex, sha256, Hash, HashEngine};

use crate::schnorr_signing::schnorr_sig::KeySet;

pub fn check_sig(
    secp: &Secp256k1<All>,
    msg: &Scalar,
    p: &XOnlyPublicKey,
    r_xonly: &XOnlyPublicKey,
) -> Vec<u8> {
    let mut engine = sha256::HashEngine::default();
    engine.input(&r_xonly.serialize());
    engine.input(&p.serialize());
    engine.input(&msg.to_be_bytes());
    let h_p_scalar = Scalar::from_be_bytes(sha256::Hash::from_engine(engine).into_inner()).unwrap();

    let challenge = p
        .public_key(Parity::Even)
        .mul_tweak(&secp, &h_p_scalar)
        .unwrap()
        .combine(&r_xonly.public_key(Parity::Even))
        .unwrap();
        
    let mut signature = r_xonly.serialize().to_vec();
    signature.extend_from_slice(&check_parity(&secp, &challenge).x_only_public_key().0.serialize());

    return signature;
}

pub fn aggregate_sign(secp: &Secp256k1<All>, alice_sig: &Vec<u8>, bob_sig: &Vec<u8>) -> Vec<u8> {
    let x_only = check_parity(
        &secp,
        &XOnlyPublicKey::from_slice(&alice_sig[..32])
            .unwrap()
            .public_key(Parity::Even)
            .combine(
                &XOnlyPublicKey::from_slice(&bob_sig[..32])
                    .unwrap()
                    .public_key(Parity::Even),
            )
            .unwrap(),
    ).x_only_public_key().0;

    let mut signature = x_only.serialize().to_vec();

    let last_half = SecretKey::from_slice(&alice_sig[32..])
        .unwrap()
        .add_tweak(&Scalar::from_be_bytes(bob_sig[32..].try_into().unwrap()).unwrap())
        .unwrap();
        
    signature.extend_from_slice(&KeySet::from_slice(&secp, &last_half.secret_bytes()).secret_key.secret_bytes());
    return signature;
}

pub fn aggregate_aux(alice_sig: &Vec<u8>, bob_sig: &Vec<u8>) -> PublicKey {
    return PublicKey::from_x_only_public_key(
        XOnlyPublicKey::from_slice(&alice_sig[..32]).unwrap(),
        Parity::Even,
    )
    .combine(&PublicKey::from_x_only_public_key(
        XOnlyPublicKey::from_slice(&bob_sig[..32]).unwrap(),
        Parity::Even,
    ))
    .unwrap();
}

pub fn check_parity(secp: &Secp256k1<All>, aggregate_pub_k: &PublicKey) -> PublicKey {
    return if aggregate_pub_k.x_only_public_key().1.eq(&Parity::Odd) {
        aggregate_pub_k.negate(&secp)
    } else {
        aggregate_pub_k.clone()
    };
}
#[test]
pub fn test() {
    let msg = Scalar::ZERO;
    let secp = Secp256k1::<All>::new();
    
    // let alice_pub_k = KeySet::new(&secp);
    let alice_pub_k =KeySet::from_slice(&secp,&SecretKey::from_str("68e5f0af5f8f47bf79cfd8523cbaf8caa1406586124bc49aca6790c958964860").unwrap().secret_bytes());
    // dbg!(alice_pub_k.secret_key.display_secret());



    // let bob_pub_k = KeySet::new(&secp);
    let bob_pub_k =KeySet::from_slice(&secp,&SecretKey::from_str("e0ac30e24c00a231af56de9ff362c4857f20b450ad7f93950513f31706a4d723").unwrap().secret_bytes());
    // dbg!(bob_pub_k.secret_key.display_secret());

    let aggregate_x_only = check_parity(
        &secp,
        &alice_pub_k
            .public_key
            .combine(&bob_pub_k.public_key)
            .unwrap(),
    )
    .x_only_public_key()
    .0;

    // let a_z = KeySet::new(&secp);
    let a_z =KeySet::from_slice(&secp,&SecretKey::from_str("dbe34ab85f62b78690829d33ccfcc9d59f4d3fa8f1bc26baa36e557953c61732").unwrap().secret_bytes());
    // dbg!(a_z.secret_key.display_secret());

    // let b_z = KeySet::new(&secp);
    let b_z=KeySet::from_slice(&secp,&SecretKey::from_str("f97284a5284a768cb0d0bdfe6e27984d9f3b74607d797d567183d5df3168fd7e").unwrap().secret_bytes());
    // dbg!(b_z.secret_key.display_secret());

    let z = a_z
        .public_key
        .combine(&b_z.public_key)
        .unwrap()
        .x_only_public_key()
        .0;

    let alice_sig = alice_pub_k.schnorr_sig_x_only(
        &msg,
        &aggregate_x_only,
        &Scalar::from_be_bytes(a_z.secret_key.secret_bytes()).unwrap(),
        &z,
    );
    let bob_sig = bob_pub_k.schnorr_sig_x_only(
        &msg,
        &aggregate_x_only,
        &Scalar::from_be_bytes(b_z.secret_key.secret_bytes()).unwrap(),
        &z,
    );

    // assert_eq!(z, r_pub.x_only_public_key().0);

    let sig = aggregate_sign(&secp, &alice_sig, &bob_sig);

    let is_valid = KeySet::aggreate_verify(&secp, &msg, &aggregate_x_only, &sig);

    assert!(is_valid);
}

impl KeySet {
    pub fn aggreate_verify(
        secp: &Secp256k1<All>,
        msg: &Scalar,
        aggregate_pub_k: &XOnlyPublicKey,
        sig: &Vec<u8>,
    ) -> bool {
        let last_half_sig = KeySet::from_slice(secp, &sig[32..]).public_key;

        let parity = Parity::Even;

        let r_pub_check = XOnlyPublicKey::from_slice(&sig[..32])
            .unwrap()
            .public_key(parity);

        let check_sig = check_sig(
            secp,
            &msg,
            &aggregate_pub_k,
            &r_pub_check.x_only_public_key().0,
        );

        let last_half_check = XOnlyPublicKey::from_slice(&check_sig[32..])
            .unwrap()
            .public_key(parity);

        // let last_half_sig=KeySet::from_slice(&secp, &sig[32..].to_vec()).public_key;

        let mut final_signature = sig[..32].to_vec();
        final_signature.extend_from_slice(&last_half_sig.x_only_public_key().0.serialize());

        let mut check_signature = sig[..32].to_vec();
        check_signature.extend_from_slice(&last_half_check.x_only_public_key().0.serialize());

        dbg!(last_half_sig.x_only_public_key().0.serialize().to_hex());
        dbg!(last_half_check.x_only_public_key().0.serialize().to_hex());
        // dbg!(last_half_sig);

        // assert_eq!(r_pub.clone().x_only_public_key().1,r_pub_check.clone().x_only_public_key().1);

        return final_signature.eq(&check_signature);
    }
    pub fn schnorr_sig_x_only(
        &self,
        msg: &Scalar,
        p: &XOnlyPublicKey,
        z: &Scalar,
        r: &XOnlyPublicKey,
    ) -> Vec<u8> {
        let secp = self.secp.clone();

        let random_keyset = KeySet::from_slice(&secp, &z.to_be_bytes());

        let mut engine = sha256::HashEngine::default();
        engine.input(&r.serialize());
        engine.input(&p.serialize());
        engine.input(&msg.to_be_bytes());

        let h_p_scalar =
            Scalar::from_be_bytes(sha256::Hash::from_engine(engine).into_inner()).unwrap();
        // x*H(R|P|m)+r=s
        let last_half = self
            .secret_key
            .mul_tweak(&h_p_scalar)
            .unwrap()
            .add_tweak(z)
            .unwrap();

        let mut signature = random_keyset
            .public_key
            .x_only_public_key()
            .0
            .serialize()
            .to_vec();
        signature.extend_from_slice(&last_half.secret_bytes());
        return signature;
    }

    // pub fn partial_verification(sig: &[u8], msg: &Vec<u8>, x_only: &XOnlyPublicKey, aggreate_k:&XOnlyPublicKey, r:&XOnlyPublicKey) -> bool {
    //     let secp = Secp256k1::new();

    //     let pk_r: [u8; 32] = sig[..32].try_into().unwrap();

    //     let mut engine = sha256::HashEngine::default();
    //     engine.input(&r.serialize());
    //     engine.input(&aggreate_k.serialize());
    //     engine.input(&msg);

    //     let h_p_scalar =
    //         Scalar::from_be_bytes(sha256::Hash::from_engine(engine).into_inner()).unwrap();
    // 			// dbg!(SecretKey::from_slice(&h_p_scalar.to_be_bytes()).unwrap().secret_bytes().to_hex());
    //     let public_r = XOnlyPublicKey::from_slice(&pk_r).unwrap();

    //     let aux = public_r.public_key(bitcoin::secp256k1::Parity::Even);
    //     // Gx*H(R|P|m)+Gr=Gs => P*H(R|P|m)+R=S

    //     let public_key = x_only.public_key(bitcoin::secp256k1::Parity::Even);

    //     let our_last_half = public_key
    //         .mul_tweak(&secp, &h_p_scalar)
    //         .unwrap()
    //         .combine(&aux)
    //         .unwrap()
    //         .x_only_public_key()
    //         .0
    //         .serialize();

    // 	// dbg!(h_p_scalar.to_be_bytes().to_hex());
    // 	// dbg!(public_key.mul_tweak(&secp, &h_p_scalar).unwrap().x_only_public_key().0);

    //     let mut our_signature = pk_r.to_vec();
    //     our_signature.extend_from_slice(&our_last_half);

    //     let there_last_half = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&sig[32..]).unwrap())
    //         .x_only_public_key()
    //         .0
    //         .serialize();

    //     let mut there_signature = pk_r.to_vec();
    //     there_signature.extend_from_slice(&there_last_half);
    //     let result = our_signature.eq(&there_signature);

    //     if (!result) {
    //         println!("my hex: {}", our_last_half.to_hex());
    //         println!("There hex: {}", there_last_half.to_hex());
    //     }
    //     return result;
    // }
}
