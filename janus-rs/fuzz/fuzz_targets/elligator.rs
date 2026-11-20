//! Inverse d'Elligator 2 (spec § 5.4) sur des points QUELCONQUES de la courbe :
//! e·B + L, avec e choisi par le fuzzer et L parmi les 8 points d'ordre faible.
//! Propriété : quand un représentant existe, la carte directe redonne exactement u,
//! et les deux bits de poids fort sont ceux du « tweak ».
#![no_main]

use curve25519_elligator2::{EdwardsPoint, MapToPointVariant, Randomized, Scalar};
use janus::elligator::representant;
use janus::xwing::elligator_vers_point;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|octets: &[u8]| {
    if octets.len() < 64 + 32 + 1 {
        return;
    }
    let e = Scalar::from_bytes_mod_order_wide(octets[..64].try_into().unwrap());
    let x: [u8; 32] = octets[64..96].try_into().unwrap();
    let tweak = octets[96];
    // Point d'ordre faible choisi par les 3 bits bas de x (voir xwing::ephemere_cache).
    let l = Randomized::mul_base_clamped(x) - EdwardsPoint::mul_base_clamped(x);
    let u = (EdwardsPoint::mul_base(&e) + l).to_montgomery().to_bytes();
    if let Some(r) = Option::<[u8; 32]>::from(representant(&u, tweak)) {
        assert_eq!(r[31] & 0xc0, tweak & 0xc0);
        assert_eq!(elligator_vers_point(&r), u, "aller-retour Elligator faux");
    }
});
