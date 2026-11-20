//! Kemeleon (spec § 5.5).
//! Propriétés : toute chaîne de 1536 octets se décode en un chiffré ML-KEM de
//! 1088 octets ; tout chiffré se réencode puis se redécode à l'identique.
#![no_main]

use janus::kemeleon::{TAILLE_CT, TAILLE_ENCODEE, decoder_chiffre, encoder_chiffre};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|octets: &[u8]| {
    let mut encode = [0u8; TAILLE_ENCODEE];
    let n = octets.len().min(TAILLE_ENCODEE);
    encode[..n].copy_from_slice(&octets[..n]);
    let ct = decoder_chiffre(&encode);
    assert_eq!(ct.len(), TAILLE_CT);
    assert_eq!(decoder_chiffre(&encoder_chiffre(&ct)), ct);

    let mut ct2 = [0u8; TAILLE_CT];
    let m = octets.len().min(TAILLE_CT);
    ct2[..m].copy_from_slice(&octets[..m]);
    assert_eq!(decoder_chiffre(&encoder_chiffre(&ct2)), ct2);
});
