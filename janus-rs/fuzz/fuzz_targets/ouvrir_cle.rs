//! Ouvre un fichier quelconque avec deux identités connues (graines 0x01… et 0x02…,
//! celles des vecteurs de test). Le corpus de départ contient les vecteurs à clé :
//! le fuzzer part de fichiers valides et explore autour.
//! Propriété : jamais de panique, et un succès ne rend jamais plus d'octets que le fichier.
#![no_main]

use janus::format::{self, Ouverture};
use janus::xwing::Identite;
use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;

static IDENTITES: LazyLock<[Identite; 2]> =
    LazyLock::new(|| [Identite::depuis_graine(&[1; 32]), Identite::depuis_graine(&[2; 32])]);

fuzz_target!(|fichier: &[u8]| {
    if let Ok(clair) = format::dechiffrer(fichier, Ouverture::Identites(&IDENTITES[..])) {
        assert!(clair.len() < fichier.len());
    }
});
