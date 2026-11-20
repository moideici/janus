//! Chiffre un leurre (et parfois un visage caché), applique des mutations choisies
//! par le fuzzer, puis ouvre le leurre.
//! Propriété (intégrité, docs/05) : l'ouverture échoue, ou rend EXACTEMENT le leurre
//! d'origine. Jamais un autre clair, jamais de panique.
//!
//! Sous cfg(fuzzing), Argon2id utilise des paramètres minuscules (voir format.rs).
#![no_main]

use janus::format::{self, Destinataires, Ouverture};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|donnees: &[u8]| {
    let Some((&entete, reste)) = donnees.split_first() else { return };
    // Octet d'en-tête : longueur du leurre (0 à 255 octets répétés), et visage caché ou non.
    let longueur = usize::from(entete) * 37;
    let leurre: Vec<u8> = (0..longueur).map(|k| (k * 31 + 7) as u8).collect();
    let mut fichier = if entete & 1 == 1 {
        format::chiffrer_deux_visages(
            &leurre,
            Destinataires::MotDePasse(b"leurre"),
            b"secret",
            Destinataires::MotDePasse(b"cache"),
        )
    } else {
        format::chiffrer(&leurre, Destinataires::MotDePasse(b"leurre"))
    }
    .expect("chiffrement");

    // Mutations : suites de 4 octets (position sur 3 octets, octet à XOR).
    // Un octet XOR nul tronque le fichier à cette position.
    for m in reste.chunks_exact(4) {
        let pos = (usize::from(m[0]) << 16 | usize::from(m[1]) << 8 | usize::from(m[2])) % fichier.len();
        if m[3] == 0 {
            fichier.truncate(pos);
            if fichier.is_empty() {
                break;
            }
        } else {
            fichier[pos] ^= m[3];
        }
    }

    if let Ok(clair) = format::dechiffrer(&fichier, Ouverture::MotDePasse(b"leurre")) {
        assert_eq!(&clair[..], &leurre[..], "un fichier modifié a rendu un autre clair");
    }
});
