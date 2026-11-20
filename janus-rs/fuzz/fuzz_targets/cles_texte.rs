//! Décodage des clés en texte (Bech32m, spec § 3.3).
//! Propriétés : jamais de panique ; tout texte accepté se réencode à l'identique
//! (à la casse près) ; aucun texte n'est à la fois une clé publique et une identité.
#![no_main]

use janus::cles;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|octets: &[u8]| {
    let Ok(texte) = std::str::from_utf8(octets) else { return };
    let publique = cles::publique_depuis_texte(texte);
    let identite = cles::secrete_depuis_texte(texte);
    assert!(publique.is_none() || identite.is_none());
    if let Some(pk) = publique {
        assert!(cles::publique_vers_texte(&pk).eq_ignore_ascii_case(texte.trim()));
    }
    if let Some(id) = identite {
        // Les identités de l'aperçu (JANUS-SECRET-V0-) se réencodent en Bech32m.
        if !texte.trim().starts_with("JANUS-SECRET-V0-") {
            assert!(cles::secrete_vers_texte(&id).eq_ignore_ascii_case(texte.trim()));
        }
    }
    let _ = cles::decoder_bech32m(texte, usize::MAX);
});
