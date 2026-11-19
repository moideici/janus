//! Encodage texte des clés (spec, question Q7, tranchée le 19 novembre 2026).
//!
//! **Bech32m** (BIP 350), comme age :
//! - clé publique : préfixe `janus`, en minuscules (`janus1…`), 1216 octets ;
//! - identité (graine de 32 octets) : préfixe `JANUS-SECRET-KEY-`, en majuscules.
//!
//! Pourquoi Bech32m plutôt que base64 avec somme de contrôle :
//! - l'identité tient en 76 caractères, sous la limite de 90 de Bech32 : sa somme
//!   de contrôle **garantit** la détection de 4 fautes de frappe au plus, ce qui
//!   compte pour une sauvegarde sur papier ;
//! - insensible à la casse, sans caractères ambigus (ni `1`, `b`, `i`, `o` dans les
//!   données), sélectionnable d'un double clic, et compact en QR code (mode
//!   alphanumérique, en majuscules) ;
//! - la clé publique dépasse 90 caractères : comme age, on lève la limite. La
//!   détection n'est plus garantie, mais une erreur aléatoire passe avec une
//!   probabilité de 2⁻³⁰ seulement.
//!
//! Le préfixe distingue les types : une clé publique n'est jamais lue comme une
//! identité, et inversement. Une future version des clés changera de préfixe
//! (`janus2`, …), sans champ de version (J-09).
//!
//! **Temps constant.** L'identité est secrète : la conversion entre symboles et
//! valeurs balaie tout l'alphabet au lieu d'indexer une table, et le calcul de la
//! somme de contrôle ne contient aucun branchement dépendant des données.

use crate::xwing::{self, Identite, TAILLE_PK};
use subtle::{ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroizing;

pub const PREFIXE_PUBLIQUE: &str = "janus";
pub const PREFIXE_SECRETE: &str = "JANUS-SECRET-KEY-";

/// Préfixes de l'aperçu v0.1.0-alpha (base64url avec somme SHA-256), lus
/// seulement pour les identités, le temps de migrer. Retirés avant la v1.0.
const ANCIEN_PREFIXE_SECRETE: &str = "JANUS-SECRET-V0-";

const ALPHABET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const CONSTANTE_BECH32M: u32 = 0x2bc8_30a3;
const LONGUEUR_MAX_STANDARD: usize = 90;

fn polymod(valeurs: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];
    let mut chk: u32 = 1;
    for &v in valeurs {
        let b = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(v);
        for (i, g) in GEN.iter().enumerate() {
            // Sans branchement : masque à 0 ou à 0xFFFF_FFFF selon le bit i de b.
            chk ^= g & ((b >> i) & 1).wrapping_neg();
        }
    }
    chk
}

fn etendre_prefixe(prefixe: &[u8]) -> Vec<u8> {
    let mut v: Vec<u8> = prefixe.iter().map(|c| c >> 5).collect();
    v.push(0);
    v.extend(prefixe.iter().map(|c| c & 31));
    v
}

/// Symbole Bech32 de la valeur `v` (< 32), en balayant tout l'alphabet.
fn symbole(v: u8) -> u8 {
    let mut s = 0u8;
    for (i, &c) in ALPHABET.iter().enumerate() {
        s.conditional_assign(&c, (i as u8).ct_eq(&v));
    }
    s
}

/// Valeur du symbole `c` (déjà en minuscules), ou `None` s'il n'est pas dans
/// l'alphabet. Balaye tout l'alphabet ; seul le refus final dépend des données.
fn valeur(c: u8) -> Option<u8> {
    let (mut v, mut trouve) = (0u8, subtle::Choice::from(0));
    for (i, &a) in ALPHABET.iter().enumerate() {
        let egal = a.ct_eq(&c);
        v.conditional_assign(&(i as u8), egal);
        trouve |= egal;
    }
    bool::from(trouve).then_some(v)
}

/// Regroupe des octets en symboles de 5 bits (avec bourrage final à zéro).
fn octets_vers_5bits(octets: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut sortie = Zeroizing::new(Vec::with_capacity(octets.len() * 8 / 5 + 1));
    let (mut acc, mut bits) = (0u32, 0u32);
    for &o in octets {
        acc = ((acc << 8) | u32::from(o)) & 0xfff;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            sortie.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        sortie.push(((acc << (5 - bits)) & 31) as u8);
    }
    sortie
}

/// Inverse de `octets_vers_5bits` : refuse un bourrage de plus de 4 bits ou non nul.
fn cinq_bits_vers_octets(symboles: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let mut sortie = Zeroizing::new(Vec::with_capacity(symboles.len() * 5 / 8));
    let (mut acc, mut bits) = (0u32, 0u32);
    for &s in symboles {
        acc = ((acc << 5) | u32::from(s)) & 0xfff;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            sortie.push(((acc >> bits) & 0xff) as u8);
        }
    }
    (bits < 5 && (acc << (8 - bits)) & 0xff == 0).then_some(sortie)
}

/// Encode en Bech32m. `prefixe` est en minuscules ou en majuscules ; la chaîne
/// entière suit sa casse.
pub fn encoder_bech32m(prefixe: &str, donnees: &[u8]) -> Zeroizing<String> {
    let majuscules = prefixe.bytes().any(|c| c.is_ascii_uppercase());
    let p = prefixe.to_ascii_lowercase();
    let symboles = octets_vers_5bits(donnees);
    let mut calcul = Zeroizing::new(etendre_prefixe(p.as_bytes()));
    calcul.extend_from_slice(&symboles);
    calcul.extend_from_slice(&[0; 6]);
    let somme = polymod(&calcul) ^ CONSTANTE_BECH32M;

    let mut s = Zeroizing::new(String::with_capacity(p.len() + 1 + symboles.len() + 6));
    s.push_str(&p);
    s.push('1');
    let controle = (0..6).map(|i| ((somme >> (5 * (5 - i))) & 31) as u8);
    for v in symboles.iter().copied().chain(controle) {
        s.push(char::from(symbole(v)));
    }
    if majuscules {
        s.make_ascii_uppercase();
    }
    s
}

/// Décode une chaîne Bech32m. Rend le préfixe (en minuscules) et les données.
/// `limite` : longueur maximale de la chaîne (90 dans le standard).
pub fn decoder_bech32m(texte: &str, limite: usize) -> Option<(String, Zeroizing<Vec<u8>>)> {
    let o = texte.as_bytes();
    if o.len() > limite || o.iter().any(|&c| !(33..=126).contains(&c)) {
        return None;
    }
    let (min, maj) = (o.iter().any(u8::is_ascii_lowercase), o.iter().any(u8::is_ascii_uppercase));
    if min && maj {
        return None;
    }
    let bas = Zeroizing::new(texte.to_ascii_lowercase());
    let sep = bas.rfind('1')?;
    let (prefixe, reste) = (&bas[..sep], &bas.as_bytes()[sep + 1..]);
    if prefixe.is_empty() || reste.len() < 6 {
        return None;
    }
    let mut symboles = Zeroizing::new(Vec::with_capacity(reste.len()));
    for &c in reste {
        symboles.push(valeur(c)?);
    }
    let mut calcul = Zeroizing::new(etendre_prefixe(prefixe.as_bytes()));
    calcul.extend_from_slice(&symboles);
    if polymod(&calcul) != CONSTANTE_BECH32M {
        return None;
    }
    let donnees = cinq_bits_vers_octets(&symboles[..symboles.len() - 6])?;
    Some((prefixe.to_owned(), donnees))
}

pub fn publique_vers_texte(pk: &[u8; TAILLE_PK]) -> String {
    encoder_bech32m(PREFIXE_PUBLIQUE, pk).to_string()
}

pub fn publique_depuis_texte(texte: &str) -> Option<[u8; TAILLE_PK]> {
    let (prefixe, d) = decoder_bech32m(texte.trim(), usize::MAX)?;
    if prefixe != PREFIXE_PUBLIQUE {
        return None;
    }
    let pk: [u8; TAILLE_PK] = d[..].try_into().ok()?;
    xwing::cle_publique_valide(&pk).then_some(pk)
}

pub fn secrete_vers_texte(id: &Identite) -> Zeroizing<String> {
    encoder_bech32m(PREFIXE_SECRETE, id.graine())
}

/// Vrai si la ligne ressemble à une identité (actuelle ou de l'aperçu v0.1.0-alpha).
pub fn est_ligne_secrete(ligne: &str) -> bool {
    let l = ligne.trim();
    l.to_ascii_uppercase().starts_with(&format!("{PREFIXE_SECRETE}1")) || l.starts_with(ANCIEN_PREFIXE_SECRETE)
}

pub fn secrete_depuis_texte(texte: &str) -> Option<Identite> {
    let texte = texte.trim();
    if texte.starts_with(ANCIEN_PREFIXE_SECRETE) {
        return ancienne_secrete(texte);
    }
    let (prefixe, d) = decoder_bech32m(texte, LONGUEUR_MAX_STANDARD)?;
    if prefixe != PREFIXE_SECRETE.to_ascii_lowercase() {
        return None;
    }
    let graine: Zeroizing<[u8; 32]> = Zeroizing::new(d[..].try_into().ok()?);
    Some(Identite::depuis_graine(&graine))
}

/// Lecture des identités de l'aperçu v0.1.0-alpha : base64url(graine ‖ SHA-256(préfixe ‖ graine)[..4]).
/// La graine, donc la paire de clés, est la même : seul le texte change.
fn ancienne_secrete(texte: &str) -> Option<Identite> {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use sha2::{Digest, Sha256};
    let corps = texte.strip_prefix(ANCIEN_PREFIXE_SECRETE)?;
    let tout = Zeroizing::new(URL_SAFE_NO_PAD.decode(corps).ok()?);
    if tout.len() != 36 {
        return None;
    }
    let (graine, s) = tout.split_at(32);
    let h = Sha256::new().chain_update(ANCIEN_PREFIXE_SECRETE).chain_update(graine).finalize();
    if !bool::from(h[..4].ct_eq(s)) {
        return None;
    }
    let graine: Zeroizing<[u8; 32]> = Zeroizing::new(graine.try_into().ok()?);
    Some(Identite::depuis_graine(&graine))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Chaînes valides de BIP 350 (Bech32m).
    #[test]
    fn vecteurs_bip350() {
        for t in [
            "A1LQFN3A",
            "a1lqfn3a",
            "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
            "?1v759aa",
        ] {
            assert!(decoder_bech32m(t, 90).is_some(), "{t} devrait être valide");
        }
        // Somme de contrôle Bech32 (ancienne constante) et casse mélangée : refusés.
        assert!(decoder_bech32m("a12uel5l", 90).is_none());
        assert!(decoder_bech32m("A1lqfn3a", 90).is_none());
        assert!(decoder_bech32m("a1lqfn3b", 90).is_none());
    }

    #[test]
    fn aller_retour_quelles_que_soient_les_longueurs() {
        for n in 0..70usize {
            let d: Vec<u8> = (0..n).map(|k| (k * 37 + 11) as u8).collect();
            for p in ["janus", "JANUS-SECRET-KEY-"] {
                let t = encoder_bech32m(p, &d);
                let (pp, dd) = decoder_bech32m(&t, usize::MAX).unwrap();
                assert_eq!((pp.as_str(), &dd[..]), (p.to_ascii_lowercase().as_str(), &d[..]));
            }
        }
    }

    #[test]
    fn aller_retour_et_fautes_de_frappe() {
        let id = Identite::generer();
        let pub_txt = publique_vers_texte(id.cle_publique());
        assert!(pub_txt.starts_with("janus1"));
        assert_eq!(&publique_depuis_texte(&pub_txt).unwrap(), id.cle_publique());
        let sec_txt = secrete_vers_texte(&id);
        assert!(sec_txt.starts_with("JANUS-SECRET-KEY-1"));
        assert_eq!(sec_txt.len(), 76);
        assert_eq!(secrete_depuis_texte(&sec_txt).unwrap().cle_publique(), id.cle_publique());
        // Insensible à la casse, tant qu'elle n'est pas mélangée.
        assert!(secrete_depuis_texte(&sec_txt.to_ascii_lowercase()).is_some());

        // Toute faute de frappe isolée dans l'identité est détectée.
        let alphabet = "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L";
        let debut = PREFIXE_SECRETE.len() + 1;
        for i in debut..sec_txt.len() {
            for c in alphabet.chars() {
                let mut t = sec_txt.to_string().into_bytes();
                if t[i] == c as u8 {
                    continue;
                }
                t[i] = c as u8;
                assert!(secrete_depuis_texte(std::str::from_utf8(&t).unwrap()).is_none());
            }
        }
        // Deux symboles échangés : détecté aussi.
        let mut t = sec_txt.to_string().into_bytes();
        let i = (debut..t.len() - 1).find(|&i| t[i] != t[i + 1]).unwrap();
        t.swap(i, i + 1);
        assert!(secrete_depuis_texte(std::str::from_utf8(&t).unwrap()).is_none());

        let mut abime = pub_txt.clone().into_bytes();
        let i = abime.len() / 2;
        abime[i] = if abime[i] == b'q' { b'p' } else { b'q' };
        assert!(publique_depuis_texte(std::str::from_utf8(&abime).unwrap()).is_none());

        // Pas de confusion entre les types de clé.
        assert!(publique_depuis_texte(&sec_txt).is_none(), "identité lue comme clé publique");
        assert!(secrete_depuis_texte(&pub_txt).is_none(), "clé publique lue comme identité");
    }

    #[test]
    fn identite_de_l_apercu_encore_lisible() {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use sha2::{Digest, Sha256};
        let id = Identite::depuis_graine(&[7; 32]);
        let mut tout = vec![7u8; 32];
        let h = Sha256::new().chain_update(ANCIEN_PREFIXE_SECRETE).chain_update([7u8; 32]).finalize();
        tout.extend_from_slice(&h[..4]);
        let ancien = format!("{ANCIEN_PREFIXE_SECRETE}{}", URL_SAFE_NO_PAD.encode(&tout));
        assert!(est_ligne_secrete(&ancien));
        assert_eq!(secrete_depuis_texte(&ancien).unwrap().cle_publique(), id.cle_publique());
        let mut faux = ancien.into_bytes();
        let n = faux.len() - 1;
        faux[n] = if faux[n] == b'A' { b'B' } else { b'A' };
        assert!(secrete_depuis_texte(std::str::from_utf8(&faux).unwrap()).is_none());
    }
}
