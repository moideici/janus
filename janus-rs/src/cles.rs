//! Encodage texte des clés — PROVISOIRE (spec Q7).
//!
//! préfixe ‖ base64url( données ‖ somme de contrôle de 4 octets )
//! La somme de contrôle est SHA-256(préfixe ‖ données)[..4] : elle détecte
//! les fautes de frappe et empêche de confondre clé publique et clé secrète.

use crate::xwing::{self, Identite, TAILLE_PK};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const PREFIXE_PUBLIQUE: &str = "janus-pub-v0-";
pub const PREFIXE_SECRETE: &str = "JANUS-SECRET-V0-";

fn somme(prefixe: &str, donnees: &[u8]) -> [u8; 4] {
    let h = Sha256::new().chain_update(prefixe).chain_update(donnees).finalize();
    h[..4].try_into().unwrap()
}

fn encoder(prefixe: &str, donnees: &[u8]) -> String {
    let mut tout = donnees.to_vec();
    tout.extend_from_slice(&somme(prefixe, donnees));
    format!("{prefixe}{}", URL_SAFE_NO_PAD.encode(tout))
}

fn decoder(prefixe: &str, texte: &str, longueur: usize) -> Option<Zeroizing<Vec<u8>>> {
    let corps = texte.trim().strip_prefix(prefixe)?;
    let tout = Zeroizing::new(URL_SAFE_NO_PAD.decode(corps).ok()?);
    if tout.len() != longueur + 4 {
        return None;
    }
    let (donnees, s) = tout.split_at(longueur);
    (somme(prefixe, donnees) == s).then(|| Zeroizing::new(donnees.to_vec()))
}

pub fn publique_vers_texte(pk: &[u8; TAILLE_PK]) -> String {
    encoder(PREFIXE_PUBLIQUE, pk)
}

pub fn publique_depuis_texte(texte: &str) -> Option<[u8; TAILLE_PK]> {
    let d = decoder(PREFIXE_PUBLIQUE, texte, TAILLE_PK)?;
    let pk: [u8; TAILLE_PK] = d[..].try_into().ok()?;
    xwing::cle_publique_valide(&pk).then_some(pk)
}

pub fn secrete_vers_texte(id: &Identite) -> Zeroizing<String> {
    Zeroizing::new(encoder(PREFIXE_SECRETE, id.graine()))
}

pub fn secrete_depuis_texte(texte: &str) -> Option<Identite> {
    let d = decoder(PREFIXE_SECRETE, texte, 32)?;
    let graine: Zeroizing<[u8; 32]> = Zeroizing::new(d[..].try_into().ok()?);
    Some(Identite::depuis_graine(&graine))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aller_retour_et_faute_de_frappe() {
        let id = Identite::generer();
        let pub_txt = publique_vers_texte(id.cle_publique());
        assert_eq!(&publique_depuis_texte(&pub_txt).unwrap(), id.cle_publique());
        let sec_txt = secrete_vers_texte(&id);
        assert_eq!(secrete_depuis_texte(&sec_txt).unwrap().cle_publique(), id.cle_publique());

        let mut abime = pub_txt.into_bytes();
        let i = abime.len() / 2;
        abime[i] = if abime[i] == b'A' { b'B' } else { b'A' };
        assert!(publique_depuis_texte(std::str::from_utf8(&abime).unwrap()).is_none());
        assert!(publique_depuis_texte(&sec_txt).is_none(), "confusion des types de clé");
    }
}
