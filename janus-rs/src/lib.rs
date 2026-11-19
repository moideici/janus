//! Janus v1 à deux visages — prototype de recherche de docs/02-spec-v0.md,
//! modifiée par docs/03-deux-visages.md.
//!
//! NE PAS UTILISER POUR DE VRAIS SECRETS : le format n'est pas figé et le code
//! n'a fait l'objet d'aucun audit externe.

pub mod alea;
pub mod cles;
pub mod elligator;
pub mod format;
pub mod inspect;
pub mod kemeleon;
pub mod xwing;

#[cfg(test)]
mod vecteurs;
