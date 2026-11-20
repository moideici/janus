//! Janus v1 — implémentation de référence de spec/janus-v1.md (conception et
//! preuves en français dans docs/).
//!
//! NE PAS UTILISER POUR DE VRAIS SECRETS : le format est candidat au gel mais pas
//! gelé, et le code n'a fait l'objet d'aucun audit externe.
//!
//! Aucun `unsafe` hors du module `memoire`, qui se limite aux appels système de
//! verrouillage de la mémoire.

#![deny(unsafe_code)]

pub mod alea;
pub mod cles;
pub mod elligator;
pub mod format;
pub mod inspect;
pub mod kemeleon;
pub mod memoire;
pub mod xwing;

#[cfg(test)]
mod vecteurs;
