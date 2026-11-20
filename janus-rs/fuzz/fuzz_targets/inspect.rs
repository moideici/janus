//! `janus inspect` lit des fichiers quelconques, venus de n'importe qui : c'est
//! l'analyseur le plus exposé. Propriété : jamais de panique, et le rapport s'affiche.
#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|octets: &[u8]| {
    if let Ok(rapport) = janus::inspect::inspecter(&mut Cursor::new(octets)) {
        let _ = rapport.to_string();
    }
});
