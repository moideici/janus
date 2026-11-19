//! Banc d'essai du prototype : cargo run --release --example banc
use janus::format::{self, Destinataires, Ouverture};
use janus::xwing::{self, Identite};
use std::time::Instant;

fn mesurer<T>(n: u32, mut f: impl FnMut() -> T) -> f64 {
    let t = Instant::now();
    for _ in 0..n {
        std::hint::black_box(f());
    }
    t.elapsed().as_secs_f64() / n as f64
}

fn main() {
    let coeurs = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    println!("Cœurs logiques : {coeurs}\n");
    let alice = Identite::generer();
    let pk = *alice.cle_publique();

    let t = mesurer(200, || xwing::encapsuler_cache(&pk));
    println!("Encapsulation cachée (par destinataire)   : {:7.3} ms", t * 1e3);
    let f = format::chiffrer(b"x", Destinataires::Cles(&[pk])).unwrap();
    let t = mesurer(50, || format::dechiffrer(&f, Ouverture::Identites(std::slice::from_ref(&alice))));
    println!("Ouverture par clé (16 emplacements)       : {:7.3} ms", t * 1e3);
    let fm = format::chiffrer(b"x", Destinataires::MotDePasse(b"mdp")).unwrap();
    let t = mesurer(5, || format::dechiffrer(&fm, Ouverture::MotDePasse(b"mdp")));
    println!("Ouverture par mot de passe (Argon2id)     : {:7.1} ms", t * 1e3);
    let pks: Vec<_> = (0..16).map(|_| *Identite::generer().cle_publique()).collect();
    let t = mesurer(20, || format::chiffrer(b"x", Destinataires::Cles(&pks)));
    println!("Chiffrer pour 16 destinataires            : {:7.3} ms\n", t * 1e3);

    for mio in [1usize, 64, 512] {
        let clair = vec![0x42u8; mio << 20];
        let n = if mio >= 512 { 3 } else { 10 };
        let tc = mesurer(n, || format::chiffrer(&clair, Destinataires::Cles(&[pk])).unwrap());
        let f = format::chiffrer(&clair, Destinataires::Cles(&[pk])).unwrap();
        let td = mesurer(n, || format::dechiffrer(&f, Ouverture::Identites(std::slice::from_ref(&alice))).unwrap());
        println!(
            "{mio:4} Mio : chiffrer {:6.0} Mio/s ({:7.1} ms) | déchiffrer {:6.0} Mio/s ({:7.1} ms)",
            mio as f64 / tc, tc * 1e3, mio as f64 / td, td * 1e3
        );
    }
}
