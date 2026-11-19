//! Fuzzing par mutations (Rust stable, sans cargo-fuzz).
//!
//! On part de fichiers Janus valides, à un et à deux visages, on leur applique des
//! mutations aléatoires (bits, octets, insertions, suppressions, troncatures,
//! greffes…) et on exige :
//! - aucune panique, aucun débordement ;
//! - toujours la même erreur « impossible de déchiffrer » ;
//! - jamais un autre clair que l'original. Une mutation n'est acceptée que si elle
//!   garde la taille et ne touche QUE ce qui appartient à l'autre visage : son
//!   étiquette (T_0 ou T_1) et la réserve (03-deux-visages.md, § 8).
//!
//! Nombre d'itérations : variable JANUS_FUZZ_ITER (2000 par défaut).
//!   JANUS_FUZZ_ITER=100000 cargo test --release --test fuzz -- --nocapture

use janus::alea;
use janus::format::{self, Destinataires, Ouverture, H, TB};
use janus::xwing::Identite;
use std::panic::{catch_unwind, AssertUnwindSafe};

fn hasard(borne: usize) -> usize {
    alea::uniforme_u64_jusqua(borne.saturating_sub(1) as u64) as usize
}

fn octets_aleatoires(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    alea::remplir(&mut v);
    v
}

/// Applique une mutation aléatoire et la décrit.
fn muter(f: &[u8], autre: &[u8]) -> (Vec<u8>, String) {
    let mut g = f.to_vec();
    let n = g.len();
    let desc = match hasard(10) {
        0 => {
            let p = hasard(n);
            g[p] ^= 1 << hasard(8);
            format!("bit inversé à {p}")
        }
        1 => {
            // Zone à fort enjeu : l'en-tête.
            let p = hasard(H);
            g[p] = alea::octets::<1>()[0];
            format!("octet d'en-tête {p} remplacé")
        }
        2 => {
            let p = hasard(n);
            let k = 1 + hasard(64);
            for x in g.iter_mut().skip(p).take(k) {
                *x ^= 0xff;
            }
            format!("{k} octets inversés à {p}")
        }
        3 => {
            let p = hasard(n + 1);
            let k = 1 + hasard(100);
            g.splice(p..p, octets_aleatoires(k));
            format!("{k} octets insérés à {p}")
        }
        4 => {
            let p = hasard(n);
            let k = (1 + hasard(5000)).min(n - p);
            g.drain(p..p + k);
            format!("{k} octets supprimés à {p}")
        }
        5 => {
            let p = hasard(n);
            g.truncate(p);
            format!("tronqué à {p}")
        }
        6 => {
            let k = 1 + hasard(70_000);
            g.extend(octets_aleatoires(k));
            format!("{k} octets ajoutés")
        }
        7 => {
            let k = 1 + hasard(n / 4);
            let (a, b) = (hasard(n - k), hasard(n - k));
            let morceau = g[a..a + k].to_vec();
            g[b..b + k].copy_from_slice(&morceau);
            format!("{k} octets recopiés de {a} vers {b}")
        }
        8 => {
            // Greffe d'une zone d'un autre fichier valide.
            let k = 1 + hasard(n.min(autre.len()) / 2);
            let p = hasard(n.min(autre.len()) - k);
            g[p..p + k].copy_from_slice(&autre[p..p + k]);
            format!("{k} octets greffés depuis un autre fichier à {p}")
        }
        _ => {
            let p = hasard(n);
            g[p] = g[p].wrapping_add(1);
            format!("octet {p} incrémenté")
        }
    };
    (g, desc)
}

/// Vérifie le résultat d'une ouverture de fichier muté `g` (original `f`, clair `clair`,
/// visage de `l` octets au début du corps).
fn verifier(r: std::thread::Result<Result<zeroize::Zeroizing<Vec<u8>>, format::ImpossibleDeDechiffrer>>,
            f: &[u8], g: &[u8], clair: &[u8], quoi: &str) -> bool {
    match r {
        Err(_) => panic!("PANIQUE : {quoi}"),
        Ok(Err(_)) => false,
        Ok(Ok(c)) => {
            assert!(&c[..] == clair, "AUTRE CLAIR rendu : {quoi}");
            assert_eq!(g.len(), f.len(), "taille changée mais acceptée : {quoi}");
            let fin_visage = H + format::taille_chiffree(clair.len() as u64) as usize;
            // Seuls sont hors du visage ouvert : l'étiquette de l'autre visage (T_0 ou
            // T_1, jamais les deux) et la réserve.
            let diff: Vec<usize> = (0..f.len()).filter(|&p| f[p] != g[p]).collect();
            let interdit = diff.iter().find(|&&p| (64..fin_visage).contains(&p));
            assert!(interdit.is_none(), "octet {interdit:?} de l'en-tête ou du visage modifié mais accepté : {quoi}");
            let t0 = diff.iter().any(|&p| p < 32);
            let t1 = diff.iter().any(|&p| (32..64).contains(&p));
            assert!(!(t0 && t1), "les deux étiquettes modifiées mais accepté : {quoi}");
            true
        }
    }
}

#[test]
fn mutations_jamais_acceptees() {
    let iterations: usize = std::env::var("JANUS_FUZZ_ITER").ok().and_then(|s| s.parse().ok()).unwrap_or(2000);
    let alice = [Identite::generer()];
    let pk = *alice[0].cle_publique();
    let autre_dest = *Identite::generer().cle_publique();
    let secret_dest = *Identite::generer().cle_publique();
    let mut sources: Vec<(Vec<u8>, Vec<u8>)> = [0usize, 17, 5000, TB, 3 * TB + 99]
        .iter()
        .map(|&n| {
            let c = octets_aleatoires(n);
            (format::chiffrer(&c, Destinataires::Cles(&[pk, autre_dest])).unwrap(), c)
        })
        .collect();
    // Deux visages : Alice ouvre le leurre, le secret occupe une partie de la réserve.
    let leurre = octets_aleatoires(2 * TB);
    let f2 = format::chiffrer_deux_visages(
        &leurre,
        Destinataires::Cles(&[pk]),
        &octets_aleatoires(40_000),
        Destinataires::Cles(&[secret_dest]),
    )
    .unwrap();
    sources.push((f2, leurre));
    let etranger = format::chiffrer(b"autre", Destinataires::Cles(&[pk])).unwrap();

    let (mut identiques, mut dans_la_reserve) = (0, 0);
    for it in 0..iterations {
        let (f, clair) = &sources[it % sources.len()];
        let (g, desc) = muter(f, &etranger);
        if g == *f {
            identiques += 1;
            continue;
        }
        let r = catch_unwind(AssertUnwindSafe(|| format::dechiffrer(&g, Ouverture::Identites(&alice))));
        if verifier(r, f, &g, clair, &format!("itération {it} : {desc}")) {
            dans_la_reserve += 1;
        }
    }
    eprintln!(
        "{iterations} mutations testées ({identiques} sans effet ignorées) : aucune panique, jamais un autre clair ; {dans_la_reserve} acceptées car limitées à la réserve"
    );
}

#[test]
fn mutations_fichier_a_mot_de_passe() {
    // Argon2id coûte ~90 ms par essai : peu d'itérations, mais toutes les zones.
    let clair = octets_aleatoires(3000);
    let f = format::chiffrer(&clair, Destinataires::MotDePasse(b"mdp")).unwrap();
    for it in 0..40 {
        let (g, desc) = muter(&f, &f);
        if g == f {
            continue;
        }
        let r = catch_unwind(AssertUnwindSafe(|| format::dechiffrer(&g, Ouverture::MotDePasse(b"mdp"))));
        verifier(r, &f, &g, &clair, &format!("itération {it} : {desc}"));
    }
}

#[test]
fn entrees_arbitraires() {
    let alice = [Identite::generer()];
    for _ in 0..300 {
        let n = match hasard(4) {
            0 => hasard(H + 20),
            1 => H + hasard(100),
            _ => hasard(300_000),
        };
        let g = octets_aleatoires(n);
        let r = catch_unwind(AssertUnwindSafe(|| format::dechiffrer(&g, Ouverture::Identites(&alice))));
        assert!(matches!(r, Ok(Err(_))), "entrée aléatoire de {n} octets");
    }
    for n in [0usize, 1, 31, 32, H - 1, H, H + 16, H + 17] {
        let r = catch_unwind(AssertUnwindSafe(|| format::dechiffrer(&vec![0u8; n], Ouverture::Identites(&alice))));
        assert!(matches!(r, Ok(Err(_))), "{n} zéros");
    }
}
