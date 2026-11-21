//! Q4 : fuite exacte de la taille d'un fichier Janus sur la taille du clair.
//!
//! Un observateur voit la taille F du fichier. Pour un leurre de L octets, Janus
//! tire F uniformément dans le seau PADMÉ de Ref(L) (spec, § 6.2). On mesure ce que
//! F apprend sur L, quand L suit une loi uniforme sur un intervalle :
//! - l'information mutuelle I(L ; F), en bits (fuite moyenne) ;
//! - la fuite maximale (« maximal leakage », Issa, Wagner, Kamath 2016) :
//!   log2 Σ_F max_L P(F | L), en bits. C'est la borne pertinente contre un adversaire
//!   qui cherche à deviner N'IMPORTE QUELLE fonction de L, et elle ne dépend pas de
//!   la loi de L (seulement de son support).
//!   et on compare à l'ancienne règle (F uniforme dans [Ref, PADMÉ(Ref)]), qui fuyait
//!   davantage, à PADMÉ seul (F = PADMÉ(Ref)) et à l'absence de bourrage (F = Ref).
//!
//! Calcul EXACT, sans échantillonnage, en un seul passage : Ref et PADMÉ∘Ref sont
//! croissantes en L, donc les L compatibles avec un F donné forment un intervalle
//! [a(F), b(F)] dont les deux bornes avancent avec F. La densité P(F) est constante
//! entre deux « événements » (un intervalle qui commence ou qui finit), et le maximum
//! de P(F | L) sur la fenêtre se tient avec une file monotone.
//!
//!   cargo run --release --example fuite_bourrage

use janus::format::{bornes_taille, padme, taille_reference};
use std::collections::VecDeque;

struct Resultat {
    info_mutuelle: f64,
    fuite_max: f64,
}

/// Fuite de F = uniforme[lo(L), hi(L)] pour L uniforme dans [l0, l1].
/// `bornes` doit être croissante en L sur ses deux composantes.
fn fuite(l0: u64, l1: u64, bornes: impl Fn(u64) -> (u64, u64)) -> Resultat {
    let n = (l1 - l0 + 1) as f64;
    // H(F | L) = moyenne de log2(largeur).
    let mut h_cond = 0.0;
    for l in l0..=l1 {
        let (lo, hi) = bornes(l);
        h_cond += ((hi - lo + 1) as f64).log2();
    }
    h_cond /= n;

    // Balayage des F : `debut` = prochain L dont l'intervalle n'a pas commencé,
    // `fin` = premier L dont l'intervalle n'est pas fini.
    let (mut debut, mut fin) = (l0, l0);
    let mut densite = 0.0f64; // Σ des 1/largeur des intervalles actifs (× 1/n plus tard)
    let mut fenetre: VecDeque<(u64, f64)> = VecDeque::new(); // (L, 1/largeur), décroissante
    let (mut h_f, mut somme_max) = (0.0f64, 0.0f64);
    let mut f = bornes(l0).0;
    loop {
        // Ouvre tous les intervalles qui commencent en f.
        while debut <= l1 && bornes(debut).0 == f {
            let (lo, hi) = bornes(debut);
            let p = 1.0 / (hi - lo + 1) as f64;
            densite += p;
            while fenetre.back().is_some_and(|&(_, q)| q <= p) {
                fenetre.pop_back();
            }
            fenetre.push_back((debut, p));
            debut += 1;
        }
        // Longueur du segment où rien ne change : jusqu'au prochain début ou à la prochaine fin.
        let prochain_debut = if debut <= l1 { bornes(debut).0 } else { u64::MAX };
        let prochaine_fin = if fin < debut { bornes(fin).1 + 1 } else { u64::MAX };
        let g = prochain_debut.min(prochaine_fin);
        if g == u64::MAX {
            break;
        }
        let longueur = (g - f) as f64;
        if densite > 0.0 {
            let p_f = densite / n;
            h_f -= longueur * p_f * p_f.log2();
            somme_max += longueur * fenetre.front().map_or(0.0, |&(_, q)| q);
        }
        f = g;
        // Ferme tous les intervalles qui finissent juste avant f.
        while fin < debut && bornes(fin).1 + 1 == f {
            let (lo, hi) = bornes(fin);
            densite -= 1.0 / (hi - lo + 1) as f64;
            if fenetre.front().is_some_and(|&(l, _)| l == fin) {
                fenetre.pop_front();
            }
            fin += 1;
        }
        if densite.abs() < 1e-300 {
            densite = 0.0;
        }
    }
    Resultat { info_mutuelle: h_f - h_cond, fuite_max: somme_max.log2() }
}

/// Règle de la v1 avant l'analyse (novembre 2026) : F uniforme dans [Ref, PADMÉ(Ref)].
fn bornes_ancienne_regle(l: u64) -> (u64, u64) {
    let r = taille_reference(l);
    (r, padme(r))
}

/// Surcoût moyen et maximal de F par rapport à Ref, en %, sur un échantillon de L.
fn surcout(l0: u64, l1: u64, bornes: impl Fn(u64) -> (u64, u64)) -> (f64, f64) {
    let pas = ((l1 - l0) / 200_000).max(1);
    let (mut somme, mut max, mut n) = (0.0f64, 0.0f64, 0.0f64);
    let mut l = l0;
    while l <= l1 {
        let r = taille_reference(l) as f64;
        let (lo, hi) = bornes(l);
        somme += ((lo + hi) as f64 / 2.0 - r) / r;
        max = max.max((hi as f64 - r) / r);
        n += 1.0;
        l += pas;
    }
    (100.0 * somme / n, 100.0 * max)
}

fn main() {
    println!("Fuite de la taille du fichier sur la taille L du leurre (bits).");
    println!("I = information mutuelle ; max = fuite maximale (Issa et al.) ; log2 N = tout L.\n");
    println!(
        "{:<20} {:>5} | {:>13} | {:>13} | {:>13} | {:>16} | {:>16}",
        "L uniforme dans", "log2N", "ancienne (I/max)", "PADMÉ (I/max)", "v1 seau (I/max)", "surcoût ancienne", "surcoût seau"
    );
    for (l0, l1, nom) in [
        (0u64, (1 << 10) - 1, "[0, 1 Kio)"),
        (0, (1 << 16) - 1, "[0, 64 Kio)"),
        (1 << 16, (1 << 20) - 1, "[64 Kio, 1 Mio)"),
        (1 << 20, (1 << 24) - 1, "[1 Mio, 16 Mio)"),
        (1 << 24, (1 << 26) - 1, "[16 Mio, 64 Mio)"),
        (1 << 29, (1 << 30) - 1, "[512 Mio, 1 Gio)"),
        (0, (1 << 30) - 1, "[0, 1 Gio)"),
    ] {
        let janus = fuite(l0, l1, bornes_ancienne_regle);
        let pur = fuite(l0, l1, |l| {
            let f = padme(taille_reference(l));
            (f, f)
        });
        let seau = fuite(l0, l1, bornes_taille);
        let n = ((l1 - l0 + 1) as f64).log2();
        let (sj, mj) = surcout(l0, l1, bornes_ancienne_regle);
        let (ss, ms) = surcout(l0, l1, bornes_taille);
        println!(
            "{:<20} {:>5.1} | {:>5.2} / {:>5.2} | {:>5.2} / {:>5.2} | {:>5.2} / {:>5.2} | {:>4.2} % ({:>4.2}) | {:>4.2} % ({:>4.2})",
            nom, n, janus.info_mutuelle, janus.fuite_max, pur.info_mutuelle, pur.fuite_max,
            seau.info_mutuelle, seau.fuite_max, sj, mj, ss, ms
        );
    }
}
