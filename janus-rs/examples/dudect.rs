//! Test de temps constant façon dudect (Reparaz, Balasch, Verbauwhede, 2017).
//!
//! Principe : on mesure une fonction sur deux classes d'entrées (classe A fixe,
//! classe B aléatoire), tirées dans un ordre aléatoire, puis on compare les deux
//! distributions de durées par un test t de Welch. Si |t| dépasse 4,5, les durées
//! dépendent des données : il y a une fuite. Sous ce seuil, aucune fuite n'est
//! détectée avec ce nombre de mesures (ce n'est pas une preuve d'absence).
//!
//! Témoin positif : un décodeur Kemeleon écrit avec num-bigint (temps variable)
//! doit être détecté, sinon le test n'a aucune valeur.
//!
//! Lancer : cargo run --release --example dudect

use janus::{alea, kemeleon, xwing};
use num_bigint::BigUint;
use std::hint::black_box;
use std::time::Instant;

const SEUIL: f64 = 4.5;

/// Décodeur de référence à temps variable (l'ancienne implémentation).
fn decoder_bigint(enc: &[u8]) -> Vec<u32> {
    let qn = BigUint::from(kemeleon::Q).pow(256);
    let mut sortie = Vec::with_capacity(1024);
    for v in enc.chunks(384) {
        let mut r = BigUint::from_bytes_be(v) % &qn;
        for _ in 0..256 {
            sortie.push((&r % kemeleon::Q).iter_u32_digits().next().unwrap_or(0));
            r /= kemeleon::Q;
        }
    }
    sortie
}

fn welch(a: &[f64], b: &[f64]) -> f64 {
    let moy = |x: &[f64]| x.iter().sum::<f64>() / x.len() as f64;
    let var = |x: &[f64], m: f64| x.iter().map(|v| (v - m).powi(2)).sum::<f64>() / (x.len() - 1) as f64;
    let (ma, mb) = (moy(a), moy(b));
    (ma - mb) / (var(a, ma) / a.len() as f64 + var(b, mb) / b.len() as f64).sqrt()
}

/// Mesure `n` fois ; `preparer(classe)` fabrique l'entrée hors chronométrage.
/// Renvoie le |t| maximal parmi plusieurs seuils de rognage (comme dudect),
/// qui écartent les mesures perturbées par le système.
fn tester<E>(nom: &str, n: usize, preparer: impl Fn(bool) -> E, mesurer: impl Fn(&E)) -> f64 {
    let mut a = Vec::with_capacity(n);
    let mut b = Vec::with_capacity(n);
    // Toutes les entrées sont préparées AVANT les mesures : préparer une entrée
    // juste avant de la mesurer perturbe les caches différemment selon la classe
    // (tirage aléatoire, multiplication de base…) et crée de fausses alertes.
    let entrees: Vec<(bool, E)> = (0..n)
        .map(|_| {
            let classe_b = alea::octets::<1>()[0] & 1 == 1;
            (classe_b, preparer(classe_b))
        })
        .collect();
    for (_, e) in entrees.iter().take(n / 10) {
        mesurer(e); // échauffement
    }
    for (classe_b, e) in &entrees {
        let t = Instant::now();
        mesurer(e);
        let d = t.elapsed().as_nanos() as f64;
        if *classe_b { b.push(d) } else { a.push(d) }
    }
    let mut toutes: Vec<f64> = a.iter().chain(&b).copied().collect();
    toutes.sort_by(|x, y| x.partial_cmp(y).unwrap());
    let mut pire = 0f64;
    for p in [0.5, 0.7, 0.9, 0.99, 1.0] {
        let limite = toutes[((toutes.len() - 1) as f64 * p) as usize];
        let fa: Vec<f64> = a.iter().copied().filter(|&x| x <= limite).collect();
        let fb: Vec<f64> = b.iter().copied().filter(|&x| x <= limite).collect();
        if fa.len() > 100 && fb.len() > 100 {
            pire = pire.max(welch(&fa, &fb).abs());
        }
    }
    let mediane = toutes[toutes.len() / 2] / 1000.0;
    let verdict = if pire > SEUIL { "FUITE DÉTECTÉE" } else { "aucune fuite détectée" };
    println!("{nom:<48} médiane {mediane:8.1} µs   |t| max = {pire:6.2}   → {verdict}");
    pire
}

fn main() {
    let n: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(20_000);
    println!("dudect : {n} mesures par fonction, seuil |t| = {SEUIL}\n");

    let fixe_zero = vec![0u8; kemeleon::TAILLE_ENCODEE];
    let aleatoire = |_: bool| {
        let mut x = vec![0u8; kemeleon::TAILLE_ENCODEE];
        alea::remplir(&mut x);
        x
    };
    let classe = |b: bool| if b { aleatoire(true) } else { fixe_zero.clone() };

    let temoin = tester("Témoin : décodage num-bigint (zéros / aléa)", n, classe, |e| {
        black_box(decoder_bigint(black_box(e)));
    });
    tester("Kemeleon.DecodeCtxt temps constant (zéros / aléa)", n, classe, |e| {
        black_box(kemeleon::decoder_chiffre(black_box(e)));
    });

    let ct_fixe = vec![0u8; kemeleon::TAILLE_CT];
    tester("Kemeleon.EncodeCtxt (chiffré nul / aléatoire)", n / 2, |b| {
        if b {
            let mut x = vec![0u8; kemeleon::TAILLE_CT];
            alea::remplir(&mut x);
            x
        } else {
            ct_fixe.clone()
        }
    }, |e| {
        black_box(kemeleon::encoder_chiffre(black_box(e)));
    });

    // Q9 : ouvrir un emplacement valide ou un emplacement aléatoire prend-il le même temps ?
    let id = xwing::Identite::generer();
    let (_, r_ok, k_ok) = xwing::encapsuler_cache(id.cle_publique()).unwrap();
    tester("Décapsulation d'emplacement (valide / aléatoire)", n / 2, |b| {
        if b {
            (alea::octets::<32>(), aleatoire(true))
        } else {
            (r_ok, k_ok.to_vec())
        }
    }, |(r, k)| {
        black_box(id.decapsuler_cache(black_box(r), black_box(k)));
    });

    // Inverse d'Elligator 2 maison (04-preuve, § 7.1) : un point fixe ou un point aléatoire.
    let u_fixe = curve25519_elligator2::EdwardsPoint::mul_base_clamped([7u8; 32]).to_montgomery().to_bytes();
    tester("Inverse d'Elligator 2 (point fixe / aléatoire)", n / 2, |b| {
        if b {
            curve25519_elligator2::EdwardsPoint::mul_base_clamped(alea::octets::<32>()).to_montgomery().to_bytes()
        } else {
            u_fixe
        }
    }, |u| {
        black_box(janus::elligator::representant(black_box(u), 0x41));
    });

    // Deux visages (03-deux-visages.md, § 9) : ouvrir le leurre d'un fichier qui
    // cache un second visage ne doit pas prendre plus ou moins de temps.
    use janus::format::{self, Destinataires, Ouverture};
    let cache = xwing::Identite::generer();
    let leurre = vec![7u8; 20_000];
    let fabriquer = |avec: bool| {
        if avec {
            format::chiffrer_deux_visages(
                &leurre,
                Destinataires::Cles(&[*id.cle_publique()]),
                &[9u8; 30_000],
                Destinataires::Cles(&[*cache.cle_publique()]),
            )
        } else {
            format::chiffrer(&leurre, Destinataires::Cles(&[*id.cle_publique()]))
        }
        .unwrap()
    };
    let reserve: Vec<Vec<u8>> = (0..40).map(|_| fabriquer(false)).collect();
    let avec: Vec<Vec<u8>> = (0..40).map(|_| fabriquer(true)).collect();
    tester("Ouverture du leurre (sans / avec visage caché)", n / 20, |b| {
        let i = alea::uniforme_u32(40) as usize;
        if b { &avec[i] } else { &reserve[i] }
    }, |f| {
        black_box(format::dechiffrer(black_box(f), Ouverture::Identites(std::slice::from_ref(&id))).unwrap());
    });

    // 05-preuve-integrite.md, § 6 et § 7.3 : un fichier piégé dont un emplacement se
    // déballe (étiquettes invalides) ne doit pas s'ouvrir plus lentement qu'un fichier
    // où rien ne se déballe. Les deux échouent ; seul le temps pourrait les distinguer.
    let etiquettes_cassees = |mut f: Vec<u8>| {
        f[0] ^= 1;
        f[32] ^= 1;
        f
    };
    let deballe: Vec<Vec<u8>> =
        (0..40).map(|_| etiquettes_cassees(format::chiffrer(b"x", Destinataires::Cles(&[*id.cle_publique()])).unwrap())).collect();
    let rien: Vec<Vec<u8>> =
        (0..40).map(|_| etiquettes_cassees(format::chiffrer(b"x", Destinataires::Cles(&[*cache.cle_publique()])).unwrap())).collect();
    tester("Ouverture ratée (emplacement déballé / aucun)", n / 10, |b| {
        let i = alea::uniforme_u32(40) as usize;
        if b { &deballe[i] } else { &rien[i] }
    }, |f| {
        black_box(format::dechiffrer(black_box(f), Ouverture::Identites(std::slice::from_ref(&id))).is_err());
    });

    if temoin <= SEUIL {
        println!("\nATTENTION : le témoin n'a pas été détecté, ces mesures ne prouvent rien.");
    }
}
