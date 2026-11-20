//! Tests des deux visages (docs/03-deux-visages.md).
//!
//! - Chaque identifiant ouvre son visage, et seulement le sien.
//! - Règles R3 et R5 : limites, capacité exacte de la réserve.
//! - La taille ne dépend que du leurre.
//! - Vue de l'adversaire contraint : avec la clé du leurre, ce qu'il ne peut pas
//!   ouvrir a la même loi avec ou sans visage caché (test d'homogénéité du χ²).

use janus::alea;
use janus::format::{
    self, bornes_taille, capacite_cachee, taille_chiffree, Destinataires, ErreurChiffrement, ErreurOuverture,
    Ouverture, Visage, H, MAX_CACHES, N_ETIQ, TB,
};
use janus::inspect::p_chi2_255;
use janus::xwing::Identite;
use std::sync::OnceLock;

fn identites() -> &'static [Identite; 4] {
    static I: OnceLock<[Identite; 4]> = OnceLock::new();
    I.get_or_init(|| std::array::from_fn(|_| Identite::generer()))
}
fn pk(i: usize) -> [u8; 1216] {
    *identites()[i].cle_publique()
}
fn ouvrir_par(f: &[u8], i: usize) -> Option<Vec<u8>> {
    format::dechiffrer(f, Ouverture::Identites(std::slice::from_ref(&identites()[i]))).ok().map(|c| c.to_vec())
}
fn ouvrir_mdp(f: &[u8], m: &[u8]) -> Option<Vec<u8>> {
    format::dechiffrer(f, Ouverture::MotDePasse(m)).ok().map(|c| c.to_vec())
}
fn aleatoire(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    alea::remplir(&mut v);
    v
}

#[test]
fn chaque_identifiant_ouvre_son_visage() {
    let (leurre, secret) = (aleatoire(100_000), aleatoire(30_000));

    // Deux mots de passe : le cas le plus courant.
    let f = format::chiffrer_deux_visages(
        &leurre,
        Destinataires::MotDePasse(b"vacances"),
        &secret,
        Destinataires::MotDePasse(b"journal"),
    )
    .unwrap();
    assert_eq!(ouvrir_mdp(&f, b"vacances").unwrap(), leurre);
    assert_eq!(ouvrir_mdp(&f, b"journal").unwrap(), secret);
    assert!(ouvrir_mdp(&f, b"autre").is_none());
    assert!(ouvrir_par(&f, 0).is_none());

    // Clés : deux destinataires pour le leurre, un pour le secret.
    let f = format::chiffrer_deux_visages(
        &leurre,
        Destinataires::Cles(&[pk(0), pk(1)]),
        &secret,
        Destinataires::Cles(&[pk(2)]),
    )
    .unwrap();
    assert_eq!(ouvrir_par(&f, 0).unwrap(), leurre);
    assert_eq!(ouvrir_par(&f, 1).unwrap(), leurre);
    assert_eq!(ouvrir_par(&f, 2).unwrap(), secret);
    assert!(ouvrir_par(&f, 3).is_none());

    // Mélanges : leurre par mot de passe, secret par clé, et inversement.
    let f = format::chiffrer_deux_visages(&leurre, Destinataires::MotDePasse(b"x"), &secret, Destinataires::Cles(&[pk(0)]))
        .unwrap();
    assert_eq!(ouvrir_mdp(&f, b"x").unwrap(), leurre);
    assert_eq!(ouvrir_par(&f, 0).unwrap(), secret);
    let f = format::chiffrer_deux_visages(&leurre, Destinataires::Cles(&[pk(0)]), &secret, Destinataires::MotDePasse(b"x"))
        .unwrap();
    assert_eq!(ouvrir_par(&f, 0).unwrap(), leurre);
    assert_eq!(ouvrir_mdp(&f, b"x").unwrap(), secret);
}

#[test]
fn les_deux_identifiants_ensemble_sont_signales() {
    let f = format::chiffrer_deux_visages(b"leurre", Destinataires::Cles(&[pk(0)]), b"secret", Destinataires::Cles(&[pk(1)]))
        .unwrap();
    let deux = [Identite::depuis_graine(identites()[0].graine()), Identite::depuis_graine(identites()[1].graine())];
    let r = format::dechiffrer_flux(&mut &f[..], f.len() as u64, Ouverture::Identites(&deux), &mut Vec::new());
    assert!(matches!(r, Err(ErreurOuverture::PlusieursVisages)), "{r:?}");
    // Un trousseau qui contient la clé du leurre et une clé étrangère ouvre le leurre.
    let trousseau = [Identite::depuis_graine(identites()[3].graine()), Identite::depuis_graine(identites()[0].graine())];
    assert_eq!(&*format::dechiffrer(&f, Ouverture::Identites(&trousseau)).unwrap(), b"leurre");
}

#[test]
fn regles_r3_et_r5() {
    let mdp = |m: &'static [u8]| Destinataires::MotDePasse(m);
    let r = format::chiffrer_deux_visages(b"a", mdp(b"pareil"), b"b", mdp(b"pareil"));
    assert!(matches!(r, Err(ErreurChiffrement::MemeMotDePasse)));
    let r = format::chiffrer_deux_visages(b"a", Destinataires::Cles(&[pk(0), pk(1)]), b"b", Destinataires::Cles(&[pk(1)]));
    assert!(matches!(r, Err(ErreurChiffrement::MemeCle)));
    let r = format::chiffrer_deux_visages(b"a", Destinataires::Cles(&[pk(0)]), b"b", Destinataires::Cles(&[]));
    assert!(matches!(r, Err(ErreurChiffrement::AucunDestinataire)));
    // R5 : une même clé répétée dans un seul visage est refusée aussi.
    let r = format::chiffrer(b"a", Destinataires::Cles(&[pk(0), pk(2), pk(0)]));
    assert!(matches!(r, Err(ErreurChiffrement::MemeCle)));
    // R3 : 16 destinataires au total.
    let pks: Vec<_> = (0..17).map(|_| *Identite::generer().cle_publique()).collect();
    let r = format::chiffrer_deux_visages(b"a", Destinataires::Cles(&pks[..10]), b"b", Destinataires::Cles(&pks[10..17]));
    assert!(matches!(r, Err(ErreurChiffrement::TropDeDestinataires)));
    let f = format::chiffrer_deux_visages(b"a", Destinataires::Cles(&pks[..10]), b"b", Destinataires::Cles(&pks[10..16]))
        .unwrap();
    assert!(!f.is_empty());
}

#[test]
fn capacite_exacte_de_la_reserve() {
    // Leurre vide : réserve de 64 Kio, donc un secret de 65 536 − 16 octets.
    for l1 in [0u64, 1000, 1_048_576, 2_000_000] {
        let cap = capacite_cachee(l1);
        assert!(taille_chiffree(cap) <= format::reserve(l1));
        assert!(taille_chiffree(cap + 1) > format::reserve(l1), "capacité non maximale pour L₁ = {l1}");
        let leurre = aleatoire(l1 as usize);
        let secret = aleatoire(cap as usize);
        let f = format::chiffrer_deux_visages(&leurre, Destinataires::Cles(&[pk(0)]), &secret, Destinataires::Cles(&[pk(1)]))
            .unwrap();
        assert_eq!(ouvrir_par(&f, 0).unwrap(), leurre);
        assert_eq!(ouvrir_par(&f, 1).unwrap(), secret, "L₁ = {l1}, secret de {cap} octets");
        let trop = aleatoire(cap as usize + 1);
        let r = format::chiffrer_deux_visages(&leurre, Destinataires::Cles(&[pk(0)]), &trop, Destinataires::Cles(&[pk(1)]));
        assert!(matches!(r, Err(ErreurChiffrement::SecretTropGrand { capacite }) if capacite == cap));
    }
    assert_eq!(capacite_cachee(0), 65_520);
    assert_eq!(capacite_cachee(16 * 1_000_000), 1_000_000 - 16 * 16);
}

#[test]
fn la_taille_ne_depend_que_du_leurre() {
    let leurre = aleatoire(5000);
    let (reference, fmax) = bornes_taille(leurre.len() as u64);
    let (mut avec, mut sans) = (0f64, 0f64);
    let n = 300;
    for _ in 0..n {
        let f1 = format::chiffrer(&leurre, Destinataires::Cles(&[pk(0)])).unwrap();
        let f2 = format::chiffrer_deux_visages(&leurre, Destinataires::Cles(&[pk(0)]), &aleatoire(60_000), Destinataires::Cles(&[pk(1)]))
            .unwrap();
        for f in [&f1, &f2] {
            assert!((reference..=fmax).contains(&(f.len() as u64)));
        }
        sans += f1.len() as f64;
        avec += f2.len() as f64;
    }
    let ecart = (avec - sans).abs() / n as f64;
    let largeur = (fmax - reference) as f64;
    // Écart-type de la différence des moyennes ≈ largeur / √(6n) ; on tolère 5 écarts-types.
    assert!(ecart < 5.0 * largeur / (6.0 * n as f64).sqrt(), "tailles moyennes trop différentes : {ecart}");
}

/// χ² d'homogénéité entre deux histogrammes d'octets (255 degrés de liberté).
fn chi2_homogeneite(a: &[u64; 256], b: &[u64; 256]) -> f64 {
    let (na, nb) = (a.iter().sum::<u64>() as f64, b.iter().sum::<u64>() as f64);
    let n = na + nb;
    (0..256)
        .map(|i| {
            let total = (a[i] + b[i]) as f64;
            let (ea, eb) = (total * na / n, total * nb / n);
            (a[i] as f64 - ea).powi(2) / ea + (b[i] as f64 - eb).powi(2) / eb
        })
        .sum()
}

/// Tout ce que l'adversaire contraint ne peut pas ouvrir : en-tête sauf son
/// étiquette, puis le corps après le leurre.
fn hors_du_leurre(f: &[u8], l1: usize, hist: &mut [u64; 256]) {
    // Son étiquette est celle dont la modification lui ferme le fichier.
    let x = (0..N_ETIQ)
        .find(|&x| {
            let mut g = f.to_vec();
            g[32 * x] ^= 1;
            ouvrir_par(&g, 0).is_none()
        })
        .expect("une des étiquettes est celle du leurre");
    let sienne = 32 * x..32 * x + 32;
    for (p, &x) in f[..H].iter().enumerate() {
        if !sienne.contains(&p) {
            hist[x as usize] += 1;
        }
    }
    for &x in &f[H + taille_chiffree(l1 as u64) as usize..] {
        hist[x as usize] += 1;
    }
}

#[test]
fn vue_contrainte_indistinguable() {
    let leurre = vec![0x41u8; 3 * TB]; // le leurre est connu de l'adversaire
    let (mut avec, mut sans) = ([0u64; 256], [0u64; 256]);
    for _ in 0..40 {
        let f_sans = format::chiffrer(&leurre, Destinataires::Cles(&[pk(0)])).unwrap();
        // Une fois sur deux un seul visage caché, une fois sur deux trois (QB-3).
        // Secrets de zéros : le pire cas.
        let f_avec = if avec.iter().sum::<u64>() % 2 == 0 {
            format::chiffrer_deux_visages(
                &leurre,
                Destinataires::Cles(&[pk(0)]),
                &vec![0u8; capacite_cachee(leurre.len() as u64) as usize],
                Destinataires::Cles(&[pk(1)]),
            )
            .unwrap()
        } else {
            let zeros = vec![0u8; 20_000];
            let mut v = Vec::new();
            let principal = Visage { entree: &mut &leurre[..], longueur: leurre.len() as u64, dest: Destinataires::Cles(&[pk(0)]) };
            let cles = [[pk(1)], [pk(2)], [pk(3)]];
            let caches = cles
                .iter()
                .map(|c| Visage { entree: Box::leak(Box::new(&zeros[..])), longueur: 20_000, dest: Destinataires::Cles(c) })
                .collect();
            format::chiffrer_flux(principal, caches, &mut v).unwrap();
            v
        };
        hors_du_leurre(&f_sans, leurre.len(), &mut sans);
        hors_du_leurre(&f_avec, leurre.len(), &mut avec);
    }
    let c = chi2_homogeneite(&avec, &sans);
    let p = p_chi2_255(c);
    eprintln!(
        "χ² d'homogénéité avec/sans visage caché : {c:.1} (p = {p:.3}) sur {} + {} octets",
        avec.iter().sum::<u64>(),
        sans.iter().sum::<u64>()
    );
    assert!(p > 1e-6, "la vue contrainte distingue les fichiers à deux visages : χ² = {c}");
    // Le test a de la puissance : il voit la différence si le secret n'est pas chiffré.
    let mut clair_visible = avec;
    clair_visible[0] += avec.iter().sum::<u64>() / 50;
    assert!(p_chi2_255(chi2_homogeneite(&clair_visible, &sans)) < 1e-6, "test sans puissance");
}

#[test]
fn la_reserve_ne_touche_pas_le_leurre_mais_protege_le_secret() {
    let (leurre, secret) = (aleatoire(200_000), aleatoire(50_000));
    let f = format::chiffrer_deux_visages(&leurre, Destinataires::Cles(&[pk(0)]), &secret, Destinataires::Cles(&[pk(1)]))
        .unwrap();
    let fin_leurre = H + taille_chiffree(leurre.len() as u64) as usize;
    // Trouver un octet du secret : le modifier ferme le secret, pas le leurre.
    let mut touche = 0;
    for p in (fin_leurre..f.len()).step_by(4999) {
        let mut g = f.clone();
        g[p] ^= 0x80;
        assert_eq!(ouvrir_par(&g, 0).unwrap(), leurre, "le leurre dépend de l'octet {p}");
        if ouvrir_par(&g, 1).is_none() {
            touche += 1;
        }
    }
    assert!(touche >= 5, "aucun octet du secret trouvé ({touche})");
    // Toute troncature ou tout ajout ferme les deux visages (F est couvert par T).
    let mut g = f.clone();
    g.push(0);
    assert!(ouvrir_par(&g, 0).is_none() && ouvrir_par(&g, 1).is_none());
    let g = &f[..f.len() - 1];
    assert!(ouvrir_par(g, 0).is_none() && ouvrir_par(g, 1).is_none());
}

#[test]
fn flux_a_deux_visages() {
    let (leurre, secret) = (aleatoire(40 * TB + 3), aleatoire(150_000));
    let mut sortie = Vec::new();
    let principal = Visage { entree: &mut &leurre[..], longueur: leurre.len() as u64, dest: Destinataires::Cles(&[pk(0)]) };
    let cache = Visage { entree: &mut &secret[..], longueur: secret.len() as u64, dest: Destinataires::MotDePasse(b"s") };
    let f = format::chiffrer_flux(principal, vec![cache], &mut sortie).unwrap();
    assert_eq!(f, sortie.len() as u64);
    for (ouv, attendu) in [
        (Ouverture::Identites(std::slice::from_ref(&identites()[0])), &leurre),
        (Ouverture::MotDePasse(b"s"), &secret),
    ] {
        let mut clair = Vec::new();
        let n = format::dechiffrer_flux(&mut &sortie[..], f, ouv, &mut clair).unwrap();
        assert_eq!(n as usize, attendu.len());
        assert_eq!(&clair, attendu);
    }
}

#[test]
fn jusqu_a_trois_visages_caches() {
    assert_eq!((N_ETIQ, MAX_CACHES), (4, 3));
    let leurre = aleatoire(400_000);
    let secrets = [aleatoire(20_000), aleatoire(15_000), aleatoire(25_000)];
    let fabriquer = |dests: [Destinataires; 3]| {
        let mut v = Vec::new();
        let principal = Visage { entree: &mut &leurre[..], longueur: leurre.len() as u64, dest: Destinataires::Cles(&[pk(0)]) };
        let mut lecteurs: Vec<&[u8]> = secrets.iter().map(|s| &s[..]).collect();
        let caches = lecteurs
            .iter_mut()
            .zip(dests)
            .zip(&secrets)
            .map(|((l, dest), s)| Visage { entree: l, longueur: s.len() as u64, dest })
            .collect();
        format::chiffrer_flux(principal, caches, &mut v).map(|_| v)
    };
    // Trois visages cachés, mélangeant mots de passe et clés : chacun s'ouvre sur le sien.
    let f = fabriquer([
        Destinataires::MotDePasse(b"un"),
        Destinataires::Cles(&[pk(1)]),
        Destinataires::MotDePasse(b"trois"),
    ])
    .unwrap();
    assert_eq!(ouvrir_par(&f, 0).unwrap(), leurre);
    assert_eq!(ouvrir_mdp(&f, b"un").unwrap(), secrets[0]);
    assert_eq!(ouvrir_par(&f, 1).unwrap(), secrets[1]);
    assert_eq!(ouvrir_mdp(&f, b"trois").unwrap(), secrets[2]);
    assert!(ouvrir_mdp(&f, b"deux").is_none() && ouvrir_par(&f, 2).is_none());
    // La taille ne dépend toujours que du leurre.
    let (reference, fmax) = bornes_taille(leurre.len() as u64);
    assert!((reference..=fmax).contains(&(f.len() as u64)));
    // R5 entre visages cachés.
    let r = fabriquer([Destinataires::MotDePasse(b"x"), Destinataires::Cles(&[pk(1)]), Destinataires::MotDePasse(b"x")]);
    assert!(matches!(r, Err(ErreurChiffrement::MemeMotDePasse)));
    let r = fabriquer([Destinataires::Cles(&[pk(1)]), Destinataires::Cles(&[pk(2)]), Destinataires::Cles(&[pk(2)])]);
    assert!(matches!(r, Err(ErreurChiffrement::MemeCle)));
    // Ensemble, les secrets doivent tenir dans la réserve.
    let gros = vec![0u8; 30_000];
    let mut v = Vec::new();
    let principal = Visage { entree: &mut &leurre[..], longueur: leurre.len() as u64, dest: Destinataires::Cles(&[pk(0)]) };
    let (mut a, mut b, mut c) = (&gros[..], &gros[..], &gros[..]);
    let (k1, k2, k3) = ([pk(1)], [pk(2)], [pk(3)]);
    let caches = vec![
        Visage { entree: &mut a, longueur: 30_000, dest: Destinataires::Cles(&k1) },
        Visage { entree: &mut b, longueur: 30_000, dest: Destinataires::Cles(&k2) },
        Visage { entree: &mut c, longueur: 30_000, dest: Destinataires::Cles(&k3) },
    ];
    let r = format::chiffrer_flux(principal, caches, &mut v);
    assert!(matches!(r, Err(ErreurChiffrement::SecretTropGrand { .. })), "{r:?}");
    // Un quatrième visage caché : refusé.
    let mut v = Vec::new();
    let principal = Visage { entree: &mut &leurre[..], longueur: leurre.len() as u64, dest: Destinataires::Cles(&[pk(0)]) };
    let petits: Vec<Vec<u8>> = (0..4).map(|_| vec![1u8; 10]).collect();
    let mut lecteurs: Vec<&[u8]> = petits.iter().map(|p| &p[..]).collect();
    let mdps: [&[u8]; 4] = [b"a", b"b", b"c", b"d"];
    let caches = lecteurs
        .iter_mut()
        .zip(mdps)
        .map(|(l, m)| Visage { entree: l, longueur: 10, dest: Destinataires::MotDePasse(m) })
        .collect();
    assert!(matches!(format::chiffrer_flux(principal, caches, &mut v), Err(ErreurChiffrement::TropDeVisages)));
}
