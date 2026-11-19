//! Tests du format Janus (v1, un seul visage) : allers-retours, corpus de fichiers
//! piégés et propriétés. Les deux visages ont leurs tests dans tests/visages.rs.

use janus::format::{self, Destinataires, Falsification, ImpossibleDeDechiffrer, Ouverture, Visage, H, OFF_EMPL, S, TB, TC};
use janus::xwing::Identite;
use std::sync::OnceLock;

const MDP: &[u8] = b"correct cheval pile agrafe";

fn alice() -> &'static Identite {
    static A: OnceLock<Identite> = OnceLock::new();
    A.get_or_init(Identite::generer)
}
fn bob() -> &'static Identite {
    static B: OnceLock<Identite> = OnceLock::new();
    B.get_or_init(Identite::generer)
}

fn contenu(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 31 + 7) as u8).collect()
}

fn pour_alice(clair: &[u8]) -> Vec<u8> {
    format::chiffrer(clair, Destinataires::Cles(&[*alice().cle_publique()])).unwrap()
}

fn ouvrir_alice(f: &[u8]) -> Result<Vec<u8>, ImpossibleDeDechiffrer> {
    format::dechiffrer(f, Ouverture::Identites(std::slice::from_ref(alice()))).map(|c| c.to_vec())
}

// ───────────────────────── § 13.1 allers-retours ─────────────────────────

#[test]
fn aller_retour_tailles_limites() {
    for n in [0, 1, 1000, TB - 1, TB, TB + 1, 3 * TB + 17] {
        let clair = contenu(n);
        let f = pour_alice(&clair);
        assert_eq!(ouvrir_alice(&f).unwrap(), clair, "longueur {n}");
        let (reference, fmax) = format::bornes_taille(n as u64);
        assert!((reference..=fmax).contains(&(f.len() as u64)), "taille hors de [Ref, PADMÉ(Ref)]");
    }
}

#[test]
fn aller_retour_gros_fichier_parallele() {
    let clair = contenu(20 * TB + 12345);
    assert_eq!(ouvrir_alice(&pour_alice(&clair)).unwrap(), clair);
}

#[test]
fn mot_de_passe() {
    let clair = contenu(5000);
    let f = format::chiffrer(&clair, Destinataires::MotDePasse(MDP)).unwrap();
    assert_eq!(&*format::dechiffrer(&f, Ouverture::MotDePasse(MDP)).unwrap(), &clair[..]);
    assert_eq!(
        format::dechiffrer(&f, Ouverture::MotDePasse(b"correct cheval pile agrafE")),
        Err(ImpossibleDeDechiffrer)
    );
    // Une identité ne doit pas ouvrir un fichier à mot de passe.
    assert_eq!(ouvrir_alice(&f), Err(ImpossibleDeDechiffrer));
}

#[test]
fn seize_destinataires_et_dix_septieme_refuse() {
    let ids: Vec<Identite> = (0..16).map(|_| Identite::generer()).collect();
    let pks: Vec<_> = ids.iter().map(|i| *i.cle_publique()).collect();
    let clair = contenu(777);
    let f = format::chiffrer(&clair, Destinataires::Cles(&pks)).unwrap();
    for id in &ids {
        let c = format::dechiffrer(&f, Ouverture::Identites(std::slice::from_ref(id))).unwrap();
        assert_eq!(&*c, &clair[..]);
    }
    let mut trop = pks.clone();
    trop.push(*alice().cle_publique());
    assert!(format::chiffrer(&clair, Destinataires::Cles(&trop)).is_err());
}

#[test]
fn etranger_et_plusieurs_identites() {
    let f = pour_alice(b"secret");
    assert_eq!(
        format::dechiffrer(&f, Ouverture::Identites(std::slice::from_ref(bob()))),
        Err(ImpossibleDeDechiffrer)
    );
    // Avec un trousseau (Bob puis Alice), l'ouverture réussit.
    let trousseau = [Identite::depuis_graine(bob().graine()), Identite::depuis_graine(alice().graine())];
    assert_eq!(&*format::dechiffrer(&f, Ouverture::Identites(&trousseau)).unwrap(), b"secret");
}

/// P6 : la taille ne dépend pas du nombre de destinataires.
#[test]
fn taille_independante_des_destinataires() {
    let clair = contenu(10_000);
    let (reference, fmax) = format::bornes_taille(clair.len() as u64);
    let ids: Vec<_> = (0..16).map(|_| *Identite::generer().cle_publique()).collect();
    for n in [1, 16] {
        for _ in 0..5 {
            let f = format::chiffrer(&clair, Destinataires::Cles(&ids[..n])).unwrap();
            assert!((reference..=fmax).contains(&(f.len() as u64)));
        }
    }
    let f = format::chiffrer(&clair, Destinataires::MotDePasse(MDP)).unwrap();
    assert!((reference..=fmax).contains(&(f.len() as u64)));
}

// ───────────────────────── § 13.2 fichiers piégés ─────────────────────────

fn refuse(f: &[u8], quoi: &str) {
    assert_eq!(ouvrir_alice(f), Err(ImpossibleDeDechiffrer), "accepté à tort : {quoi}");
}

#[test]
fn un_bit_inverse_partout() {
    let clair = contenu(2 * TB + 500);
    let f = pour_alice(&clair);
    let fin_visage = H + format::taille_chiffree(clair.len() as u64) as usize;
    // Sel, début/milieu/fin de chaque emplacement, chaque bloc du visage et son dernier octet.
    let mut positions = vec![64, 95];
    for i in 0..16 {
        positions.extend([OFF_EMPL + i * S, OFF_EMPL + i * S + 700, OFF_EMPL + i * S + S - 1]);
    }
    for j in 0..3 {
        positions.extend([H + j * TC, H + j * TC + 100]);
    }
    positions.push(fin_visage - 1);
    for p in positions {
        let mut g = f.clone();
        g[p] ^= 0x01;
        refuse(&g, &format!("bit inversé à l'octet {p}"));
    }
    // Les deux étiquettes à la fois : l'une des deux est celle d'Alice.
    let mut g = f.clone();
    g[0] ^= 1;
    g[32] ^= 1;
    refuse(&g, "étiquettes T_0 et T_1");
    // La réserve n'appartient pas au visage : la modifier ne le gêne pas (c'est voulu, § 8).
    let mut g = f.clone();
    let dernier = g.len() - 1;
    g[dernier] ^= 1;
    g[fin_visage] ^= 1;
    assert_eq!(ouvrir_alice(&g).unwrap(), clair, "la réserve doit rester hors du visage");
}

#[test]
fn troncatures_et_ajouts() {
    let f = pour_alice(&contenu(2 * TB + 500));
    refuse(&f[..f.len() - 1], "tronqué d'un octet");
    refuse(&f[..f.len() - TC], "tronqué d'un bloc");
    refuse(&f[..H + TC], "premier bloc seul");
    refuse(&f[..H], "en-tête seul");
    refuse(&f[..100], "100 octets");
    refuse(&[], "fichier vide");
    let mut g = f.clone();
    g.push(0);
    refuse(&g, "un octet ajouté");
    let mut g = f.clone();
    g.extend_from_slice(&f[H..H + TC]);
    refuse(&g, "bloc dupliqué à la fin");
}

#[test]
fn blocs_echanges_ou_dupliques() {
    let f = pour_alice(&contenu(4 * TB));
    let bloc = |g: &[u8], j: usize| g[H + j * TC..H + (j + 1) * TC].to_vec();
    let mut g = f.clone();
    let (b0, b1) = (bloc(&f, 0), bloc(&f, 1));
    g[H..H + TC].copy_from_slice(&b1);
    g[H + TC..H + 2 * TC].copy_from_slice(&b0);
    refuse(&g, "blocs 0 et 1 échangés");
    let mut g = f.clone();
    g[H + TC..H + 2 * TC].copy_from_slice(&b0);
    refuse(&g, "bloc 0 recopié en position 1");
}

/// Un en-tête authentique qui annonce un mauvais début ou une mauvaise longueur.
#[test]
fn debut_ou_longueur_falsifies() {
    let clair = contenu(3 * TB + 10);
    let l = clair.len() as u64;
    let dest = || Destinataires::Cles(std::slice::from_ref(alice().cle_publique()));
    for (falsif, quoi) in [
        (Falsification { longueur: Some(l - 1), ..Default::default() }, "longueur − 1"),
        (Falsification { longueur: Some(l + 1), ..Default::default() }, "longueur + 1"),
        (Falsification { longueur: Some(TB as u64), ..Default::default() }, "un seul bloc annoncé"),
        (Falsification { longueur: Some(u64::MAX - 5), ..Default::default() }, "longueur énorme"),
        (Falsification { debut: Some(1), ..Default::default() }, "début décalé d'un octet"),
        (Falsification { debut: Some(u64::MAX - 5), ..Default::default() }, "début énorme"),
    ] {
        let f = format::chiffrer_falsifie_pour_tests(&clair, dest(), falsif).unwrap();
        refuse(&f, quoi);
    }
}

/// P3/P4 : greffer dans le fichier d'Alice un emplacement valide pour Bob
/// (donc une autre clé K) doit échouer pour Bob, et Alice lit toujours son contenu.
#[test]
fn greffe_d_emplacement_entre_fichiers() {
    let clair = contenu(3000);
    let fa = pour_alice(&clair);
    let fb = format::chiffrer(b"autre chose", Destinataires::Cles(&[*bob().cle_publique()])).unwrap();
    let ouvrir_bob =
        |f: &[u8]| format::dechiffrer(f, Ouverture::Identites(std::slice::from_ref(bob())));
    // Trouver l'emplacement de Bob dans son fichier et celui d'Alice dans le sien.
    let a_occupe = |f: &[u8], id: &Identite, i: usize| {
        let mut g = f.to_vec();
        g[OFF_EMPL + i * S] ^= 1; // si l'ouverture casse, c'était l'emplacement de id
        format::dechiffrer(&g, Ouverture::Identites(std::slice::from_ref(id))).is_err()
    };
    let ib = (0..16).find(|&i| a_occupe(&fb, bob(), i)).unwrap();
    let ia = (0..16).find(|&i| a_occupe(&fa, alice(), i)).unwrap();
    let cible = (0..16).find(|&i| i != ia).unwrap();
    let mut g = fa.clone();
    g[OFF_EMPL + cible * S..OFF_EMPL + (cible + 1) * S]
        .copy_from_slice(&fb[OFF_EMPL + ib * S..OFF_EMPL + (ib + 1) * S]);
    assert!(ouvrir_bob(&g).is_err(), "Bob ne doit rien ouvrir");
    refuse(&g, "en-tête modifié");
}

#[test]
fn fichiers_aleatoires_refuses() {
    let mut f = vec![0u8; 40_000];
    for _ in 0..5 {
        janus::alea::remplir(&mut f);
        refuse(&f, "aléa");
        assert!(format::dechiffrer(&f, Ouverture::MotDePasse(MDP)).is_err());
    }
}

// ───────────────────────── P5 : indistinguabilité ─────────────────────────

/// χ² sur les 256 valeurs d'octet (255 degrés de liberté : moyenne 255, écart-type ≈ 22,6).
fn khi2_octets(donnees: &[u8]) -> f64 {
    let mut comptes = [0u64; 256];
    for &b in donnees {
        comptes[b as usize] += 1;
    }
    let attendu = donnees.len() as f64 / 256.0;
    comptes.iter().map(|&c| (c as f64 - attendu).powi(2) / attendu).sum()
}

/// χ² sur les coefficients de 10 bits de la partie c1 d'un chiffré ML-KEM brut.
fn khi2_coeffs_10_bits(cts: &[Vec<u8>]) -> f64 {
    let mut comptes = vec![0u64; 1024];
    let mut total = 0u64;
    for ct in cts {
        for bloc in ct[..960].chunks(5) {
            let x = u64::from_le_bytes([bloc[0], bloc[1], bloc[2], bloc[3], bloc[4], 0, 0, 0]);
            for k in 0..4 {
                comptes[((x >> (10 * k)) & 1023) as usize] += 1;
                total += 1;
            }
        }
    }
    let attendu = total as f64 / 1024.0;
    comptes.iter().map(|&c| (c as f64 - attendu).powi(2) / attendu).sum()
}

#[test]
fn le_test_statistique_detecte_ml_kem_brut_mais_pas_janus() {
    use janus::kemeleon;
    // Chiffrés ML-KEM bruts (X-Wing standard), leur encodage Kemeleon, et les κ
    // masqués que Janus écrit vraiment dans les emplacements.
    let id = Identite::generer();
    let mut bruts = Vec::new();
    let mut encodes = Vec::new();
    let mut masques = Vec::new();
    for _ in 0..150 {
        let (_, ct) = janus::xwing::encapsuler_derand(id.cle_publique(), &janus::alea::octets::<64>());
        encodes.extend_from_slice(&kemeleon::encoder_chiffre(&ct[..1088]));
        bruts.push(ct[..1088].to_vec());
        let (_, _, kappa) = janus::xwing::encapsuler_cache(id.cle_publique()).unwrap();
        masques.extend_from_slice(&kappa);
    }
    let brut = khi2_coeffs_10_bits(&bruts);
    // 1023 degrés de liberté : moyenne 1023, écart-type ≈ 45. Le brut doit exploser.
    assert!(brut > 1500.0, "le test n'a pas de puissance : χ² brut = {brut}");

    let k_enc = khi2_octets(&encodes);
    assert!(k_enc < 380.0, "Kemeleon distinguable ? χ² = {k_enc}");
    let k_masq = khi2_octets(&masques);
    assert!(k_masq < 380.0, "κ masqué distinguable ? χ² = {k_masq}");

    // Fichier Janus complet, toutes zones confondues (T, emplacements, corps).
    let mut fichiers = Vec::new();
    for _ in 0..8 {
        fichiers.extend(pour_alice(&vec![0u8; 30_000]));
    }
    let k_fic = khi2_octets(&fichiers);
    assert!(k_fic < 380.0, "fichier Janus distinguable ? χ² = {k_fic}");
    eprintln!("χ² ML-KEM brut (10 bits) = {brut:.0} ; Kemeleon = {k_enc:.0} ; κ masqué = {k_masq:.0} ; fichiers = {k_fic:.0}");
}

/// Le tirage de taille doit couvrir [Ref, PADMÉ(Ref)] uniformément (§ 7).
#[test]
fn tirage_de_taille_uniforme() {
    let (reference, fmax) = format::bornes_taille(14);
    let largeur = (fmax - reference + 1) as f64;
    let n = 50_000;
    let mut somme = 0f64;
    let (mut mini, mut maxi, mut egal_ref) = (u64::MAX, 0, 0);
    for _ in 0..n {
        let f = format::tirer_taille(14);
        somme += f as f64;
        mini = mini.min(f);
        maxi = maxi.max(f);
        egal_ref += (f == reference) as u32;
    }
    let moyenne = somme / n as f64;
    let milieu = (reference + fmax) as f64 / 2.0;
    eprintln!("Ref={reference} PADMÉ={fmax} min={mini} max={maxi} moyenne={moyenne:.1} F=Ref : {egal_ref}/{n}");
    assert_eq!((mini, maxi), (reference, fmax));
    assert!((moyenne - milieu).abs() < largeur * 0.01);
    assert!(egal_ref < 3 * (n as f64 / largeur) as u32 + 10);
}

/// Plusieurs lots de traitement (un lot = 16 blocs par cœur) : coupures entre lots.
#[test]
fn aller_retour_plusieurs_lots_et_troncature_entre_lots() {
    let mut clair = vec![0u8; 300 * TB + 123];
    janus::alea::remplir(&mut clair);
    let f = pour_alice(&clair);
    assert_eq!(ouvrir_alice(&f).unwrap(), clair);
    let lot = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1) * 16;
    if H + lot * TC < f.len() {
        refuse(&f[..H + lot * TC], "coupé pile à la fin du premier lot");
    }
    // Clair se terminant par beaucoup de zéros : ils doivent tous revenir.
    let mut zeros = vec![0u8; 3 * TB];
    zeros[0] = 1;
    assert_eq!(ouvrir_alice(&pour_alice(&zeros)).unwrap(), zeros);
}

/// L'entrée doit faire exactement la longueur annoncée.
#[test]
fn entree_de_longueur_inattendue() {
    let clair = contenu(1000);
    let mut v = Vec::new();
    let dest = || Destinataires::Cles(std::slice::from_ref(alice().cle_publique()));
    let essai = |annonce: u64, v: &mut Vec<u8>| {
        let principal = Visage { entree: &mut &clair[..], longueur: annonce, dest: dest() };
        format::chiffrer_flux(principal, Vec::new(), v)
    };
    assert!(essai(999, &mut v).is_err(), "entrée plus longue");
    v.clear();
    assert!(essai(1001, &mut v).is_err(), "entrée plus courte");
}
