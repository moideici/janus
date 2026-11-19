//! Tests de `janus inspect`.
//!
//! - Un fichier Janus ne révèle ni outil, ni destinataires, ni algorithme, et la
//!   plage de taille annoncée contient toujours la vraie taille du clair.
//! - Les vrais fichiers gpg et 7-Zip de `tests/echantillons/` sont décrits fidèlement.
//! - Aucun fichier aléatoire n'est pris pour un format connu (pas de faux positif).

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use janus::alea;
use janus::format::{self, bornes_taille, Destinataires, H, TB, TC};
use janus::inspect::{inspecter, plage_clair_janus, HypotheseJanus, Rapport, TailleClair};
use janus::xwing::Identite;
use std::io::Cursor;

fn radio(octets: &[u8]) -> Rapport {
    inspecter(&mut Cursor::new(octets)).unwrap()
}

fn echantillon(nom: &str) -> Rapport {
    let chemin = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/echantillons").join(nom);
    radio(&std::fs::read(chemin).unwrap())
}

fn aleatoire(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    alea::remplir(&mut v);
    v
}

fn texte(r: &Rapport) -> String {
    r.to_string()
}

#[test]
fn un_fichier_janus_reste_muet() {
    let pks: Vec<[u8; 1216]> = (0..16).map(|_| *Identite::generer().cle_publique()).collect();
    for (len, n_dest) in [(0usize, 1usize), (13, 16), (5000, 3), (TB, 1), (3 * TB + 99, 16), (300_000, 2)] {
        let f = format::chiffrer(&aleatoire(len), Destinataires::Cles(&pks[..n_dest])).unwrap();
        let r = radio(&f);
        assert!(r.format.is_none(), "{len} : format reconnu à tort");
        assert!(r.alea.aleatoire(), "{len} : χ² = {}, p = {}", r.alea.chi2, r.alea.p);
        match r.janus {
            Some(HypotheseJanus::Compatible { clair_min, clair_max }) => {
                assert!(clair_min <= len as u64 && len as u64 <= clair_max, "{len} ∉ [{clair_min}, {clair_max}]")
            }
            autre => panic!("{len} : {autre:?}"),
        }
        let t = texte(&r);
        assert!(t.contains("aucun") && !t.contains("Destinataire"), "{t}");
    }
    // Mot de passe : même rapport, rien ne trahit le mode.
    let f = format::chiffrer(b"secret", Destinataires::MotDePasse(b"mdp")).unwrap();
    assert!(matches!(radio(&f).janus, Some(HypotheseJanus::Compatible { .. })));
}

#[test]
fn la_plage_de_clair_contient_toujours_la_vraie_taille() {
    for len in (0..3000u64).chain([TB as u64 - 1, TB as u64, TB as u64 + 1, 10 * TB as u64 + 7, 123_456_789]) {
        let (reference, plafond) = bornes_taille(len);
        let pas = ((plafond - reference) / 50).max(1);
        let mut f = reference;
        while f <= plafond {
            let (a, b) = plage_clair_janus(f).expect("taille valide refusée");
            assert!(a <= len && len <= b, "L = {len}, F = {f} : [{a}, {b}]");
            f += pas;
        }
        let f = format::tirer_taille(len);
        let (a, b) = plage_clair_janus(f).unwrap();
        assert!(a <= len && len <= b);
    }
}

#[test]
fn tailles_impossibles_pour_janus() {
    // Le plus petit fichier v1 : H + c(0) + 64 Kio = H + TC.
    for n in [0usize, 1000, H, H + 16, H + TC - 1] {
        let r = radio(&aleatoire(n));
        assert!(matches!(r.janus, Some(HypotheseJanus::Exclue(_))), "{n} : {:?}", r.janus);
    }
    // Bonne taille mais contenu structuré.
    let r = radio(&vec![0x41u8; H + 1000]);
    assert!(matches!(r.janus, None | Some(HypotheseJanus::Exclue(_))));
}

#[test]
fn aucun_faux_positif_sur_l_alea() {
    for i in 0..4000 {
        let n = 1 + (i * 37) % 3000;
        let r = radio(&aleatoire(n));
        assert!(r.format.is_none(), "{n} octets aléatoires pris pour {:?}", r.format.map(|f| f.nom));
    }
    // Chaque premier octet possible, y compris ceux d'un paquet OpenPGP.
    for premier in 0..=255u8 {
        for _ in 0..40 {
            let mut v = aleatoire(600);
            v[0] = premier;
            let r = radio(&v);
            assert!(r.format.is_none(), "premier octet {premier:#04x} : {:?}", r.format.map(|f| f.nom));
        }
    }
}

#[test]
fn gpg_revele_les_destinataires() {
    let r = echantillon("gpg-deux-cles.gpg");
    let f = r.format.as_ref().unwrap();
    assert_eq!(f.nom, "OpenPGP (gpg)");
    assert_eq!(f.destinataires, Some(2));
    let t = texte(&r);
    assert!(t.contains("0x8E00C833B44B46CE (ECDH)") && t.contains("0x954BDA8FD5A6F602 (RSA)"), "{t}");
    assert!(matches!(f.clair, Some(TailleClair::Environ(_))));

    let r = echantillon("gpg-cle-masquee.gpg");
    assert_eq!(r.format.as_ref().unwrap().destinataires, Some(1));
    assert!(texte(&r).contains("masqué"));

    let r = echantillon("gpg-mot-de-passe.gpg");
    let t = texte(&r);
    assert!(t.contains("AES-256") && t.contains("SHA-512") && t.contains("24 117 248"), "{t}");

    let r = echantillon("gpg-armure.asc");
    let f = r.format.as_ref().unwrap();
    assert_eq!(f.nom, "OpenPGP (gpg), armure ASCII");
    assert!(texte(&r).contains("0x8E00C833B44B46CE"));
}

#[test]
fn zip_revele_noms_tailles_et_faiblesses() {
    let r = echantillon("zip-zipcrypto.zip");
    let t = texte(&r);
    assert!(t.contains("dossier/salaires.xlsx : 13 octets") && t.contains("lettre-de-demission.docx : 1 octet,"), "{t}");
    assert!(t.contains("ZipCrypto est cassé") && t.contains("CRC-32"), "{t}");
    assert_eq!(r.format.unwrap().clair, Some(TailleClair::Exacte(14)));

    let r = echantillon("zip-aes.zip");
    let t = texte(&r);
    assert!(t.contains("AES-256") && t.contains("salaires.xlsx") && !t.contains("ZipCrypto est cassé"), "{t}");
}

#[test]
fn sept_zip_selon_l_option_mhe() {
    assert!(texte(&echantillon("7z-noms-visibles.7z")).contains("En-tête non chiffré"));
    assert!(texte(&echantillon("7z-noms-caches.7z")).contains("En-tête chiffré"));
}

/// Fichier age construit à la main (age n'est pas installé) : deux strophes.
fn fichier_age(n: u64) -> Vec<u8> {
    let b64 = |k: usize| STANDARD.encode(aleatoire(k)).trim_end_matches('=').to_string();
    let mut f = String::from("age-encryption.org/v1\n");
    f += &format!("-> X25519 {}\n{}\n", b64(32), b64(32));
    f += &format!("-> ssh-ed25519 {} {}\n{}\n", b64(4), b64(32), b64(32));
    f += &format!("--- {}\n", b64(32));
    let mut v = f.into_bytes();
    let charge = n + 16 * n.div_ceil(65_536).max(1);
    v.extend(aleatoire(16 + charge as usize));
    v
}

#[test]
fn age_revele_la_taille_exacte() {
    for n in [0u64, 1, 65_535, 65_536, 65_537, 200_000] {
        let r = radio(&fichier_age(n));
        let f = r.format.as_ref().expect("age non reconnu");
        assert_eq!(f.nom, "age v1");
        assert_eq!(f.destinataires, Some(2));
        assert_eq!(f.clair, Some(TailleClair::Exacte(n)), "n = {n}");
        assert!(texte(&r).contains("clé SSH"));
    }
    // Armure ASCII : base64 standard, 64 colonnes.
    let binaire = fichier_age(1000);
    let b64 = STANDARD.encode(&binaire);
    let lignes: Vec<&str> = b64.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect();
    let armure = format!("-----BEGIN AGE ENCRYPTED FILE-----\n{}\n-----END AGE ENCRYPTED FILE-----\n", lignes.join("\n"));
    let r = radio(armure.as_bytes());
    let f = r.format.unwrap();
    assert_eq!(f.nom, "age v1, armure ASCII");
    assert_eq!(f.clair, Some(TailleClair::Exacte(1000)));
}

#[test]
fn signatures_simples() {
    let mut openssl = b"Salted__".to_vec();
    openssl.extend(aleatoire(8 + 64));
    let r = radio(&openssl);
    assert_eq!(r.format.as_ref().unwrap().nom, "openssl enc");
    assert_eq!(r.format.unwrap().clair, Some(TailleClair::Entre(48, 63)));

    let mut luks = vec![0u8; 1024];
    luks[..6].copy_from_slice(b"LUKS\xBA\xBE");
    luks[7] = 1;
    luks[8..11].copy_from_slice(b"aes");
    luks[40..51].copy_from_slice(b"xts-plain64");
    luks[72..78].copy_from_slice(b"sha256");
    luks[168..172].copy_from_slice(b"1234");
    for i in [0usize, 3] {
        luks[208 + 48 * i..212 + 48 * i].copy_from_slice(&0x00AC_71F3u32.to_be_bytes());
    }
    let t = texte(&radio(&luks));
    assert!(t.contains("aes-xts-plain64") && t.contains("actifs : 2 sur 8"), "{t}");

    assert_eq!(radio(b"Bonjour, ceci est un texte.\n").format.unwrap().nom, "texte");
    assert_eq!(radio(b"\x89PNG\r\n\x1a\n....").format.unwrap().nom, "image PNG");
}

#[test]
fn le_test_d_alea_repere_une_zone_structuree() {
    // Un fichier aléatoire avec 8 Kio de zéros au milieu.
    let mut v = aleatoire(200_000);
    v[100_000..108_192].fill(0);
    let r = radio(&v);
    assert!(r.alea.blocs_structures >= 1);
    assert!(matches!(r.janus, Some(HypotheseJanus::Exclue(_))));
}

/// Un fichier piégé ne doit jamais faire paniquer l'analyseur : on tronque
/// chaque échantillon à toutes les longueurs et on l'abîme au hasard.
#[test]
fn echantillons_abimes_sans_panique() {
    let dossier = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/echantillons");
    let mut sources: Vec<Vec<u8>> = std::fs::read_dir(dossier).unwrap().map(|e| std::fs::read(e.unwrap().path()).unwrap()).collect();
    sources.push(fichier_age(70_000)[..2000].to_vec());
    for s in &sources {
        for n in 0..s.len().min(2000) {
            let _ = radio(&s[..n]);
        }
        for _ in 0..3000 {
            let mut v = s.clone();
            for _ in 0..1 + alea::uniforme_u32(4) {
                let p = alea::uniforme_u64_jusqua(v.len() as u64 - 1) as usize;
                v[p] = alea::octets::<1>()[0];
            }
            let _ = radio(&v);
        }
    }
}
