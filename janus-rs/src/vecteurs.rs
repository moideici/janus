//! Vecteurs de test Janus v1 (03-deux-visages.md, § 13), dans `janus-rs/vecteurs/`.
//!
//! Deux usages :
//! 1. **Interopérabilité** : chaque fichier `.janus` publié, ouvert avec la clé
//!    indiquée dans `manifeste.json`, doit redonner exactement le clair décrit.
//!    Une autre implémentation peut le vérifier sans rien connaître de la nôtre.
//! 2. **Non-régression** : avec l'aléa remplacé par un flux déterministe
//!    (`alea::deterministe`, absent du programme réel), notre chiffrement doit
//!    reproduire ces fichiers octet pour octet. Toute modification involontaire
//!    du format fait échouer le test.
//!
//! Régénérer (après un changement VOULU du format) :
//!   JANUS_REGENERER_VECTEURS=1 cargo test --release vecteurs

use crate::alea::deterministe::avec_graine;
use crate::format::{self, Destinataires, Ouverture};
use crate::xwing::Identite;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::path::PathBuf;

const MDP: &str = "janus";

enum Dest {
    MotDePasse,
    Cles(u8), // nombre de destinataires ; graine du destinataire i = [i + 1; 32]
    /// Leurre ouvert par MDP, puis des visages cachés : (mot de passe, longueur).
    /// Le j-ième secret vaut octet k = (17·k + 3 + 50·j) mod 256.
    Visages(&'static [(&'static str, usize)]),
    /// Leurre pour les clés 0 et 1 ; visage caché 0 pour la clé 2 (500 octets) ;
    /// visage caché 1 pour le mot de passe « visage » (300 octets). Ouvrir avec les
    /// identités 0 et 2 ensemble doit donner « plusieurs visages ».
    VisagesCles,
}

/// Configuration de `Dest::VisagesCles`.
const VC_CACHE_CLE: (u8, usize) = (2, 500);
const VC_CACHE_MDP: (&str, usize) = ("visage", 300);

struct Cas {
    nom: &'static str,
    dest: Dest,
    longueur: usize,
}

const CAS: &[Cas] = &[
    Cas { nom: "mot-de-passe", dest: Dest::MotDePasse, longueur: 13 },
    Cas { nom: "une-cle", dest: Dest::Cles(1), longueur: 13 },
    Cas { nom: "seize-cles", dest: Dest::Cles(16), longueur: 1000 },
    Cas { nom: "vide", dest: Dest::Cles(1), longueur: 0 },
    Cas { nom: "un-bloc-exact", dest: Dest::Cles(1), longueur: 65_536 },
    Cas { nom: "deux-blocs", dest: Dest::Cles(1), longueur: 65_537 },
    Cas { nom: "deux-visages", dest: Dest::Visages(&[("visage", 700)]), longueur: 1000 },
    Cas {
        nom: "quatre-visages",
        dest: Dest::Visages(&[("visage", 700), ("deuxieme", 300), ("troisieme", 200)]),
        longueur: 1000,
    },
    Cas { nom: "visages-cles", dest: Dest::VisagesCles, longueur: 1000 },
];

/// Clair de longueur n : octet k = (31·k + 7) mod 256.
fn clair(n: usize) -> Vec<u8> {
    (0..n).map(|k| (31 * k + 7) as u8).collect()
}

/// Clair du j-ième visage caché : octet k = (17·k + 3 + 50·j) mod 256.
fn clair_secret(j: usize, n: usize) -> Vec<u8> {
    (0..n).map(|k| (17 * k + 3 + 50 * j) as u8).collect()
}

fn graine(i: u8) -> [u8; 32] {
    [i + 1; 32]
}

fn hex_sha256(x: &[u8]) -> String {
    hex::encode(Sha256::digest(x))
}

fn dossier() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("vecteurs")
}

fn generer(cas: &Cas) -> Vec<u8> {
    let m = clair(cas.longueur);
    avec_graine(cas.nom.as_bytes(), || match cas.dest {
        Dest::MotDePasse => format::chiffrer(&m, Destinataires::MotDePasse(MDP.as_bytes())).unwrap(),
        Dest::Visages(caches) => {
            let secrets: Vec<Vec<u8>> = caches.iter().enumerate().map(|(j, &(_, n))| clair_secret(j, n)).collect();
            let mut lecteurs: Vec<&[u8]> = secrets.iter().map(|s| &s[..]).collect();
            let visages = lecteurs
                .iter_mut()
                .zip(caches.iter())
                .map(|(l, &(mdp, n))| format::Visage {
                    entree: l,
                    longueur: n as u64,
                    dest: Destinataires::MotDePasse(mdp.as_bytes()),
                })
                .collect();
            let principal = format::Visage {
                entree: &mut &m[..],
                longueur: m.len() as u64,
                dest: Destinataires::MotDePasse(MDP.as_bytes()),
            };
            let mut v = Vec::new();
            format::chiffrer_flux(principal, visages, &mut v).unwrap();
            v
        }
        Dest::Cles(n) => {
            let pks: Vec<_> = (0..n).map(|i| *Identite::depuis_graine(&graine(i)).cle_publique()).collect();
            format::chiffrer(&m, Destinataires::Cles(&pks)).unwrap()
        }
        Dest::VisagesCles => {
            let pk = |i: u8| *Identite::depuis_graine(&graine(i)).cle_publique();
            let pks_leurre = [pk(0), pk(1)];
            let pks_cache = [pk(VC_CACHE_CLE.0)];
            let (s0, s1) = (clair_secret(0, VC_CACHE_CLE.1), clair_secret(1, VC_CACHE_MDP.1));
            let (mut l0, mut l1) = (&s0[..], &s1[..]);
            let visages = vec![
                format::Visage { entree: &mut l0, longueur: s0.len() as u64, dest: Destinataires::Cles(&pks_cache) },
                format::Visage {
                    entree: &mut l1,
                    longueur: s1.len() as u64,
                    dest: Destinataires::MotDePasse(VC_CACHE_MDP.0.as_bytes()),
                },
            ];
            let principal =
                format::Visage { entree: &mut &m[..], longueur: m.len() as u64, dest: Destinataires::Cles(&pks_leurre) };
            let mut v = Vec::new();
            format::chiffrer_flux(principal, visages, &mut v).unwrap();
            v
        }
    })
}

fn manifeste(fichiers: &[(&Cas, Vec<u8>)]) -> String {
    let mut s = String::from(
        "{\n  \"format\": \"Janus v1, 4 étiquettes : un leurre et jusqu'à 3 visages cachés (docs/03-deux-visages.md, sur la base de docs/02-spec-v0.md)\",\n  \
         \"clair\": \"octet k = (31*k + 7) mod 256, sur clair_longueur octets\",\n  \
         \"graines\": \"identité X-Wing du destinataire i (à partir de 0) : 32 octets valant i+1\",\n  \
         \"vecteurs\": [\n",
    );
    for (n, (cas, f)) in fichiers.iter().enumerate() {
        let ouverture = match cas.dest {
            Dest::MotDePasse => format!("{{ \"type\": \"mot_de_passe\", \"valeur\": \"{MDP}\" }}"),
            Dest::Visages(caches) => {
                let v: Vec<String> = caches
                    .iter()
                    .enumerate()
                    .map(|(j, &(mdp, n))| {
                        format!(
                            "{{ \"mot_de_passe\": \"{mdp}\", \"clair\": \"octet k = (17*k + 3 + 50*{j}) mod 256\", \
                             \"clair_longueur\": {n}, \"sha256_clair\": \"{}\" }}",
                            hex_sha256(&clair_secret(j, n))
                        )
                    })
                    .collect();
                format!(
                    "{{ \"type\": \"mot_de_passe\", \"valeur\": \"{MDP}\", \"visages_caches\": [{}] }}",
                    v.join(", ")
                )
            }
            Dest::Cles(k) => {
                let g: Vec<String> = (0..k).map(|i| format!("\"{}\"", hex::encode(graine(i)))).collect();
                format!("{{ \"type\": \"identites\", \"chacune_ouvre\": [{}] }}", g.join(", "))
            }
            Dest::VisagesCles => {
                let (i, n0) = VC_CACHE_CLE;
                let (mdp, n1) = VC_CACHE_MDP;
                format!(
                    "{{ \"type\": \"identites\", \"chacune_ouvre\": [\"{}\", \"{}\"], \"visages_caches\": [\
                     {{ \"identite\": \"{}\", \"clair\": \"octet k = (17*k + 3 + 50*0) mod 256\", \"clair_longueur\": {n0}, \"sha256_clair\": \"{}\" }}, \
                     {{ \"mot_de_passe\": \"{mdp}\", \"clair\": \"octet k = (17*k + 3 + 50*1) mod 256\", \"clair_longueur\": {n1}, \"sha256_clair\": \"{}\" }}], \
                     \"plusieurs_visages\": [\"{}\", \"{}\"] }}",
                    hex::encode(graine(0)),
                    hex::encode(graine(1)),
                    hex::encode(graine(i)),
                    hex_sha256(&clair_secret(0, n0)),
                    hex_sha256(&clair_secret(1, n1)),
                    hex::encode(graine(0)),
                    hex::encode(graine(i)),
                )
            }
        };
        let m = clair(cas.longueur);
        let _ = write!(
            s,
            "    {{\n      \"nom\": \"{}\",\n      \"fichier\": \"{}.janus\",\n      \"taille\": {},\n      \
             \"sha256_fichier\": \"{}\",\n      \"ouverture\": {},\n      \"clair_longueur\": {},\n      \
             \"sha256_clair\": \"{}\"\n    }}{}\n",
            cas.nom,
            cas.nom,
            f.len(),
            hex_sha256(f),
            ouverture,
            cas.longueur,
            hex_sha256(&m),
            if n + 1 < fichiers.len() { "," } else { "" }
        );
    }
    s.push_str("  ]\n}\n");
    s
}

#[test]
fn vecteurs_reproductibles_et_ouvrables() {
    let generes: Vec<(&Cas, Vec<u8>)> = CAS.iter().map(|c| (c, generer(c))).collect();
    // Le déterminisme lui-même : deux générations identiques.
    assert_eq!(generer(&CAS[1]), generes[1].1, "génération non déterministe");

    if std::env::var("JANUS_REGENERER_VECTEURS").is_ok() {
        std::fs::create_dir_all(dossier()).unwrap();
        for (cas, f) in &generes {
            std::fs::write(dossier().join(format!("{}.janus", cas.nom)), f).unwrap();
        }
        std::fs::write(dossier().join("manifeste.json"), manifeste(&generes)).unwrap();
    }

    for (cas, f) in &generes {
        // 1. Le fichier publié est reproduit octet pour octet.
        let publie = std::fs::read(dossier().join(format!("{}.janus", cas.nom)))
            .expect("vecteurs absents : JANUS_REGENERER_VECTEURS=1 cargo test --release vecteurs");
        assert!(publie == *f, "{} : le format a changé (taille {} → {})", cas.nom, publie.len(), f.len());

        // 2. Le fichier publié s'ouvre, hors mode déterministe, avec chaque clé annoncée.
        let attendu = clair(cas.longueur);
        match cas.dest {
            Dest::MotDePasse => {
                let c = format::dechiffrer(&publie, Ouverture::MotDePasse(MDP.as_bytes())).unwrap();
                assert_eq!(&*c, &attendu[..]);
            }
            Dest::Visages(caches) => {
                let c = format::dechiffrer(&publie, Ouverture::MotDePasse(MDP.as_bytes())).unwrap();
                assert_eq!(&*c, &attendu[..], "leurre");
                for (j, &(mdp, n)) in caches.iter().enumerate() {
                    let c = format::dechiffrer(&publie, Ouverture::MotDePasse(mdp.as_bytes())).unwrap();
                    assert_eq!(&*c, &clair_secret(j, n)[..], "{} : visage caché {j}", cas.nom);
                }
            }
            Dest::Cles(n) => {
                for i in 0..n {
                    let id = [Identite::depuis_graine(&graine(i))];
                    let c = format::dechiffrer(&publie, Ouverture::Identites(&id)).unwrap();
                    assert_eq!(&*c, &attendu[..], "{} : destinataire {i}", cas.nom);
                }
                let etranger = [Identite::depuis_graine(&[0xEE; 32])];
                assert!(format::dechiffrer(&publie, Ouverture::Identites(&etranger)).is_err());
            }
            Dest::VisagesCles => {
                for i in [0, 1] {
                    let id = [Identite::depuis_graine(&graine(i))];
                    let (c, principal) = format::dechiffrer_visage(&publie, Ouverture::Identites(&id)).unwrap();
                    assert!(principal && *c == attendu[..], "{} : leurre, destinataire {i}", cas.nom);
                }
                let id = [Identite::depuis_graine(&graine(VC_CACHE_CLE.0))];
                let (c, principal) = format::dechiffrer_visage(&publie, Ouverture::Identites(&id)).unwrap();
                assert!(!principal && *c == clair_secret(0, VC_CACHE_CLE.1)[..], "{} : visage caché à clé", cas.nom);
                let c = format::dechiffrer(&publie, Ouverture::MotDePasse(VC_CACHE_MDP.0.as_bytes())).unwrap();
                assert_eq!(&*c, &clair_secret(1, VC_CACHE_MDP.1)[..], "{} : visage caché à mot de passe", cas.nom);
                let deux = [Identite::depuis_graine(&graine(0)), Identite::depuis_graine(&graine(VC_CACHE_CLE.0))];
                let r = format::dechiffrer_visage(&publie, Ouverture::Identites(&deux));
                assert!(matches!(r, Err(format::ErreurOuverture::PlusieursVisages)), "{} : plusieurs visages", cas.nom);
                let etranger = [Identite::depuis_graine(&[0xEE; 32])];
                assert!(format::dechiffrer(&publie, Ouverture::Identites(&etranger)).is_err());
                assert!(format::dechiffrer(&publie, Ouverture::MotDePasse(b"mauvais")).is_err());
            }
        }
    }
    let m = std::fs::read_to_string(dossier().join("manifeste.json")).unwrap();
    assert_eq!(m, manifeste(&generes), "manifeste désynchronisé");
}

/// Vecteurs de l'encodage texte des clés (Q7, Bech32m), dans `vecteurs/cles.json` :
/// pour chaque graine, l'identité et la clé publique attendues, caractère pour caractère.
fn manifeste_cles() -> String {
    let graines: [(&str, [u8; 32]); 3] = [
        ("32 octets valant 0x01 (destinataire 0 des vecteurs de fichiers)", graine(0)),
        ("32 octets valant 0x02 (destinataire 1)", graine(1)),
        ("octet k = k, pour k de 0 à 31", core::array::from_fn(|k| k as u8)),
    ];
    let mut s = String::from(
        "{\n  \"encodage\": \"Bech32m (BIP 350). Identité : préfixe JANUS-SECRET-KEY-, majuscules, graine X-Wing de 32 octets. \
         Clé publique : préfixe janus, minuscules, pk_M (1184 octets) suivi de pk_X (32 octets), sans limite de longueur.\",\n  \
         \"cles\": [\n",
    );
    for (n, (description, g)) in graines.iter().enumerate() {
        let id = Identite::depuis_graine(g);
        let _ = write!(
            s,
            "    {{\n      \"graine\": \"{}\",\n      \"description\": \"{description}\",\n      \"identite\": \"{}\",\n      \
             \"cle_publique_hex_sha256\": \"{}\",\n      \"cle_publique\": \"{}\"\n    }}{}\n",
            hex::encode(g),
            *crate::cles::secrete_vers_texte(&id),
            hex_sha256(id.cle_publique()),
            crate::cles::publique_vers_texte(id.cle_publique()),
            if n + 1 < graines.len() { "," } else { "" }
        );
    }
    s.push_str("  ]\n}\n");
    s
}

#[test]
fn vecteurs_des_cles() {
    let attendu = manifeste_cles();
    let chemin = dossier().join("cles.json");
    if std::env::var("JANUS_REGENERER_VECTEURS").is_ok() {
        std::fs::write(&chemin, &attendu).unwrap();
    }
    let publie = std::fs::read_to_string(&chemin)
        .expect("vecteurs absents : JANUS_REGENERER_VECTEURS=1 cargo test --release vecteurs");
    assert_eq!(publie, attendu, "l'encodage des clés a changé");
    // Le texte publié se relit vers la même paire de clés.
    for (i, g) in [graine(0), graine(1)].iter().enumerate() {
        let id = Identite::depuis_graine(g);
        let ligne = |cle: &str| {
            publie
                .lines()
                .filter(|l| l.contains(&format!("\"{cle}\"")))
                .nth(i)
                .and_then(|l| l.split('"').nth(3))
                .unwrap()
                .to_owned()
        };
        let lu = crate::cles::secrete_depuis_texte(&ligne("identite")).unwrap();
        assert_eq!(lu.cle_publique(), id.cle_publique());
        assert_eq!(&crate::cles::publique_depuis_texte(&ligne("cle_publique")).unwrap(), id.cle_publique());
    }
}
