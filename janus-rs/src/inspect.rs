//! `janus inspect` : radiographie défensive d'un fichier (cartographie, piste H).
//!
//! On lit seulement ce qu'un tiers voit déjà, sans clé ni mot de passe, et on le
//! dit en clair : l'outil qui a produit le fichier, ses destinataires, ses
//! algorithmes, la taille du clair et la part d'aléa. On ne tente aucun
//! déchiffrement et on n'écrit rien.
//!
//! Formats analysés : age, OpenPGP (gpg), ZIP, 7-Zip, LUKS, KeePass,
//! `openssl enc`, Ansible Vault, plus quelques formats non chiffrés courants.
//! Pour un fichier sans signature, on teste l'hypothèse « fichier Janus v1 ».

use crate::format::bornes_taille;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine;
use std::fmt;
use std::io::{self, Read, Seek, SeekFrom};

/// Taille de la zone lue au début du fichier pour reconnaître son format.
const FENETRE: u64 = 1 << 20;
/// Taille des blocs du test d'aléa local.
const BLOC: usize = 4096;
/// Seuil du test global : en dessous, la structure est jugée détectable.
pub const SEUIL_GLOBAL: f64 = 1e-6;
/// Seuil par bloc, plus strict car un gros fichier compte des milliers de blocs.
const SEUIL_BLOC: f64 = 1e-9;
/// Il faut au moins 5 occurrences attendues par valeur pour que le χ² soit fiable.
const TAILLE_MIN_TEST: u64 = 256 * 5;
/// Borne de lecture d'un répertoire central ZIP ou d'un en-tête 7z.
const MAX_REPERTOIRE: u64 = 16 << 20;

// ─────────────────────────────── rapport ───────────────────────────────

/// Ce que révèle un fichier à quelqu'un qui n'a aucune clé.
#[derive(Debug, Clone)]
pub struct Rapport {
    pub taille: u64,
    pub format: Option<Format>,
    pub alea: Alea,
    /// Nombre d'octets de texte lisible au début du fichier.
    pub texte_initial: usize,
    /// Seulement si aucun format n'est reconnu.
    pub janus: Option<HypotheseJanus>,
}

#[derive(Debug, Clone)]
pub struct Format {
    pub nom: String,
    pub details: Vec<String>,
    /// Ce qu'un tiers apprend, phrase par phrase.
    pub fuites: Vec<String>,
    pub destinataires: Option<usize>,
    pub clair: Option<TailleClair>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TailleClair {
    Exacte(u64),
    Environ(u64),
    Entre(u64, u64),
}

#[derive(Debug, Clone)]
pub struct Alea {
    /// Entropie de Shannon de la distribution des octets, en bits par octet.
    pub entropie: f64,
    /// χ² à 255 degrés de liberté sur les 256 valeurs d'octet.
    pub chi2: f64,
    pub p: f64,
    /// Faux si le fichier est trop court pour un test fiable.
    pub fiable: bool,
    pub blocs: u64,
    pub blocs_structures: u64,
    /// Positions des premiers blocs non aléatoires.
    pub premiers_structures: Vec<u64>,
}

impl Alea {
    /// Vrai si aucun test ne distingue le fichier de l'aléa.
    pub fn aleatoire(&self) -> bool {
        self.fiable && self.p >= SEUIL_GLOBAL && self.blocs_structures == 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HypotheseJanus {
    Exclue(&'static str),
    Compatible { clair_min: u64, clair_max: u64 },
}

// ─────────────────────────────── entrée ───────────────────────────────

/// Radiographie complète. Lit tout le fichier une fois (pour l'aléa), plus
/// quelques zones ciblées (début, fin, répertoires).
pub fn inspecter<R: Read + Seek>(r: &mut R) -> io::Result<Rapport> {
    let taille = r.seek(SeekFrom::End(0))?;
    r.seek(SeekFrom::Start(0))?;
    let alea = mesurer_alea(r)?;
    let tete = lire_zone(r, 0, taille.min(FENETRE))?;
    let texte_initial = tete.iter().take_while(|&&b| imprimable(b)).count();
    let format = identifier(r, taille, &tete)?;
    let janus = format.is_none().then(|| hypothese_janus(taille, &alea));
    Ok(Rapport { taille, format, alea, texte_initial, janus })
}

fn lire_zone<R: Read + Seek>(r: &mut R, debut: u64, n: u64) -> io::Result<Vec<u8>> {
    r.seek(SeekFrom::Start(debut))?;
    let mut v = vec![0u8; n as usize];
    r.read_exact(&mut v)?;
    Ok(v)
}

fn imprimable(b: u8) -> bool {
    matches!(b, 0x20..=0x7e | b'\n' | b'\r' | b'\t')
}

// ─────────────────────────────── aléa ───────────────────────────────

fn mesurer_alea<R: Read>(r: &mut R) -> io::Result<Alea> {
    let mut global = [0u64; 256];
    let mut bloc = [0u64; 256];
    let mut dans_bloc = 0usize;
    let mut position = 0u64;
    let (mut blocs, mut structures, mut premiers) = (0u64, 0u64, Vec::new());
    let mut tampon = vec![0u8; FENETRE as usize];
    loop {
        let n = r.read(&mut tampon)?;
        if n == 0 {
            break;
        }
        let mut reste = &tampon[..n];
        while !reste.is_empty() {
            let k = (BLOC - dans_bloc).min(reste.len());
            for &b in &reste[..k] {
                bloc[b as usize] += 1;
            }
            dans_bloc += k;
            position += k as u64;
            reste = &reste[k..];
            if dans_bloc == BLOC {
                blocs += 1;
                if p_chi2_255(chi2(&bloc, BLOC as u64)) < SEUIL_BLOC {
                    structures += 1;
                    if premiers.len() < 5 {
                        premiers.push(position - BLOC as u64);
                    }
                }
                for (g, b) in global.iter_mut().zip(bloc.iter_mut()) {
                    *g += *b;
                    *b = 0;
                }
                dans_bloc = 0;
            }
        }
    }
    for (g, b) in global.iter_mut().zip(bloc.iter()) {
        *g += *b;
    }
    let c = chi2(&global, position);
    let entropie = global
        .iter()
        .filter(|&&n| n > 0)
        .map(|&n| {
            let p = n as f64 / position as f64;
            -p * p.log2()
        })
        .sum();
    Ok(Alea {
        entropie,
        chi2: c,
        p: p_chi2_255(c),
        fiable: position >= TAILLE_MIN_TEST,
        blocs,
        blocs_structures: structures,
        premiers_structures: premiers,
    })
}

fn chi2(h: &[u64; 256], n: u64) -> f64 {
    if n == 0 {
        return 0.0;
    }
    let e = n as f64 / 256.0;
    h.iter().map(|&o| (o as f64 - e).powi(2) / e).sum()
}

/// p-valeur d'un χ² à 255 degrés de liberté (approximation de Wilson–Hilferty,
/// très précise pour un tel nombre de degrés de liberté).
pub fn p_chi2_255(c: f64) -> f64 {
    let k = 255.0;
    let v = 2.0 / (9.0 * k);
    let z = ((c / k).cbrt() - (1.0 - v)) / v.sqrt();
    0.5 * erfc(z / std::f64::consts::SQRT_2)
}

/// Fonction d'erreur complémentaire (Numerical Recipes, erreur relative < 1,2·10⁻⁷).
fn erfc(x: f64) -> f64 {
    let z = x.abs();
    let t = 1.0 / (1.0 + 0.5 * z);
    let r = t * (-z * z - 1.265_512_23
        + t * (1.000_023_68
            + t * (0.374_091_96
                + t * (0.096_784_18
                    + t * (-0.186_288_06
                        + t * (0.278_868_07
                            + t * (-1.135_203_98 + t * (1.488_515_87 + t * (-0.822_152_23 + t * 0.170_872_77)))))))))
        .exp();
    if x >= 0.0 {
        r
    } else {
        2.0 - r
    }
}

// ─────────────────────────────── Janus ───────────────────────────────

fn hypothese_janus(taille: u64, alea: &Alea) -> HypotheseJanus {
    match plage_clair_janus(taille) {
        None => HypotheseJanus::Exclue("aucun fichier Janus v1 ne peut avoir cette taille"),
        Some(_) if !alea.aleatoire() => {
            HypotheseJanus::Exclue("son contenu n'est pas aléatoire, alors qu'un fichier Janus l'est entièrement")
        }
        Some((clair_min, clair_max)) => HypotheseJanus::Compatible { clair_min, clair_max },
    }
}

/// Longueurs de clair compatibles avec un fichier Janus v1 de taille `f` :
/// toutes les L dont le seau de taille [X, X + masque(X)], X = PADMÉ(Ref(L)),
/// contient f (spec, § 6.2). Les deux bornes croissent avec L.
pub fn plage_clair_janus(f: u64) -> Option<(u64, u64)> {

    let reference = |l: u64| bornes_taille(l).0;
    let plafond = |l: u64| bornes_taille(l).1;
    if reference(0) > f {
        return None;
    }
    // L_max : la plus grande L dont le seau commence au plus à f (borne croissante).
    let (mut bas, mut haut) = (0u64, f);
    while bas < haut {
        let m = bas + (haut - bas).div_ceil(2);
        if reference(m) <= f {
            bas = m;
        } else {
            haut = m - 1;
        }
    }
    let l_max = bas;
    if plafond(l_max) < f {
        return None;
    }
    // L_min : la plus petite L dont le seau finit au moins à f (croissante aussi).
    let (mut bas, mut haut) = (0u64, l_max);
    while bas < haut {
        let m = bas + (haut - bas) / 2;
        if plafond(m) >= f {
            haut = m;
        } else {
            bas = m + 1;
        }
    }
    Some((bas, l_max))
}

// ─────────────────────────────── identification ───────────────────────────────

fn identifier<R: Read + Seek>(r: &mut R, taille: u64, tete: &[u8]) -> io::Result<Option<Format>> {
    if let Some(f) = age(tete, taille) {
        return Ok(Some(f));
    }
    if let Some(f) = openpgp(tete, taille) {
        return Ok(Some(f));
    }
    if (tete.starts_with(b"PK\x03\x04") || tete.starts_with(b"PK\x05\x06"))
        && let Some(f) = zip(r, taille)? {
            return Ok(Some(f));
        }
    if tete.starts_with(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) && tete.len() >= 32 {
        return Ok(Some(sept_zip(r, taille, tete)?));
    }
    Ok(signature_simple(tete, taille))
}

fn format(nom: impl Into<String>) -> Format {
    Format { nom: nom.into(), details: Vec::new(), fuites: Vec::new(), destinataires: None, clair: None }
}

fn le16(d: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_le_bytes(d.get(i..i + 2)?.try_into().ok()?))
}
fn le32(d: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_le_bytes(d.get(i..i + 4)?.try_into().ok()?))
}
fn le64(d: &[u8], i: usize) -> Option<u64> {
    Some(u64::from_le_bytes(d.get(i..i + 8)?.try_into().ok()?))
}
fn be16(d: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes(d.get(i..i + 2)?.try_into().ok()?))
}
fn be32(d: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_be_bytes(d.get(i..i + 4)?.try_into().ok()?))
}
/// Chaîne C de longueur fixe (terminée par des zéros).
fn chaine_c(d: &[u8]) -> String {
    let fin = d.iter().position(|&b| b == 0).unwrap_or(d.len());
    String::from_utf8_lossy(&d[..fin]).into_owned()
}

/// Décode une armure ASCII « -----BEGIN <label>----- ». Renvoie les octets et
/// un booléen vrai si la ligne de fin a été vue (donc la taille est connue).
fn desarmurer(t: &[u8], label: &str) -> Option<(Vec<u8>, bool)> {
    let debut = t.iter().position(|b| !b.is_ascii_whitespace() && *b != 0xEF && *b != 0xBB && *b != 0xBF)?;
    let t = &t[debut..];
    let entete = format!("-----BEGIN {label}-----");
    if !t.starts_with(entete.as_bytes()) {
        return None;
    }
    let texte = String::from_utf8_lossy(t);
    let mut b64 = String::new();
    let mut complet = false;
    let mut corps = false;
    for l in texte.lines().skip(1) {
        let l = l.trim();
        if l.starts_with("-----END") {
            complet = true;
            break;
        }
        if !corps && l.contains(": ") {
            continue; // en-têtes d'armure (« Version: … »)
        }
        if l.is_empty() {
            corps = true;
            continue;
        }
        if l.starts_with('=') && l.len() == 5 {
            continue; // somme de contrôle CRC-24 d'OpenPGP
        }
        if !l.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=')) {
            return None;
        }
        corps = true;
        b64.push_str(l);
    }
    if !complet {
        b64.truncate(b64.len() / 4 * 4);
    }
    let octets = STANDARD.decode(&b64).or_else(|_| STANDARD_NO_PAD.decode(b64.trim_end_matches('=')));
    Some((octets.ok()?, complet))
}

// ─────────────────────────────── age ───────────────────────────────

const AGE_MAGIC: &[u8] = b"age-encryption.org/v1\n";
const AGE_MORCEAU: u64 = 65_536 + 16;

fn age(t: &[u8], taille: u64) -> Option<Format> {
    if let Some((octets, complet)) = desarmurer(t, "AGE ENCRYPTED FILE") {
        let mut f = age_binaire(&octets, complet.then_some(octets.len() as u64))?;
        f.nom = "age v1, armure ASCII".into();
        f.fuites.insert(0, "L'armure annonce l'outil en toutes lettres : « BEGIN AGE ENCRYPTED FILE ».".into());
        return Some(f);
    }
    age_binaire(t, Some(taille))
}

fn age_binaire(d: &[u8], total: Option<u64>) -> Option<Format> {
    if !d.starts_with(AGE_MAGIC) {
        return None;
    }
    let ligne_suivante = |pos: usize| -> Option<(&[u8], usize)> {
        let fin = pos + d.get(pos..)?.iter().position(|&b| b == b'\n')?;
        Some((&d[pos..fin], fin + 1))
    };
    let mut pos = AGE_MAGIC.len();
    let mut strophes: Vec<Vec<String>> = Vec::new();
    loop {
        let (ligne, suite) = ligne_suivante(pos)?;
        pos = suite;
        let ligne = std::str::from_utf8(ligne).ok()?;
        if let Some(args) = ligne.strip_prefix("-> ") {
            strophes.push(args.split(' ').map(String::from).collect());
            // Corps : lignes base64 de 64 colonnes, la dernière plus courte.
            loop {
                let (corps, suite) = ligne_suivante(pos)?;
                pos = suite;
                if corps.len() < 64 {
                    break;
                }
            }
        } else if ligne.starts_with("---") {
            break;
        } else {
            return None;
        }
        if strophes.len() > 10_000 {
            return None;
        }
    }

    let mut f = format("age v1");
    f.destinataires = Some(strophes.len());
    f.details.push(format!("En-tête : {} octets, {} strophe(s)", pos, strophes.len()));
    f.fuites.push("L'outil : le fichier commence par « age-encryption.org/v1 » en clair.".into());
    f.fuites.push(format!(
        "Le nombre de destinataires : {} (une strophe par destinataire).",
        strophes.len()
    ));
    for (i, s) in strophes.iter().enumerate() {
        let type_ = s.first().map(String::as_str).unwrap_or("");
        let desc = match type_ {
            "X25519" => "clé X25519. Sa part éphémère est un point de courbe écrit en base64 lisible : \
                         elle se distingue de l'aléa"
                .to_string(),
            "scrypt" => format!(
                "mot de passe, dérivé par scrypt avec un facteur de travail 2^{}",
                s.get(2).map(String::as_str).unwrap_or("?")
            ),
            "ssh-ed25519" | "ssh-rsa" => format!(
                "clé SSH ({type_}). L'étiquette « {} » (4 octets du SHA-256 de la clé) permet à quiconque \
                 connaît la clé publique SSH du destinataire, publiée par exemple sur GitHub, de le reconnaître",
                s.get(1).map(String::as_str).unwrap_or("?")
            ),
            "mlkem768x25519" => "clé hybride post-quantique ML-KEM-768 + X25519".to_string(),
            autre => format!("greffon « {autre} »"),
        };
        f.details.push(format!("Destinataire {} : {desc}", i + 1));
    }
    f.fuites.push("Le type de chaque destinataire (clé, mot de passe, clé SSH, greffon).".into());
    if let Some(total) = total {
        let charge = total.checked_sub(pos as u64 + 16)?;
        if charge < 16 {
            return None;
        }
        let morceaux = charge.div_ceil(AGE_MORCEAU);
        let n = charge - 16 * morceaux;
        f.clair = Some(TailleClair::Exacte(n));
        f.fuites.push(format!("La taille exacte du clair : {} octets. age n'ajoute aucun bourrage.", nombre(n)));
    }
    Some(f)
}

// ─────────────────────────────── OpenPGP ───────────────────────────────

fn nom_cle_publique(a: u8) -> Option<&'static str> {
    Some(match a {
        1..=3 => "RSA",
        16 => "ElGamal",
        18 => "ECDH",
        25 => "X25519",
        26 => "X448",
        35 => "ML-KEM-768 + X25519 (post-quantique)",
        36 => "ML-KEM-1024 + X448 (post-quantique)",
        _ => return None,
    })
}

fn nom_chiffre(a: u8) -> Option<&'static str> {
    Some(match a {
        1 => "IDEA",
        2 => "TripleDES",
        3 => "CAST5",
        4 => "Blowfish",
        7 => "AES-128",
        8 => "AES-192",
        9 => "AES-256",
        10 => "Twofish",
        11 => "Camellia-128",
        12 => "Camellia-192",
        13 => "Camellia-256",
        _ => return None,
    })
}

fn nom_aead(a: u8) -> &'static str {
    match a {
        1 => "EAX",
        2 => "OCB",
        3 => "GCM",
        _ => "AEAD inconnu",
    }
}

fn nom_hachage(a: u8) -> &'static str {
    match a {
        1 => "MD5",
        2 => "SHA-1",
        3 => "RIPEMD-160",
        8 => "SHA-256",
        9 => "SHA-384",
        10 => "SHA-512",
        11 => "SHA-224",
        12 => "SHA3-256",
        14 => "SHA3-512",
        _ => "hachage inconnu",
    }
}

/// Spécificateur S2K (dérivation de la clé depuis le mot de passe).
fn s2k(b: &[u8]) -> Option<String> {
    Some(match *b.first()? {
        0 => format!("S2K simple ({}, sans sel ni itérations)", nom_hachage(*b.get(1)?)),
        1 => format!("S2K salé ({}, sans itérations)", nom_hachage(*b.get(1)?)),
        3 => {
            let c = *b.get(10)? as u64;
            let compte = (16 + (c & 15)) << ((c >> 4) + 6);
            format!(
                "S2K itéré et salé : {} appliqué à {} octets. Rapide sur carte graphique, car il n'exige pas de mémoire",
                nom_hachage(*b.get(1)?),
                nombre(compte)
            )
        }
        4 => {
            let (t, p, m) = (*b.get(17)?, *b.get(18)?, *b.get(19)?);
            format!("Argon2 (t = {t}, p = {p}, mémoire 2^{m} Kio)")
        }
        _ => return None,
    })
}

fn skesk(b: &[u8]) -> Option<String> {
    match *b.first()? {
        4 => Some(format!("{}, {}", nom_chiffre(*b.get(1)?)?, s2k(b.get(2..)?)?)),
        5 => Some(format!("{} {}, {}", nom_chiffre(*b.get(1)?)?, nom_aead(*b.get(2)?), s2k(b.get(3..)?)?)),
        6 => Some(format!("{} {}, {}", nom_chiffre(*b.get(2)?)?, nom_aead(*b.get(3)?), s2k(b.get(5..)?)?)),
        _ => None,
    }
}

struct Paquet {
    tag: u8,
    entete: usize,
    /// None : longueur partielle ou indéterminée (flux).
    longueur: Option<usize>,
}

fn paquet(d: &[u8], pos: usize) -> Option<Paquet> {
    let b = *d.get(pos)?;
    if b & 0x80 == 0 {
        return None;
    }
    if b & 0x40 != 0 {
        let o1 = *d.get(pos + 1)? as usize;
        let (entete, longueur) = match o1 {
            0..=191 => (2, Some(o1)),
            192..=223 => (3, Some(((o1 - 192) << 8) + *d.get(pos + 2)? as usize + 192)),
            255 => (6, Some(be32(d, pos + 2)? as usize)),
            _ => (2, None),
        };
        Some(Paquet { tag: b & 0x3f, entete, longueur })
    } else {
        let (entete, longueur) = match b & 3 {
            0 => (2, Some(*d.get(pos + 1)? as usize)),
            1 => (3, Some(be16(d, pos + 1)? as usize)),
            2 => (5, Some(be32(d, pos + 1)? as usize)),
            _ => (1, None),
        };
        Some(Paquet { tag: (b >> 2) & 0x0f, entete, longueur })
    }
}

fn openpgp(t: &[u8], taille: u64) -> Option<Format> {
    if let Some((octets, complet)) = desarmurer(t, "PGP MESSAGE") {
        let mut f = pgp_binaire(&octets, complet.then_some(octets.len() as u64))?;
        f.nom = "OpenPGP (gpg), armure ASCII".into();
        f.fuites.insert(0, "L'armure annonce l'outil en toutes lettres : « BEGIN PGP MESSAGE ».".into());
        return Some(f);
    }
    pgp_binaire(t, Some(taille))
}

/// Exige au moins un paquet de clé de session (PKESK ou SKESK) suivi d'un
/// paquet de données chiffrées, avec des numéros de version valides : un
/// fichier aléatoire n'y satisfait presque jamais.
fn pgp_binaire(d: &[u8], total: Option<u64>) -> Option<Format> {
    let mut f = format("OpenPGP (gpg)");
    let mut cles = 0usize;
    let mut mots_de_passe = 0usize;
    let mut pos = 0usize;
    loop {
        let p = paquet(d, pos)?;
        let corps = pos + p.entete;
        match p.tag {
            1 => {
                let b = d.get(corps..corps + p.longueur?)?;
                let (qui, algo) = match *b.first()? {
                    3 => {
                        let id = b.get(1..9)?;
                        let qui = if id.iter().all(|&x| x == 0) {
                            None
                        } else {
                            Some(format!("identifiant de clé 0x{}", hex::encode_upper(id)))
                        };
                        (qui, *b.get(9)?)
                    }
                    6 => {
                        let n = *b.get(1)? as usize;
                        let qui = (n > 0).then(|| -> Option<String> {
                            Some(format!("empreinte de clé {}", hex::encode_upper(b.get(3..2 + n)?)))
                        });
                        (qui.flatten(), *b.get(2 + n)?)
                    }
                    _ => return None,
                };
                let algo = nom_cle_publique(algo)?;
                cles += 1;
                match qui {
                    Some(q) => {
                        f.details.push(format!("Destinataire {} : {q} ({algo})", cles + mots_de_passe));
                        f.fuites.push(format!(
                            "L'identité d'un destinataire : {q}. Elle désigne une clé publique précise, souvent \
                             publiée sur un serveur de clés avec un nom et une adresse."
                        ));
                    }
                    None => {
                        f.details.push(format!("Destinataire {} : masqué ({algo})", cles + mots_de_passe));
                        f.fuites.push(format!(
                            "Un destinataire masqué (identifiant nul, option --throw-keyids) : son identité est \
                             cachée, mais pas son algorithme ({algo})."
                        ));
                    }
                }
            }
            3 => {
                let b = d.get(corps..corps + p.longueur?)?;
                let desc = skesk(b)?;
                mots_de_passe += 1;
                f.details.push(format!("Destinataire {} : mot de passe ({desc})", cles + mots_de_passe));
                f.fuites.push(format!("L'usage d'un mot de passe, et comment il est protégé : {desc}."));
            }
            9 | 18 | 20 => {
                if cles + mots_de_passe == 0 {
                    return None;
                }
                let b = d.get(corps..)?;
                let donnees = match p.longueur {
                    Some(l) => {
                        if let Some(t) = total
                            && (corps + l) as u64 != t {
                                return None;
                            }
                        Some(l as u64)
                    }
                    None => total.and_then(|t| t.checked_sub(corps as u64)),
                };
                // (description, surcoût fixe, taille des morceaux AEAD)
                let (desc, fixe, morceau): (String, u64, Option<u64>) = match (p.tag, *b.first()?) {
                    (18, 1) => ("paquet SEIPD v1 (mode CFB, intégrité par MDC/SHA-1)".into(), 1 + 18 + 22, None),
                    (18, 2) => (
                        format!(
                            "paquet SEIPD v2 ({}, {})",
                            nom_chiffre(*b.get(1)?)?,
                            nom_aead(*b.get(2)?)
                        ),
                        4 + 32,
                        Some(1u64 << (*b.get(3)? as u64 + 6).min(62)),
                    ),
                    (20, 1) => (
                        format!(
                            "paquet AEAD propre à gpg 2.3+ ({}, {})",
                            nom_chiffre(*b.get(1)?)?,
                            nom_aead(*b.get(2)?)
                        ),
                        4 + 16,
                        Some(1u64 << (*b.get(3)? as u64 + 6).min(62)),
                    ),
                    (9, _) => {
                        f.fuites.push(
                            "⚠ Un paquet SED, sans aucune protection d'intégrité : un attaquant peut modifier le \
                             message sans être détecté (famille d'attaques EFAIL)."
                                .into(),
                        );
                        ("paquet SED (ancien, sans intégrité)".into(), 18, None)
                    }
                    _ => return None,
                };
                match donnees {
                    Some(n) => {
                        f.details.push(format!("Données chiffrées : {desc}, {} octets", nombre(n)));
                        let interieur = match morceau {
                            None => n.saturating_sub(fixe),
                            Some(m) => {
                                let utile = n.saturating_sub(fixe + 16);
                                utile.saturating_sub(16 * utile.div_ceil(m + 16))
                            }
                        };
                        f.clair = Some(TailleClair::Environ(interieur));
                        f.fuites.push(format!(
                            "La taille du clair, à quelques octets près : environ {} octets, compression \
                             éventuelle, nom de fichier et date compris. OpenPGP n'ajoute aucun bourrage.",
                            nombre(interieur)
                        ));
                    }
                    None => f.details.push(format!("Données chiffrées : {desc}")),
                }
                break;
            }
            _ => return None,
        }
        pos = corps + p.longueur?;
        if cles + mots_de_passe > 10_000 {
            return None;
        }
    }
    let n = cles + mots_de_passe;
    f.destinataires = Some(n);
    f.fuites.insert(0, "L'outil : la structure OpenPGP se reconnaît dès le premier octet.".into());
    f.fuites.insert(1, format!("Le nombre de destinataires : {n}."));
    Some(f)
}

// ─────────────────────────────── ZIP ───────────────────────────────

fn date_dos(date: u16, heure: u16) -> String {
    format!(
        "{:02}/{:02}/{} {:02}:{:02}",
        date & 31,
        (date >> 5) & 15,
        1980 + (date >> 9),
        heure >> 11,
        (heure >> 5) & 63
    )
}

fn zip<R: Read + Seek>(r: &mut R, taille: u64) -> io::Result<Option<Format>> {
    let n = taille.min(65_557);
    let queue = lire_zone(r, taille - n, n)?;
    let Some(i) = queue.windows(4).rposition(|w| w == b"PK\x05\x06") else {
        return Ok(None);
    };
    let e = &queue[i..];
    let (Some(nb), Some(cd_taille), Some(cd_debut)) = (le16(e, 10), le32(e, 12), le32(e, 16)) else {
        return Ok(None);
    };
    let mut f = format("ZIP");
    f.fuites.push("L'outil : la signature « PK » ouvre le fichier.".into());
    if nb == 0xFFFF || cd_debut == 0xFFFF_FFFF {
        f.details.push("Archive ZIP64 : répertoire non analysé.".into());
        return Ok(Some(f));
    }
    let (cd_debut, cd_taille) = (cd_debut as u64, cd_taille as u64);
    if cd_debut + cd_taille > taille || cd_taille > MAX_REPERTOIRE {
        return Ok(None);
    }
    let cd = lire_zone(r, cd_debut, cd_taille)?;

    let (mut fichiers, mut chiffres, mut zipcrypto, mut crc_visibles, mut total) = (0usize, 0, 0, 0, 0u64);
    let mut pos = 0usize;
    while cd.get(pos..pos + 4) == Some(b"PK\x01\x02") {
        let champ = |o: usize| le16(&cd, pos + o).unwrap_or(0);
        let (drapeaux, methode, heure, date) = (champ(8), champ(10), champ(12), champ(14));
        let crc = le32(&cd, pos + 16).unwrap_or(0);
        let taille_clair = le32(&cd, pos + 24).unwrap_or(0) as u64;
        let (ln, lx, lc) = (champ(28) as usize, champ(30) as usize, champ(32) as usize);
        let Some(nom) = cd.get(pos + 46..pos + 46 + ln) else { break };
        let nom = String::from_utf8_lossy(nom);
        let extra = cd.get(pos + 46 + ln..pos + 46 + ln + lx).unwrap_or(&[]);
        pos += 46 + ln + lx + lc;
        if nom.ends_with('/') {
            continue;
        }
        fichiers += 1;
        total += taille_clair;
        let chiffrement = if drapeaux & 1 == 0 {
            "non chiffré".to_string()
        } else if drapeaux & 0x40 != 0 {
            chiffres += 1;
            "chiffrement fort PKWARE".into()
        } else if methode == 99 {
            chiffres += 1;
            // Champ supplémentaire 0x9901 de WinZip AES.
            let mut desc = "AES (WinZip)".to_string();
            let mut k = 0;
            while k + 4 <= extra.len() {
                let (id, l) = (le16(extra, k).unwrap_or(0), le16(extra, k + 2).unwrap_or(0) as usize);
                if id == 0x9901 && l >= 7 {
                    let version = le16(extra, k + 4).unwrap_or(0);
                    let bits = match extra.get(k + 8) {
                        Some(1) => "128",
                        Some(2) => "192",
                        _ => "256",
                    };
                    desc = format!("AES-{bits} (WinZip AE-{version})");
                    if version == 1 {
                        crc_visibles += 1;
                    }
                }
                k += 4 + l;
            }
            desc
        } else {
            chiffres += 1;
            zipcrypto += 1;
            if crc != 0 {
                crc_visibles += 1;
            }
            "ZipCrypto".into()
        };
        if fichiers <= 12 {
            f.details.push(format!(
                "{nom} : {}, modifié le {}, {chiffrement}",
                octets(taille_clair),
                date_dos(date, heure)
            ));
        }
    }
    if fichiers > 12 {
        f.details.push(format!("… et {} autres fichiers", fichiers - 12));
    }
    f.clair = Some(TailleClair::Exacte(total));
    if chiffres == 0 {
        f.fuites.push("Archive non chiffrée : tout est lisible.".into());
        return Ok(Some(f));
    }
    f.fuites.push(format!(
        "Les noms des {fichiers} fichiers, en clair : ZIP ne chiffre que leur contenu, jamais leur nom."
    ));
    f.fuites.push("La taille exacte de chaque fichier avant compression, et sa date de modification.".into());
    if zipcrypto > 0 {
        f.fuites.push(
            "⚠ ZipCrypto est cassé : 12 octets de clair connus suffisent pour retrouver les clés internes \
             (attaque de Biham et Kocher, outil bkcrack). Or le début d'un .docx ou d'un .png est connu d'avance."
                .into(),
        );
    }
    if crc_visibles > 0 {
        f.fuites.push(
            "Le CRC-32 du clair de chaque fichier : il permet de vérifier une supposition sur le contenu, \
             et de deviner un petit fichier par essais successifs."
                .into(),
        );
    }
    Ok(Some(f))
}

// ─────────────────────────────── 7-Zip ───────────────────────────────

fn sept_zip<R: Read + Seek>(r: &mut R, taille: u64, tete: &[u8]) -> io::Result<Format> {
    let mut f = format("7-Zip");
    f.fuites.push("L'outil : la signature 7z ouvre le fichier.".into());
    let (decalage, longueur) = (le64(tete, 12).unwrap_or(u64::MAX), le64(tete, 20).unwrap_or(u64::MAX));
    let debut = 32u64.saturating_add(decalage);
    if longueur > MAX_REPERTOIRE || debut.saturating_add(longueur) > taille {
        f.details.push("En-tête de fin illisible.".into());
        return Ok(f);
    }
    let entete = lire_zone(r, debut, longueur)?;
    // 0x17 : en-tête « encodé ». S'il passe par le codeur AES (06 F1 07 01),
    // il est chiffré ; sinon il est seulement compressé, donc lisible par tous.
    let aes = entete.windows(4).any(|w| w == [0x06, 0xF1, 0x07, 0x01]);
    f.details.push(format!("En-tête de fin : {} octets", nombre(longueur)));
    if entete.first() == Some(&0x17) && aes {
        f.details.push("En-tête chiffré (option -mhe=on)".into());
        f.fuites.push(
            "La taille de l'en-tête, qui donne une idée du nombre de fichiers. Leurs noms et tailles sont \
             chiffrés (option -mhe=on)."
                .into(),
        );
    } else {
        f.details.push("En-tête non chiffré".into());
        f.fuites.push(
            "Les noms, tailles et dates de chaque fichier : l'en-tête n'est pas chiffré, `7z l` les affiche \
             sans mot de passe, même si le contenu est chiffré. Il fallait l'option -mhe=on."
                .into(),
        );
    }
    Ok(f)
}

// ─────────────────────────────── signatures simples ───────────────────────────────

fn signature_simple(t: &[u8], taille: u64) -> Option<Format> {
    if t.starts_with(b"LUKS\xBA\xBE") {
        let v = be16(t, 6)?;
        let mut f = format(format!("LUKS{v} (disque chiffré Linux)"));
        f.fuites.push("L'outil : la signature « LUKS » ouvre le volume.".into());
        if v == 1 {
            let (algo, mode, hach) = (chaine_c(t.get(8..40)?), chaine_c(t.get(40..72)?), chaine_c(t.get(72..104)?));
            let uuid = chaine_c(t.get(168..208)?);
            let actifs = (0..8).filter(|i| be32(t, 208 + 48 * i) == Some(0x00AC_71F3)).count();
            f.details.push(format!("Chiffrement : {algo}-{mode}, hachage {hach}"));
            f.details.push(format!("UUID : {uuid}"));
            f.details.push(format!("Emplacements de clé actifs : {actifs} sur 8"));
            f.fuites.push(format!("Les algorithmes : {algo}-{mode} et {hach}."));
            f.fuites.push("L'UUID du volume, qui le suit d'une machine à l'autre.".into());
            f.fuites.push(format!("Le nombre de phrases de passe ou de clés enregistrées : {actifs}."));
        } else {
            let label = chaine_c(t.get(24..72)?);
            let uuid = chaine_c(t.get(168..208)?);
            f.details.push(format!("Étiquette : « {label} », UUID : {uuid}"));
            f.fuites.push("L'étiquette et l'UUID du volume.".into());
            f.fuites.push(
                "Un en-tête JSON, à partir de l'octet 4096, qui décrit en clair les algorithmes, les paramètres \
                 Argon2 et le nombre d'emplacements de clé."
                    .into(),
            );
        }
        return Some(f);
    }
    if t.starts_with(&[0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5]) {
        let mut f = format(format!("KeePass KDBX {}.{}", le16(t, 10)?, le16(t, 8)?));
        f.fuites.push("L'outil : la signature KeePass ouvre le fichier.".into());
        f.fuites.push(
            "L'en-tête décrit en clair l'algorithme de chiffrement et les paramètres de dérivation de clé."
                .into(),
        );
        return Some(f);
    }
    if t.starts_with(b"Salted__") && t.len() >= 16 {
        let mut f = format("openssl enc");
        let n = taille - 16;
        f.details.push(format!("Sel : {}", hex::encode(&t[8..16])));
        f.fuites.push("L'outil : le fichier commence par « Salted__ ».".into());
        f.fuites.push(
            "Aucun algorithme n'est indiqué et aucune authentification n'est prévue : un fichier modifié se \
             déchiffre en un clair altéré, sans alerte."
                .into(),
        );
        f.clair = Some(if n.is_multiple_of(16) && n > 0 { TailleClair::Entre(n - 16, n - 1) } else { TailleClair::Exacte(n) });
        f.fuites.push("La taille du clair, au bloc de 16 octets près.".into());
        return Some(f);
    }
    if t.starts_with(b"$ANSIBLE_VAULT;") {
        let ligne = t.split(|&b| b == b'\n').next().unwrap_or(t);
        let mut f = format("Ansible Vault");
        f.details.push(format!("En-tête : {}", String::from_utf8_lossy(ligne).trim()));
        f.fuites.push("L'outil, sa version, l'algorithme et parfois l'étiquette du coffre, en clair.".into());
        return Some(f);
    }
    // Signatures d'au moins 4 octets : un fichier aléatoire ne commence par
    // l'une d'elles qu'avec une probabilité de l'ordre de 2⁻³².
    let non_chiffre: &[(&[u8], &str)] = &[
        (b"\x89PNG\r\n\x1a\n", "image PNG"),
        (b"\xFF\xD8\xFF\xE0", "image JPEG"),
        (b"\xFF\xD8\xFF\xE1", "image JPEG"),
        (b"\xFF\xD8\xFF\xDB", "image JPEG"),
        (b"%PDF-", "document PDF"),
        (b"\x1F\x8B\x08\x00", "archive gzip"),
        (b"\x1F\x8B\x08\x08", "archive gzip"),
        (b"\x28\xB5\x2F\xFD", "archive zstd"),
        (b"\xFD7zXZ\x00", "archive xz"),
        (b"\x7FELF", "exécutable ELF"),
        (b"SQLite format 3\x00", "base SQLite"),
        (b"-----BEGIN PGP SIGNED MESSAGE-----", "message OpenPGP signé, non chiffré"),
        (b"-----BEGIN PGP PUBLIC KEY BLOCK-----", "clé publique OpenPGP"),
    ];
    // Exécutable Windows : « MZ » seul est trop court, on suit le pointeur vers « PE\0\0 ».
    let pe = t.starts_with(b"MZ")
        && le32(t, 0x3C).is_some_and(|o| t.get(o as usize..o as usize + 4) == Some(b"PE\0\0"));
    let bzip2 = t.starts_with(b"BZh") && t.get(4..10) == Some(&[0x31, 0x41, 0x59, 0x26, 0x53, 0x59]);
    let speciaux = [(pe, "exécutable Windows"), (bzip2, "archive bzip2")];
    let trouve = non_chiffre
        .iter()
        .find(|(m, _)| t.starts_with(m))
        .map(|(_, n)| *n)
        .or_else(|| speciaux.iter().find(|(ok, _)| *ok).map(|(_, n)| *n));
    if let Some(nom) = trouve {
        let mut f = format(nom);
        f.fuites.push("Format non chiffré : son contenu est lisible par tous.".into());
        return Some(f);
    }
    let texte = match std::str::from_utf8(t) {
        Ok(_) => true,
        Err(e) => e.error_len().is_none() && e.valid_up_to() + 4 >= t.len(),
    };
    // 16 octets au moins : 16 octets aléatoires sont tous imprimables avec une
    // probabilité d'environ 2·10⁻⁷.
    if t.len() >= 16 && texte && t.iter().all(|&b| b >= 0x20 || matches!(b, b'\n' | b'\r' | b'\t')) {
        let mut f = format("texte");
        f.fuites.push("Texte en clair : son contenu est lisible par tous.".into());
        return Some(f);
    }
    None
}

// ─────────────────────────────── affichage ───────────────────────────────

/// 1234567 → « 1 234 567 ».
pub fn nombre(n: u64) -> String {
    let s = n.to_string();
    let mut r = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            r.push(' ');
        }
        r.push(c);
    }
    r
}

/// « 1 octet », « 0 octet », « 14 octets » (accord à la française).
fn octets(n: u64) -> String {
    format!("{} octet{}", nombre(n), if n >= 2 { "s" } else { "" })
}

fn decimal(x: f64, chiffres: usize) -> String {
    format!("{x:.chiffres$}").replace('.', ",")
}

impl fmt::Display for TailleClair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            TailleClair::Exacte(n) => write!(f, "exactement {} octets", nombre(n)),
            TailleClair::Environ(n) => write!(f, "environ {} octets", nombre(n)),
            TailleClair::Entre(a, b) => write!(f, "entre {} et {} octets", nombre(a), nombre(b)),
        }
    }
}

impl fmt::Display for Rapport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Taille : {} octets", nombre(self.taille))?;
        writeln!(f)?;
        match &self.format {
            Some(fo) => {
                writeln!(f, "Format reconnu : {}", fo.nom)?;
                for d in &fo.details {
                    writeln!(f, "  {d}")?;
                }
                if let Some(c) = fo.clair {
                    writeln!(f, "  Taille du clair déduite : {c}")?;
                }
            }
            None => writeln!(f, "Format reconnu : aucun. Rien dans le fichier ne désigne l'outil qui l'a produit.")?,
        }

        writeln!(f)?;
        writeln!(f, "Aléa")?;
        let a = &self.alea;
        if a.fiable {
            writeln!(f, "  Entropie : {} bits par octet (maximum : 8)", decimal(a.entropie, 4))?;
            let p = if a.p < SEUIL_GLOBAL { "p < 0,000001".to_string() } else { format!("p = {}", decimal(a.p, 2)) };
            let verdict = if a.p < SEUIL_GLOBAL { "structure détectable" } else { "indiscernable de l'aléa" };
            writeln!(
                f,
                "  Test du χ² sur les 256 valeurs d'octet : {} pour 255 attendu, {p} → {verdict}",
                decimal(a.chi2, 1)
            )?;
        } else {
            writeln!(
                f,
                "  Fichier trop court pour un test fiable (il faut au moins {} octets).",
                nombre(TAILLE_MIN_TEST)
            )?;
        }
        if a.blocs > 0 {
            write!(f, "  Blocs de 4 Kio non aléatoires : {} sur {}", nombre(a.blocs_structures), nombre(a.blocs))?;
            if !a.premiers_structures.is_empty() {
                let pos: Vec<String> = a.premiers_structures.iter().map(|&p| nombre(p)).collect();
                write!(f, ", le premier à l'octet {}", pos[0])?;
            }
            writeln!(f)?;
        }
        if self.texte_initial >= 16 {
            writeln!(f, "  Les {} premiers octets sont du texte lisible.", nombre(self.texte_initial as u64))?;
        }

        match &self.janus {
            Some(HypotheseJanus::Exclue(raison)) => {
                writeln!(f)?;
                writeln!(f, "Hypothèse « fichier Janus v1 » : exclue, car {raison}.")?;
            }
            Some(HypotheseJanus::Compatible { clair_min, clair_max }) => {
                writeln!(f)?;
                writeln!(f, "Hypothèse « fichier Janus v1 » : compatible.")?;
                writeln!(
                    f,
                    "  Si c'en est un, son visage principal fait entre {} et {} octets.",
                    nombre(*clair_min),
                    nombre(*clair_max)
                )?;
                writeln!(
                    f,
                    "  Il cache peut-être jusqu'à 3 autres visages, d'au plus {} octets en tout : rien ne permet de le savoir.",
                    nombre(crate::format::capacite_cachee(*clair_max))
                )?;
                writeln!(
                    f,
                    "  Rien d'autre n'est visible : ni l'outil, ni le nombre de destinataires, ni le mode \
                     (clés ou mot de passe), ni les algorithmes."
                )?;
                writeln!(
                    f,
                    "  Cela ne prouve pas que c'en est un : n'importe quel fichier aléatoire de cette taille \
                     donnerait le même résultat."
                )?;
            }
            None => {}
        }

        if let Some(fo) = &self.format {
            writeln!(f)?;
            writeln!(f, "Ce qu'un tiers apprend sans aucune clé")?;
            for x in &fo.fuites {
                writeln!(f, "  - {x}")?;
            }
        }
        Ok(())
    }
}
