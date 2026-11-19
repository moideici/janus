//! Format Janus v1, à deux visages (docs/03-deux-visages.md, qui modifie
//! docs/02-spec-v0.md). Les numéros § renvoient à 03-deux-visages.md.
//!
//! Tout fichier a la même structure : deux étiquettes d'en-tête, un sel commun,
//! 16 emplacements, puis un corps qui contient le visage principal (le leurre),
//! une réserve de taille fixe et, éventuellement, le visage caché.

use crate::xwing::{self, Identite, TAILLE_PK};
use crate::{alea, kemeleon};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroizing;

// § 3 — constantes
pub const N_EMPL: usize = 16;
pub const S: usize = 1632;
pub const OFF_T0: usize = 0;
pub const OFF_T1: usize = 32;
pub const OFF_SEL: usize = 64;
pub const OFF_EMPL: usize = 96;
pub const H: usize = OFF_EMPL + N_EMPL * S; // 26 208
pub const TB: usize = 65_536;
pub const TC: usize = TB + 16;
const OFF_KAPPA: usize = 32;
const OFF_W: usize = 32 + kemeleon::TAILLE_ENCODEE; // 1568
/// K ‖ BE64(début) ‖ BE64(longueur)
const CHARGE_W: usize = 48;
const TAILLE_W: usize = CHARGE_W + 16;

// § 5 — réserve (décision D-4) : max(64 Kio, ⌈L₁ / 16⌉)
pub const RESERVE_MIN: u64 = 65_536;
pub const RESERVE_RHO: u64 = 16;

const ET_ENTETE: &[u8] = b"janus/v1/entete";
const ET_CORPS: &[u8] = b"janus/v1/corps";
const ET_EMB_XWING: &[u8] = b"janus/v1/emballage/xwing";
const ET_EMB_MDP: &[u8] = b"janus/v1/emballage/mdp";

// Argon2id, seconde configuration recommandée de la RFC 9106 (inchangé depuis v0)
pub const ARGON2_M_KIO: u32 = 65_536;
pub const ARGON2_T: u32 = 3;
pub const ARGON2_P: u32 = 4;

pub enum Destinataires<'a> {
    Cles(&'a [[u8; TAILLE_PK]]),
    MotDePasse(&'a [u8]),
}

pub enum Ouverture<'a> {
    Identites(&'a [Identite]),
    MotDePasse(&'a [u8]),
}

/// Un visage à chiffrer : son contenu, lu en flux, et ses destinataires.
pub struct Visage<'a> {
    pub entree: &'a mut dyn Read,
    pub longueur: u64,
    pub dest: Destinataires<'a>,
}

// § 4 — dérivations

fn hkdf(ikm: &[u8], info: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    let mut sortie = Zeroizing::new([0u8; 32]);
    let info: Vec<u8> = info.concat();
    Hkdf::<Sha256>::new(None, ikm)
        .expand(&info, &mut sortie[..])
        .expect("32 octets");
    sortie
}

fn argon2id(mdp: &[u8], sel: &[u8]) -> Zeroizing<[u8; 32]> {
    let params = Params::new(ARGON2_M_KIO, ARGON2_T, ARGON2_P, Some(32)).expect("paramètres");
    let mut sortie = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(mdp, sel, &mut sortie[..])
        .expect("argon2");
    sortie
}

fn cle_emb_mdp(a: &[u8], i: usize) -> Zeroizing<[u8; 32]> {
    hkdf(a, &[ET_EMB_MDP, &[i as u8]])
}

fn cle_emb_xwing(ss: &[u8], i: usize) -> Zeroizing<[u8; 32]> {
    hkdf(ss, &[ET_EMB_XWING, &[i as u8]])
}

/// T = HMAC(K_entete, BE64(F) ‖ BE64(début) ‖ BE64(longueur) ‖ sel ‖ E_0 ‖ … ‖ E_15).
fn mac_entete(k: &[u8; 32], f: u64, debut: u64, longueur: u64, sel_et_empl: &[u8]) -> [u8; 32] {
    let k_entete = hkdf(k, &[ET_ENTETE]);
    let mut m = <Hmac<Sha256>>::new_from_slice(&k_entete[..]).expect("clé");
    m.update(&f.to_be_bytes());
    m.update(&debut.to_be_bytes());
    m.update(&longueur.to_be_bytes());
    m.update(sel_et_empl);
    m.finalize().into_bytes().into()
}

/// AEAD(clé, 0¹², K ‖ début ‖ longueur) → 64 octets.
fn emballer(cle: &[u8; 32], charge: &[u8; CHARGE_W]) -> [u8; TAILLE_W] {
    let mut w = [0u8; TAILLE_W];
    w[..CHARGE_W].copy_from_slice(charge);
    let tag = ChaCha20Poly1305::new(cle.into())
        .encrypt_inout_detached(&[0u8; 12].into(), b"", (&mut w[..CHARGE_W]).into())
        .expect("aead");
    w[CHARGE_W..].copy_from_slice(&tag);
    w
}

fn deballer(cle: &[u8; 32], w: &[u8]) -> Option<Zeroizing<[u8; CHARGE_W]>> {
    let mut c = Zeroizing::new([0u8; CHARGE_W]);
    c.copy_from_slice(&w[..CHARGE_W]);
    let tag = chacha20poly1305::Tag::try_from(&w[CHARGE_W..TAILLE_W]).ok()?;
    ChaCha20Poly1305::new(cle.into())
        .decrypt_inout_detached(&[0u8; 12].into(), b"", (&mut c[..]).into(), &tag)
        .ok()?;
    Some(c)
}

// § 5 — taille

/// PADMÉ (Nikitin et al., 2019), identique au labo 9.2 du cours.
pub fn padme(l: u64) -> u64 {
    if l < 2 {
        return l;
    }
    let e = 63 - l.leading_zeros() as u64; // ⌊log2 L⌋
    let s = 64 - e.leading_zeros() as u64; // ⌊log2 E⌋ + 1
    let bits = e - s;
    let masque = (1u64 << bits) - 1;
    (l + masque) & !masque
}

/// Nombre de blocs STREAM d'un visage de `l` octets (au moins un, même vide).
pub fn nb_blocs(l: u64) -> u64 {
    l.div_ceil(TB as u64).max(1)
}

/// c(L) : taille chiffrée d'un visage de `l` octets.
pub fn taille_chiffree(l: u64) -> u64 {
    l + 16 * nb_blocs(l)
}

/// Réserve(L₁) = max(64 Kio, ⌈L₁ / 16⌉), fonction fixe et publique.
pub fn reserve(l1: u64) -> u64 {
    RESERVE_MIN.max(l1.div_ceil(RESERVE_RHO))
}

/// Plus grand secret qu'on peut cacher derrière un leurre de `l1` octets.
pub fn capacite_cachee(l1: u64) -> u64 {
    let r = reserve(l1);
    let (k, reste) = (r / TC as u64, r % TC as u64);
    if reste > 16 {
        k * TB as u64 + reste - 16
    } else {
        k * TB as u64
    }
}

/// Bornes [Ref, PADMÉ(Ref)] de la taille du fichier pour un leurre de `l1` octets.
pub fn bornes_taille(l1: u64) -> (u64, u64) {
    let reference = H as u64 + taille_chiffree(l1) + reserve(l1);
    (reference, padme(reference))
}

/// F uniforme dans [Ref, PADMÉ(Ref)]. Toutes les tailles sont possibles en v1.
pub fn tirer_taille(l1: u64) -> u64 {
    let (reference, fmax) = bornes_taille(l1);
    reference + alea::uniforme_u64_jusqua(fmax - reference)
}

// ───────────────────────────────── erreurs ─────────────────────────────────

/// L'unique erreur d'ouverture (J-07) : elle ne dit jamais pourquoi.
#[derive(Debug, PartialEq, Eq)]
pub struct ImpossibleDeDechiffrer;

impl std::fmt::Display for ImpossibleDeDechiffrer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("impossible de déchiffrer")
    }
}
impl std::error::Error for ImpossibleDeDechiffrer {}

#[derive(Debug)]
pub enum ErreurOuverture {
    Impossible,
    /// Les identifiants fournis ouvrent deux visages différents. Seul celui qui
    /// les possède tous les deux peut provoquer cette erreur.
    PlusieursVisages,
    Io(io::Error),
}

impl From<io::Error> for ErreurOuverture {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl std::fmt::Display for ErreurOuverture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Impossible => ImpossibleDeDechiffrer.fmt(f),
            Self::PlusieursVisages => {
                f.write_str("ces identifiants ouvrent deux visages différents : donne-les séparément")
            }
            Self::Io(e) => write!(f, "erreur d'entrée-sortie : {e}"),
        }
    }
}
impl std::error::Error for ErreurOuverture {}

#[derive(Debug)]
pub enum ErreurChiffrement {
    AucunDestinataire,
    TropDeDestinataires,
    ClePubliqueInvalide,
    /// R5 : le visage caché dépasse la réserve.
    SecretTropGrand { capacite: u64 },
    /// R5 : le même mot de passe pour les deux visages.
    MemeMotDePasse,
    /// R5 : la même clé publique dans les deux visages.
    MemeCle,
    Io(io::Error),
}

impl From<io::Error> for ErreurChiffrement {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl std::fmt::Display for ErreurChiffrement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AucunDestinataire => f.write_str("aucun destinataire"),
            Self::TropDeDestinataires => f.write_str("plus de 16 destinataires au total"),
            Self::ClePubliqueInvalide => f.write_str("clé publique invalide"),
            Self::SecretTropGrand { capacite } => write!(
                f,
                "le visage caché est trop grand : ce leurre ne peut cacher que {capacite} octets \
                 (la réserve vaut 1/16 du leurre, et au moins 64 Kio). Prends un leurre plus grand"
            ),
            Self::MemeMotDePasse => f.write_str("les deux visages ne doivent pas avoir le même mot de passe"),
            Self::MemeCle => f.write_str("une même clé publique ne doit pas ouvrir les deux visages"),
            Self::Io(e) => write!(f, "erreur d'entrée-sortie : {e}"),
        }
    }
}
impl std::error::Error for ErreurChiffrement {}

// ─────────────────── corps (STREAM), par lots et en parallèle ───────────────────

fn nonce_bloc(j: u64, dernier: bool) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[3..11].copy_from_slice(&j.to_be_bytes()); // BE88(j) : 11 octets, les 3 premiers nuls
    n[11] = dernier as u8;
    n
}

fn nb_coeurs() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}

/// Nombre de blocs par lot : mémoire d'environ 2 × LOT × 64 Kio, quelle que soit la taille.
fn taille_lot() -> usize {
    nb_coeurs() * 16
}

/// Chiffre un lot de blocs j0, j0+1, … (`c` blocs au total dans le visage).
/// Un lot vide (visage vide) produit un unique bloc de 16 octets.
fn chiffrer_lot(aead: &ChaCha20Poly1305, j0: u64, c: u64, clair: &[u8], corps: &mut [u8]) {
    let n = clair.len();
    let nblocs = n.div_ceil(TB).max(1);
    let par_fil = nblocs.div_ceil(nb_coeurs().min(nblocs));
    let mut reste: &mut [u8] = corps;
    std::thread::scope(|portee| {
        for b0 in (0..nblocs).step_by(par_fil) {
            let b1 = (b0 + par_fil).min(nblocs);
            let e = &clair[(b0 * TB).min(n)..(b1 * TB).min(n)];
            let (sorties, r) = std::mem::take(&mut reste).split_at_mut(e.len() + 16 * (b1 - b0));
            reste = r;
            portee.spawn(move || {
                for jj in 0..b1 - b0 {
                    let ee = &e[(jj * TB).min(e.len())..((jj + 1) * TB).min(e.len())];
                    let s = &mut sorties[jj * TC..jj * TC + ee.len() + 16];
                    let j = j0 + (b0 + jj) as u64;
                    let k = ee.len();
                    s[..k].copy_from_slice(ee);
                    let tag = aead
                        .encrypt_inout_detached(&nonce_bloc(j, j == c - 1).into(), b"", (&mut s[..k]).into())
                        .expect("aead");
                    s[k..].copy_from_slice(&tag);
                }
            });
        }
    });
}

/// Déchiffre un lot ; faux si un seul tag est invalide.
fn dechiffrer_lot(aead: &ChaCha20Poly1305, j0: u64, c: u64, corps: &[u8], clair: &mut [u8]) -> bool {
    let nblocs = corps.len().div_ceil(TC);
    let echec = AtomicBool::new(false);
    let par_fil = nblocs.div_ceil(nb_coeurs().min(nblocs));
    let mut reste: &mut [u8] = clair;
    std::thread::scope(|portee| {
        for (g, entrees) in corps.chunks(par_fil * TC).enumerate() {
            let nb = entrees.len().div_ceil(TC);
            let (sorties, r) = std::mem::take(&mut reste).split_at_mut(entrees.len() - 16 * nb);
            reste = r;
            let echec = &echec;
            portee.spawn(move || {
                let mut off = 0;
                for (jj, e) in entrees.chunks(TC).enumerate() {
                    let j = j0 + (g * par_fil + jj) as u64;
                    let k = e.len() - 16;
                    let s = &mut sorties[off..off + k];
                    off += k;
                    s.copy_from_slice(&e[..k]);
                    let tag = chacha20poly1305::Tag::try_from(&e[k..]).expect("16 octets");
                    if aead
                        .decrypt_inout_detached(&nonce_bloc(j, j == c - 1).into(), b"", s.into(), &tag)
                        .is_err()
                    {
                        echec.store(true, Ordering::Relaxed);
                        return;
                    }
                }
            });
        }
    });
    !echec.load(Ordering::Relaxed)
}

fn aead_corps(k: &[u8; 32]) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new((&*hkdf(k, &[ET_CORPS])).into())
}

/// Écrit `n` octets d'aléa (réserve inutilisée et marge PADMÉ).
fn ecrire_alea<W: Write>(sortie: &mut W, mut n: u64) -> io::Result<()> {
    let mut tampon = vec![0u8; (1 << 20).min(n as usize)];
    while n > 0 {
        let k = (n as usize).min(tampon.len());
        alea::remplir(&mut tampon[..k]);
        sortie.write_all(&tampon[..k])?;
        n -= k as u64;
    }
    Ok(())
}

/// Chiffre un visage de `longueur` octets lus dans `entree` (STREAM, par lots).
fn ecrire_visage<W: Write>(
    entree: &mut dyn Read,
    longueur: u64,
    k: &[u8; 32],
    sortie: &mut W,
) -> Result<(), ErreurChiffrement> {
    let aead = aead_corps(k);
    let c = nb_blocs(longueur);
    let lot = taille_lot().min(c as usize);
    let mut clair = Zeroizing::new(vec![0u8; lot * TB]);
    let mut corps = vec![0u8; lot * TC];
    let (mut pos, mut j) = (0u64, 0u64);
    loop {
        let n = ((longueur - pos) as usize).min(lot * TB);
        entree.read_exact(&mut clair[..n])?;
        let nblocs = n.div_ceil(TB).max(1);
        let m = n + 16 * nblocs;
        chiffrer_lot(&aead, j, c, &clair[..n], &mut corps[..m]);
        sortie.write_all(&corps[..m])?;
        pos += n as u64;
        j += nblocs as u64;
        if pos == longueur {
            break;
        }
    }
    debug_assert_eq!(j, c);
    // L'entrée doit s'arrêter exactement à la longueur annoncée.
    if entree.read(&mut [0u8; 1])? != 0 {
        return Err(io::Error::other("l'entrée est plus longue que annoncé").into());
    }
    Ok(())
}

// ─────────────────────────────── § 7.1 — chiffrer ───────────────────────────────

/// Réservé aux tests : fausse les valeurs `début` et `longueur` annoncées pour le
/// visage principal (dans `w` ET dans `T`, donc un en-tête authentique).
#[doc(hidden)]
#[derive(Clone, Copy, Default)]
pub struct Falsification {
    pub debut: Option<u64>,
    pub longueur: Option<u64>,
}

/// Un visage tel qu'il est décrit dans l'en-tête.
struct Description<'a> {
    dest: Destinataires<'a>,
    debut: u64,
    longueur: u64,
}

fn verifier_regles(visages: &[Description]) -> Result<(), ErreurChiffrement> {
    let mut total = 0;
    for v in visages {
        total += match v.dest {
            Destinataires::MotDePasse(_) => 1,
            Destinataires::Cles(c) if c.is_empty() => return Err(ErreurChiffrement::AucunDestinataire),
            Destinataires::Cles(c) => c.len(),
        };
    }
    if total > N_EMPL {
        return Err(ErreurChiffrement::TropDeDestinataires);
    }
    if let [a, b] = visages {
        match (&a.dest, &b.dest) {
            (Destinataires::MotDePasse(x), Destinataires::MotDePasse(y)) if bool::from(x.ct_eq(y)) => {
                return Err(ErreurChiffrement::MemeMotDePasse)
            }
            (Destinataires::Cles(x), Destinataires::Cles(y)) if x.iter().any(|k| y.contains(k)) => {
                return Err(ErreurChiffrement::MemeCle)
            }
            _ => {}
        }
    }
    Ok(())
}

/// En-tête complet (T_0 ‖ T_1 ‖ sel ‖ E_0 … E_15) et clé de chaque visage.
fn construire_entete(f: u64, visages: &[Description]) -> Result<(Vec<u8>, Vec<Zeroizing<[u8; 32]>>), ErreurChiffrement> {
    verifier_regles(visages)?;
    let mut entete = vec![0u8; H];
    // Étiquettes, sel et emplacements commencent remplis d'aléa (§ 4.3 de v0, R4).
    alea::remplir(&mut entete);
    let sel = entete[OFF_SEL..OFF_EMPL].to_vec();

    // R2 : positions tirées au hasard pour l'ensemble des destinataires.
    let mut positions: Vec<usize> = (0..N_EMPL).collect();
    for i in (1..N_EMPL).rev() {
        positions.swap(i, alea::uniforme_u32(i as u32 + 1) as usize);
    }
    let mut positions = positions.into_iter();

    let mut cles = Vec::new();
    for v in visages {
        let k = Zeroizing::new(alea::octets::<32>());
        let mut charge = Zeroizing::new([0u8; CHARGE_W]);
        charge[..32].copy_from_slice(&k[..]);
        charge[32..40].copy_from_slice(&v.debut.to_be_bytes());
        charge[40..].copy_from_slice(&v.longueur.to_be_bytes());
        match v.dest {
            Destinataires::MotDePasse(mdp) => {
                // R1 : un visage à mot de passe n'a que ce mot de passe.
                let i = positions.next().expect("R3 vérifiée");
                let a = argon2id(mdp, &sel);
                let e = &mut entete[OFF_EMPL + i * S..OFF_EMPL + (i + 1) * S];
                e[OFF_W..].copy_from_slice(&emballer(&cle_emb_mdp(&a[..], i), &charge));
            }
            Destinataires::Cles(pks) => {
                for pk in pks {
                    let i = positions.next().expect("R3 vérifiée");
                    let (ss, r, kappa) =
                        xwing::encapsuler_cache(pk).ok_or(ErreurChiffrement::ClePubliqueInvalide)?;
                    let e = &mut entete[OFF_EMPL + i * S..OFF_EMPL + (i + 1) * S];
                    e[..32].copy_from_slice(&r);
                    e[OFF_KAPPA..OFF_W].copy_from_slice(&kappa);
                    e[OFF_W..].copy_from_slice(&emballer(&cle_emb_xwing(&ss[..], i), &charge));
                }
            }
        }
        cles.push(k);
    }
    // R4 : le visage principal prend T_0 ou T_1 à pile ou face, le caché l'autre.
    let pile = alea::uniforme_u32(2) as usize;
    for (n, (v, k)) in visages.iter().zip(&cles).enumerate() {
        let t = mac_entete(k, f, v.debut, v.longueur, &entete[OFF_SEL..]);
        let off = [OFF_T0, OFF_T1][(n + pile) % 2];
        entete[off..off + 32].copy_from_slice(&t);
    }
    Ok((entete, cles))
}

/// Chiffre un leurre (visage principal) et, éventuellement, un secret (visage
/// caché), à mémoire bornée. Renvoie la taille F du fichier produit.
pub fn chiffrer_flux<W: Write>(
    principal: Visage,
    cache: Option<Visage>,
    sortie: &mut W,
) -> Result<u64, ErreurChiffrement> {
    chiffrer_flux_interne(principal, cache, sortie, Falsification::default())
}

#[doc(hidden)]
pub fn chiffrer_flux_interne<W: Write>(
    principal: Visage,
    cache: Option<Visage>,
    sortie: &mut W,
    falsif: Falsification,
) -> Result<u64, ErreurChiffrement> {
    let l1 = principal.longueur;
    let c1 = taille_chiffree(l1);
    if let Some(v) = &cache {
        if taille_chiffree(v.longueur) > reserve(l1) {
            return Err(ErreurChiffrement::SecretTropGrand { capacite: capacite_cachee(l1) });
        }
    }
    let f = tirer_taille(l1);
    let b = f - H as u64;

    let mut descriptions = vec![Description {
        dest: principal.dest,
        debut: falsif.debut.unwrap_or(0),
        longueur: falsif.longueur.unwrap_or(l1),
    }];
    let mut entree_cachee = None;
    if let Some(v) = cache {
        let c2 = taille_chiffree(v.longueur);
        // Position uniforme dans la réserve et la marge PADMÉ (§ 5).
        let debut = c1 + alea::uniforme_u64_jusqua(b - c1 - c2);
        descriptions.push(Description { dest: v.dest, debut, longueur: v.longueur });
        entree_cachee = Some((v.entree, v.longueur, debut, c2));
    }
    let (entete, cles) = construire_entete(f, &descriptions)?;
    sortie.write_all(&entete)?;
    ecrire_visage(principal.entree, l1, &cles[0], sortie)?;
    match entree_cachee {
        Some((entree, l2, debut, c2)) => {
            ecrire_alea(sortie, debut - c1)?;
            ecrire_visage(entree, l2, &cles[1], sortie)?;
            ecrire_alea(sortie, b - debut - c2)?;
        }
        None => ecrire_alea(sortie, b - c1)?,
    }
    Ok(f)
}

/// Variante en mémoire, à un seul visage.
pub fn chiffrer(clair: &[u8], dest: Destinataires) -> Result<Vec<u8>, ErreurChiffrement> {
    let mut v = Vec::with_capacity(bornes_taille(clair.len() as u64).1 as usize);
    let principal = Visage { entree: &mut &clair[..], longueur: clair.len() as u64, dest };
    chiffrer_flux(principal, None, &mut v)?;
    Ok(v)
}

/// Variante en mémoire, à deux visages : un leurre et un secret.
pub fn chiffrer_deux_visages(
    leurre: &[u8],
    dest_leurre: Destinataires,
    secret: &[u8],
    dest_secret: Destinataires,
) -> Result<Vec<u8>, ErreurChiffrement> {
    let mut v = Vec::with_capacity(bornes_taille(leurre.len() as u64).1 as usize);
    let principal = Visage { entree: &mut &leurre[..], longueur: leurre.len() as u64, dest: dest_leurre };
    let cache = Visage { entree: &mut &secret[..], longueur: secret.len() as u64, dest: dest_secret };
    chiffrer_flux(principal, Some(cache), &mut v)?;
    Ok(v)
}

/// Réservé aux tests : fichier à en-tête authentique mais dont `début` ou
/// `longueur` sont faux (corpus de fichiers piégés).
#[doc(hidden)]
pub fn chiffrer_falsifie_pour_tests(
    clair: &[u8],
    dest: Destinataires,
    falsif: Falsification,
) -> Result<Vec<u8>, ErreurChiffrement> {
    let mut v = Vec::new();
    let principal = Visage { entree: &mut &clair[..], longueur: clair.len() as u64, dest };
    chiffrer_flux_interne(principal, None, &mut v, falsif)?;
    Ok(v)
}

// ──────────────────────────────── § 7.2 — ouvrir ────────────────────────────────

/// Un visage retrouvé : sa clé et sa position dans le corps.
struct VisageOuvert {
    k: Zeroizing<[u8; 32]>,
    debut: u64,
    longueur: u64,
}

/// Essaie l'identifiant sur les 16 emplacements (tous, même après un succès), puis
/// garde les visages dont l'étiquette est valide (T_0 ou T_1, en temps constant).
fn retrouver_visages(entete: &[u8], f: u64, ouv: &Ouverture) -> Vec<VisageOuvert> {
    let empl = |i: usize| &entete[OFF_EMPL + i * S..OFF_EMPL + (i + 1) * S];
    // Chaque essai donne (déballé ?, charge). Un échec donne une charge nulle, et
    // la suite fait EXACTEMENT le même travail dans les deux cas
    // (05-preuve-integrite.md, § 7.3, défaut 2).
    let essayer = |cle: &[u8; 32], w: &[u8]| match deballer(cle, w) {
        Some(c) => (Choice::from(1), c),
        None => (Choice::from(0), Zeroizing::new([0u8; CHARGE_W])),
    };
    let mut essais = Vec::new();
    match ouv {
        Ouverture::MotDePasse(mdp) => {
            let a = argon2id(mdp, &entete[OFF_SEL..OFF_EMPL]);
            for i in 0..N_EMPL {
                essais.push(essayer(&cle_emb_mdp(&a[..], i), &empl(i)[OFF_W..]));
            }
        }
        Ouverture::Identites(ids) => {
            for i in 0..N_EMPL {
                let e = empl(i);
                let r: [u8; 32] = e[..32].try_into().unwrap();
                for id in ids.iter() {
                    let ss = id.decapsuler_cache(&r, &e[OFF_KAPPA..OFF_W]);
                    essais.push(essayer(&cle_emb_xwing(&ss[..], i), &e[OFF_W..]));
                }
            }
        }
    }
    let mut visages: Vec<VisageOuvert> = Vec::new();
    for (deballe, c) in essais {
        let mut k = Zeroizing::new([0u8; 32]);
        k.copy_from_slice(&c[..32]);
        let debut = u64::from_be_bytes(c[32..40].try_into().unwrap());
        let longueur = u64::from_be_bytes(c[40..48].try_into().unwrap());
        // L'étiquette est calculée pour CHAQUE essai, déballé ou non.
        let t = mac_entete(&k, f, debut, longueur, &entete[OFF_SEL..]);
        let valide = deballe & (t.ct_eq(&entete[OFF_T0..OFF_T0 + 32]) | t.ct_eq(&entete[OFF_T1..OFF_T1 + 32]));
        // Dédoublonnage sur le triplet (K, début, longueur), pas sur K seul
        // (défaut 1) : deux triplets distincts sont deux visages distincts.
        let deja = visages.iter().fold(Choice::from(0), |acc, v| {
            acc | (v.k.ct_eq(&k[..]) & v.debut.ct_eq(&debut) & v.longueur.ct_eq(&longueur))
        });
        if bool::from(valide & !deja) {
            visages.push(VisageOuvert { k, debut, longueur });
        }
    }
    visages
}

/// Lit et jette `n` octets ; échoue si l'entrée est plus courte.
fn sauter<R: Read>(entree: &mut R, n: u64) -> Result<(), ErreurOuverture> {
    let lus = io::copy(&mut entree.take(n), &mut io::sink())?;
    if lus != n {
        return Err(ErreurOuverture::Impossible);
    }
    Ok(())
}

/// Ouvre le visage qui correspond à l'identifiant, dans un fichier de `taille`
/// octets lu dans `entree`, et écrit exactement son clair dans `sortie`.
/// Renvoie la longueur du clair. En cas d'erreur, la sortie déjà écrite doit être
/// jetée (d'où l'écriture dans un fichier temporaire, J-06).
pub fn dechiffrer_flux<R: Read, W: Write>(
    entree: &mut R,
    taille: u64,
    ouv: Ouverture,
    sortie: &mut W,
) -> Result<u64, ErreurOuverture> {
    use ErreurOuverture::Impossible;
    let b = taille.checked_sub(H as u64).ok_or(Impossible)?;
    let mut entete = vec![0u8; H];
    entree.read_exact(&mut entete).map_err(|_| Impossible)?;

    let mut visages = retrouver_visages(&entete, taille, &ouv);
    let v = match visages.len() {
        0 => return Err(Impossible),
        1 => visages.pop().unwrap(),
        _ => return Err(ErreurOuverture::PlusieursVisages),
    };
    let c = nb_blocs(v.longueur);
    let fin = v
        .longueur
        .checked_add(16 * c)
        .and_then(|cv| v.debut.checked_add(cv))
        .filter(|&fin| fin <= b)
        .ok_or(Impossible)?;

    sauter(entree, v.debut)?;
    let aead = aead_corps(&v.k);
    let lot = taille_lot().min(c as usize);
    let mut corps = vec![0u8; lot * TC];
    let mut clair = Zeroizing::new(vec![0u8; lot * TB]);
    let (mut restant, mut j) = (fin - v.debut, 0u64);
    while restant > 0 {
        let m = (restant as usize).min(lot * TC);
        entree.read_exact(&mut corps[..m]).map_err(|_| Impossible)?;
        let nblocs = m.div_ceil(TC);
        let n = m - 16 * nblocs;
        if !dechiffrer_lot(&aead, j, c, &corps[..m], &mut clair[..n]) {
            return Err(Impossible);
        }
        sortie.write_all(&clair[..n])?;
        j += nblocs as u64;
        restant -= m as u64;
    }
    // La taille F est couverte par T : le fichier doit faire exactement `taille`.
    sauter(entree, b - fin)?;
    if entree.read(&mut [0u8; 1])? != 0 {
        return Err(Impossible);
    }
    Ok(v.longueur)
}

/// Variante en mémoire.
pub fn dechiffrer(fichier: &[u8], ouv: Ouverture) -> Result<Zeroizing<Vec<u8>>, ImpossibleDeDechiffrer> {
    let mut v = Zeroizing::new(Vec::with_capacity(fichier.len()));
    match dechiffrer_flux(&mut &fichier[..], fichier.len() as u64, ouv, &mut *v) {
        Ok(_) => Ok(v),
        Err(_) => Err(ImpossibleDeDechiffrer),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 05-preuve-integrite.md, § 7.3, défaut 1 : un auteur malveillant fait déballer
    /// par UN mot de passe la même clé K avec deux positions (d, l) différentes,
    /// chacune validée par sa propre étiquette. Ce sont deux visages : l'ouverture
    /// doit le signaler, et non en choisir un en silence.
    #[test]
    fn meme_cle_deux_positions_donne_plusieurs_visages() {
        let mdp = b"piege";
        let f = 200_000u64;
        let mut entete = vec![0u8; H];
        alea::remplir(&mut entete);
        let a = argon2id(mdp, &entete[OFF_SEL..OFF_EMPL]);
        let k = alea::octets::<32>();
        let triplets = [(0u64, 10u64), (50_000u64, 20u64)];
        for (i, &(d, l)) in triplets.iter().enumerate() {
            let mut charge = [0u8; CHARGE_W];
            charge[..32].copy_from_slice(&k);
            charge[32..40].copy_from_slice(&d.to_be_bytes());
            charge[40..].copy_from_slice(&l.to_be_bytes());
            let w = emballer(&cle_emb_mdp(&a[..], i), &charge);
            entete[OFF_EMPL + i * S + OFF_W..OFF_EMPL + (i + 1) * S].copy_from_slice(&w);
        }
        for (x, &(d, l)) in triplets.iter().enumerate() {
            let t = mac_entete(&k, f, d, l, &entete[OFF_SEL..]);
            entete[32 * x..32 * x + 32].copy_from_slice(&t);
        }
        let visages = retrouver_visages(&entete, f, &Ouverture::MotDePasse(mdp));
        assert_eq!(visages.len(), 2, "deux triplets distincts doivent compter comme deux visages");

        // Le fichier complet : l'ouverture refuse avec « plusieurs visages ».
        let mut fichier = entete.clone();
        fichier.resize(f as usize, 0);
        let r = dechiffrer_flux(&mut &fichier[..], f, Ouverture::MotDePasse(mdp), &mut Vec::new());
        assert!(matches!(r, Err(ErreurOuverture::PlusieursVisages)), "{r:?}");

        // Même K, même triplet dans deux emplacements : un seul visage.
        let (d, l) = triplets[0];
        let mut charge = [0u8; CHARGE_W];
        charge[..32].copy_from_slice(&k);
        charge[32..40].copy_from_slice(&d.to_be_bytes());
        charge[40..].copy_from_slice(&l.to_be_bytes());
        entete[OFF_EMPL + S + OFF_W..OFF_EMPL + 2 * S].copy_from_slice(&emballer(&cle_emb_mdp(&a[..], 1), &charge));
        // L'étiquette couvre tout l'en-tête : il faut la recalculer après la modification.
        let t = mac_entete(&k, f, d, l, &entete[OFF_SEL..]);
        entete[..32].copy_from_slice(&t);
        assert_eq!(retrouver_visages(&entete, f, &Ouverture::MotDePasse(mdp)).len(), 1);
    }
}
