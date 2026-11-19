//! Encodage Kemeleon des chiffrés ML-KEM-768 (draft-irtf-cfrg-kemeleon-02, § 4.3).
//!
//! Un chiffré ML-KEM standard (1088 octets) est formé de coefficients *compressés*,
//! dont la distribution trahit la structure. Kemeleon les décompresse en tirant
//! un antécédent uniforme pour chaque coefficient, puis encode chaque vecteur de
//! 256 coefficients modulo q comme un grand entier rendu uniforme sur 3072 bits.
//! Résultat : 4 × 384 = 1536 octets indistinguables de l'aléa.
//!
//! TEMPS CONSTANT. Toute l'arithmétique porte sur des entiers de taille fixe
//! (48 mots de 64 bits), sans branchement ni accès mémoire dépendant des données :
//! - la division par q est une multiplication par une constante « magique »
//!   (jamais l'instruction `div`, dont la durée varie : c'est la leçon de KyberSlash) ;
//! - les comparaisons sont des soustractions dont on lit la retenue ;
//! - le choix d'un antécédent est un calcul d'intervalle, pas une énumération.
//!
//! Seul le tirage de m (VectorEncode) contient une boucle de rejet, dont le nombre
//! de tours ne dépend des données qu'avec une probabilité de l'ordre de 2^-77.

use crate::alea;
use std::sync::OnceLock;

pub const Q: u32 = 3329;
pub const N: usize = 256;
pub const K: usize = 3; // ML-KEM-768
pub const DU: u32 = 10;
pub const DV: u32 = 4;
pub const TAILLE_CT: usize = 1088; // chiffré ML-KEM-768 standard
pub const TAILLE_VECTEUR: usize = 384; // 3072 bits
pub const TAILLE_ENCODEE: usize = (K + 1) * TAILLE_VECTEUR; // 1536

const MOTS: usize = 48; // 48 × 64 = 3072 bits
type Grand = [u64; MOTS];

// ───────────────────── division par q sans instruction div ─────────────────────

/// m = ⌈2^56 / q⌉ : ⌊x·m / 2^56⌋ = ⌊x / q⌋ pour tout x < 2^44 (Granlund–Montgomery,
/// avec 44 bits de numérateur et ⌈log2 q⌉ = 12). Vérifié par les tests.
const MAGIQUE: u128 = (1u128 << 56).div_ceil(Q as u128);

#[inline(always)]
fn div_q(x: u64) -> u64 {
    debug_assert!(x < 1 << 44);
    ((x as u128 * MAGIQUE) >> 56) as u64
}

/// Compress_d (FIPS 203, éq. 4.7) : arrondi de (2^d / q)·x, modulo 2^d.
pub fn compress(d: u32, x: u32) -> u32 {
    (div_q(((x as u64) << d) + (Q as u64) / 2) as u32) & ((1 << d) - 1)
}

/// Decompress_d (FIPS 203, éq. 4.8) : arrondi de (q / 2^d)·y.
pub fn decompress(d: u32, y: u32) -> u32 {
    (Q * y + (1 << (d - 1))) >> d
}

// ───────────────────────────── octets ↔ coefficients ─────────────────────────────

/// ByteDecode_d : coefficients de d bits, bit de poids faible d'abord.
fn byte_decode(d: u32, octets: &[u8], sortie: &mut [u32]) {
    let mut acc: u64 = 0;
    let mut nb: u32 = 0;
    let mut i = 0;
    for c in sortie.iter_mut() {
        while nb < d {
            acc |= (octets[i] as u64) << nb;
            i += 1;
            nb += 8;
        }
        *c = (acc & ((1 << d) - 1)) as u32;
        acc >>= d;
        nb -= d;
    }
}

/// ByteEncode_d : inverse de `byte_decode`.
fn byte_encode(d: u32, coeffs: &[u32], sortie: &mut Vec<u8>) {
    let mut acc: u64 = 0;
    let mut nb: u32 = 0;
    for &c in coeffs {
        acc |= (c as u64) << nb;
        nb += d;
        while nb >= 8 {
            sortie.push(acc as u8);
            acc >>= 8;
            nb -= 8;
        }
    }
    debug_assert_eq!(nb, 0);
}

// ─────────────────────────── antécédents (SamplePreimage) ───────────────────────────

/// Intervalle des antécédents de c par Compress_d : [bas, bas + taille − 1] modulo q.
/// x a pour image c ssi (2c−1)·q/2^(d+1) < x < (2c+1)·q/2^(d+1) ; les bornes ne sont
/// jamais atteintes car (2c±1)·q est impair. Le décalage arithmétique donne le
/// plancher, y compris pour la borne négative de c = 0.
#[inline(always)]
fn intervalle(d: u32, c: u32) -> (i64, i64) {
    let k = d + 1;
    let q = Q as i64;
    let bas = ((2 * c as i64 - 1) * q + ((1 << k) - 1)) >> k; // ⌈(2c−1)q / 2^k⌉
    let haut = ((2 * c as i64 + 1) * q) >> k; // ⌊(2c+1)q / 2^k⌋
    (bas, haut - bas + 1)
}

/// Antécédent uniforme : bas + ⌊x·taille / 2^96⌋ avec x sur 96 bits.
/// Écart à l'uniforme ≤ taille / 2^96 par coefficient, soit < 2^-78 au total.
#[inline(always)]
fn antecedent(d: u32, c: u32, alea12: &[u8]) -> u32 {
    let (bas, taille) = intervalle(d, c);
    let mut x = [0u8; 16];
    x[..12].copy_from_slice(alea12);
    let x = u128::from_le_bytes(x);
    let idx = ((x * taille as u128) >> 96) as i64;
    let v = bas + idx;
    (v + ((v >> 63) & Q as i64)) as u32 // + q si négatif, sans branchement
}

/// Liste explicite des antécédents (pour les tests et la documentation).
pub fn antecedents(d: u32, c: u32) -> Vec<u32> {
    let (bas, taille) = intervalle(d, c);
    (0..taille).map(|i| (bas + i).rem_euclid(Q as i64) as u32).collect()
}

// ───────────────────────── entiers de 3072 bits, taille fixe ─────────────────────────

/// r ← r·m + a (r·m + a doit tenir sur 3072 bits).
fn mul_ajout(r: &mut Grand, m: u64, a: u64) {
    let mut retenue = a as u128;
    for mot in r.iter_mut() {
        let t = *mot as u128 * m as u128 + retenue;
        *mot = t as u64;
        retenue = t >> 64;
    }
    debug_assert_eq!(retenue, 0);
}

/// r ← r + b·x·2^(64·decalage) (sans dépassement attendu).
fn ajouter_produit(r: &mut Grand, b: &Grand, x: u64, decalage: usize) {
    let mut retenue: u128 = 0;
    for i in decalage..MOTS {
        let t = r[i] as u128 + b[i - decalage] as u128 * x as u128 + retenue;
        r[i] = t as u64;
        retenue = t >> 64;
    }
}

/// 1 si a > b, 0 sinon, en temps constant (retenue de b − a).
fn plus_grand(a: &Grand, b: &Grand) -> u64 {
    let mut emprunt: u64 = 0;
    for i in 0..MOTS {
        let (d1, e1) = b[i].overflowing_sub(a[i]);
        let (_, e2) = d1.overflowing_sub(emprunt);
        emprunt = (e1 | e2) as u64;
    }
    emprunt
}

/// r ← ⌊r / q⌋ ; renvoie r mod q. Demi-mots de 32 bits : le numérateur reste < 2^44.
fn divrem_q(r: &mut Grand) -> u32 {
    let mut reste: u64 = 0;
    for mot in r.iter_mut().rev() {
        let mut quotient: u64 = 0;
        for moitie in [*mot >> 32, *mot & 0xffff_ffff] {
            let x = (reste << 32) | moitie;
            let qt = div_q(x);
            reste = x - qt * Q as u64;
            quotient = (quotient << 32) | qt;
        }
        *mot = quotient;
    }
    reste as u32
}

struct Constantes {
    qn: Grand, // q^256
    q0: u128,  // ⌊(2^3072 − 1) / q^256⌋, environ 2^76
    r0: Grand, // (2^3072 − 1) mod q^256
    bits_q0: u32,
}

/// Constantes publiques, calculées une fois (num-bigint suffit : rien de secret ici).
fn constantes() -> &'static Constantes {
    static C: OnceLock<Constantes> = OnceLock::new();
    C.get_or_init(|| {
        use num_bigint::BigUint;
        use num_traits::{One, ToPrimitive};
        let vers_grand = |x: &BigUint| {
            let mut g = [0u64; MOTS];
            for (i, m) in x.iter_u64_digits().enumerate() {
                g[i] = m;
            }
            g
        };
        let qn = BigUint::from(Q).pow(N as u32);
        let max = (BigUint::one() << 3072u32) - BigUint::one();
        let q0 = (&max / &qn).to_u128().expect("< 2^128");
        Constantes {
            qn: vers_grand(&qn),
            q0,
            r0: vers_grand(&(&max % &qn)),
            bits_q0: 128 - q0.leading_zeros(),
        }
    })
}

/// VectorEncode : r = Σ q^i·a[i], puis r + m·q^n avec m uniforme dans
/// [0, ⌊(2^3072 − 1 − r) / q^n⌋]. Cette borne vaut q0 si r ≤ r0, sinon q0 − 1 :
/// une comparaison suffit, aucune division de grands entiers.
/// Sortie : 384 octets gros-boutistes (spec Q10).
fn vector_encode(a: &[u32]) -> [u8; TAILLE_VECTEUR] {
    let c = constantes();
    let mut r: Grand = [0; MOTS];
    for &x in a.iter().rev() {
        mul_ajout(&mut r, Q as u64, x as u64);
    }
    let borne = c.q0 - plus_grand(&r, &c.r0) as u128;
    let masque = (1u128 << c.bits_q0) - 1;
    let m = loop {
        let x = u128::from_le_bytes(alea::octets::<16>()) & masque;
        if x <= borne {
            break x;
        }
    };
    ajouter_produit(&mut r, &c.qn, m as u64, 0);
    ajouter_produit(&mut r, &c.qn, (m >> 64) as u64, 1);
    let mut sortie = [0u8; TAILLE_VECTEUR];
    for (i, mot) in r.iter().enumerate() {
        let debut = TAILLE_VECTEUR - 8 * (i + 1);
        sortie[debut..debut + 8].copy_from_slice(&mot.to_be_bytes());
    }
    sortie
}

/// VectorDecode : les 256 premiers chiffres en base q de r sont ceux de r mod q^n,
/// donc 256 divisions par q suffisent (pas de réduction modulo q^n à part).
fn vector_decode(octets: &[u8], sortie: &mut [u32]) {
    let mut r: Grand = [0; MOTS];
    for (i, mot) in r.iter_mut().enumerate() {
        let debut = TAILLE_VECTEUR - 8 * (i + 1);
        *mot = u64::from_be_bytes(octets[debut..debut + 8].try_into().unwrap());
    }
    for a in sortie.iter_mut() {
        *a = divrem_q(&mut r);
    }
}

// ─────────────────────────────── interface publique ───────────────────────────────

/// Kemeleon.EncodeCtxt : chiffré ML-KEM-768 standard → 1536 octets uniformes.
pub fn encoder_chiffre(ct: &[u8]) -> [u8; TAILLE_ENCODEE] {
    assert_eq!(ct.len(), TAILLE_CT);
    let mut c = vec![0u32; (K + 1) * N];
    byte_decode(DU, &ct[..K * N * DU as usize / 8], &mut c[..K * N]);
    byte_decode(DV, &ct[K * N * DU as usize / 8..], &mut c[K * N..]);
    let mut hasard = vec![0u8; 12 * (K + 1) * N];
    alea::remplir(&mut hasard);
    let u: Vec<u32> = c
        .iter()
        .enumerate()
        .map(|(i, &ci)| antecedent(if i < K * N { DU } else { DV }, ci, &hasard[12 * i..12 * i + 12]))
        .collect();
    let mut sortie = [0u8; TAILLE_ENCODEE];
    for i in 0..=K {
        sortie[i * TAILLE_VECTEUR..(i + 1) * TAILLE_VECTEUR]
            .copy_from_slice(&vector_encode(&u[i * N..(i + 1) * N]));
    }
    sortie
}

/// Kemeleon.DecodeCtxt : 1536 octets quelconques → chiffré ML-KEM-768 standard.
/// Ne peut pas échouer : toute chaîne de la bonne longueur se décode.
pub fn decoder_chiffre(enc: &[u8]) -> Vec<u8> {
    assert_eq!(enc.len(), TAILLE_ENCODEE);
    let mut u = vec![0u32; (K + 1) * N];
    for i in 0..=K {
        vector_decode(&enc[i * TAILLE_VECTEUR..(i + 1) * TAILLE_VECTEUR], &mut u[i * N..(i + 1) * N]);
    }
    let c1: Vec<u32> = u[..K * N].iter().map(|&x| compress(DU, x)).collect();
    let c2: Vec<u32> = u[K * N..].iter().map(|&x| compress(DV, x)).collect();
    let mut ct = Vec::with_capacity(TAILLE_CT);
    byte_encode(DU, &c1, &mut ct);
    byte_encode(DV, &c2, &mut ct);
    ct
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    #[test]
    fn division_magique_exacte() {
        // Bornes autour de chaque multiple de q au voisinage des extrêmes, puis tirages.
        let max = (1u64 << 44) - 1;
        for k in (0..2000u64).chain((max / Q as u64 - 2000)..=(max / Q as u64)) {
            for x in [k * Q as u64, (k * Q as u64).saturating_sub(1), k * Q as u64 + 1] {
                if x <= max {
                    assert_eq!(div_q(x), x / Q as u64, "x = {x}");
                }
            }
        }
        for _ in 0..1_000_000 {
            let x = u64::from_le_bytes(alea::octets::<8>()) & max;
            assert_eq!(div_q(x), x / Q as u64);
        }
        for x in 0..(1u32 << 22) {
            assert_eq!(div_q(x as u64), (x / Q) as u64);
        }
    }

    /// L'intervalle calculé coïncide avec l'énumération brute de Z_q.
    #[test]
    fn intervalles_exacts_et_tailles_du_draft() {
        for d in [DU, DV] {
            let mut couverts = 0;
            for c in 0..(1u32 << d) {
                let mut attendu: Vec<u32> = (0..Q).filter(|&x| compress(d, x) == c).collect();
                let mut obtenu = antecedents(d, c);
                attendu.sort();
                obtenu.sort();
                assert_eq!(obtenu, attendu, "d={d}, c={c}");
                let n = obtenu.len();
                assert!(if d == DU { n == 3 || n == 4 } else { n == 208 || n == 209 });
                couverts += n;
            }
            assert_eq!(couverts, Q as usize);
        }
    }

    #[test]
    fn antecedent_uniforme_et_valide() {
        // c = 0 (intervalle à cheval sur 0) puis un c ordinaire.
        for (d, c) in [(DU, 0u32), (DU, 513), (DV, 0), (DV, 9)] {
            let cands = antecedents(d, c);
            let mut comptes = std::collections::HashMap::new();
            let tirages = 400 * cands.len();
            for _ in 0..tirages {
                let x = antecedent(d, c, &alea::octets::<12>());
                assert_eq!(compress(d, x), c);
                *comptes.entry(x).or_insert(0u32) += 1;
            }
            assert_eq!(comptes.len(), cands.len(), "toutes les valeurs doivent sortir");
            for (&x, &n) in &comptes {
                assert!((250..=550).contains(&n), "d={d} c={c} x={x} : {n} sur ~400");
            }
        }
    }

    /// Le décodage en temps constant donne exactement les chiffres de num-bigint.
    #[test]
    fn decodage_identique_a_la_reference_bigint() {
        let qn = BigUint::from(Q).pow(N as u32);
        let mut octets = [0u8; TAILLE_VECTEUR];
        for _ in 0..30 {
            alea::remplir(&mut octets);
            let mut r = BigUint::from_bytes_be(&octets) % &qn;
            let attendu: Vec<u32> = (0..N)
                .map(|_| {
                    let d = (&r % Q).iter_u32_digits().next().unwrap_or(0);
                    r /= Q;
                    d
                })
                .collect();
            let mut obtenu = vec![0u32; N];
            vector_decode(&octets, &mut obtenu);
            assert_eq!(obtenu, attendu);
        }
    }

    /// L'encodage reste sous 2^3072 et m couvre bien jusqu'à sa borne (≈ 2^76).
    #[test]
    fn encodage_valeur_et_aller_retour() {
        let c = constantes();
        assert!(c.bits_q0 >= 76 && c.bits_q0 <= 78, "bits de q0 = {}", c.bits_q0);
        let mut ct = vec![0u8; TAILLE_CT];
        for _ in 0..20 {
            alea::remplir(&mut ct);
            let enc = encoder_chiffre(&ct);
            assert_eq!(decoder_chiffre(&enc), ct);
        }
        let mut x = [0u8; TAILLE_ENCODEE];
        alea::remplir(&mut x);
        assert_eq!(decoder_chiffre(&x).len(), TAILLE_CT);
        // Le bit de poids fort de la sortie doit valoir 1 environ une fois sur deux.
        let a = vec![1u32; N];
        let uns = (0..400).filter(|_| vector_encode(&a)[0] & 0x80 != 0).count();
        assert!((150..=250).contains(&uns), "bit de poids fort : {uns}/400");
    }
}
