//! X-Wing (draft-connolly-cfrg-xwing-kem-11) : ML-KEM-768 + X25519.
//!
//! Deux encapsulations :
//! - `encapsuler_derand` : X-Wing standard, utilisée seulement pour le vecteur de test du draft ;
//! - `encapsuler_cache` : la variante Janus (spec § 6), même cryptographie, mais
//!   l'éphémère X25519 est un point « sale » transmis par son représentant
//!   Elligator 2, et le chiffré ML-KEM est encodé par Kemeleon.
//!
//! La décapsulation est la fonction X-Wing standard appliquée après décodage.

use crate::{alea, elligator, kemeleon};
use curve25519_elligator2::{EdwardsPoint, MapToPointVariant, MontgomeryPoint, Randomized, Scalar};
use ml_kem::kem::{Decapsulate, KeyExport};
use ml_kem::{DecapsulationKey768, EncapsulationKey768};
use sha3::Digest;
use shake::{ExtendableOutput, Shake256, Update, XofReader};
use sha3::Sha3_256;
use zeroize::{Zeroize, Zeroizing};

pub const TAILLE_PK: usize = 1216;
pub const TAILLE_PK_M: usize = 1184;
pub const XWING_LABEL: &[u8; 6] = b"\\.//^\\";

pub struct Identite {
    graine: Zeroizing<[u8; 32]>,
    dk_m: DecapsulationKey768,
    sk_x: Zeroizing<[u8; 32]>,
    pk: [u8; TAILLE_PK],
}

impl Identite {
    pub fn generer() -> Self {
        Self::depuis_graine(&alea::octets::<32>())
    }

    /// expandDecapsulationKey : SHAKE256(graine) sur 96 octets → (d, z, sk_X).
    pub fn depuis_graine(graine: &[u8; 32]) -> Self {
        let mut etendu = Zeroizing::new([0u8; 96]);
        let mut xof = Shake256::default();
        xof.update(graine);
        xof.finalize_xof().read(&mut etendu[..]);
        let seed_m = ml_kem::Seed::try_from(&etendu[..64]).expect("64 octets");
        let dk_m = DecapsulationKey768::from_seed(seed_m);
        let mut sk_x = Zeroizing::new([0u8; 32]);
        sk_x.copy_from_slice(&etendu[64..]);
        let pk_x = MontgomeryPoint::mul_base_clamped(*sk_x).to_bytes();
        let mut pk = [0u8; TAILLE_PK];
        pk[..TAILLE_PK_M].copy_from_slice(&dk_m.encapsulation_key().to_bytes());
        pk[TAILLE_PK_M..].copy_from_slice(&pk_x);
        Identite { graine: Zeroizing::new(*graine), dk_m, sk_x, pk }
    }

    pub fn graine(&self) -> &[u8; 32] {
        &self.graine
    }

    pub fn cle_publique(&self) -> &[u8; TAILLE_PK] {
        &self.pk
    }

    /// Décapsulation standard (ct = ct_M ‖ ct_X).
    pub fn decapsuler(&self, ct_m: &[u8], ct_x: &[u8; 32]) -> Zeroizing<[u8; 32]> {
        let ss_m = self.dk_m.decapsulate_slice(ct_m).expect("1088 octets");
        let ss_x = Zeroizing::new(MontgomeryPoint(*ct_x).mul_clamped(*self.sk_x).to_bytes());
        combiner(&ss_m, &ss_x[..], ct_x, &self.pk[TAILLE_PK_M..])
    }

    /// Décapsulation d'un emplacement Janus : représentant Elligator ‖ κ masqué.
    /// Ordre : ct_X, puis ss_X, puis démasquage de κ, puis Kemeleon et ML-KEM.
    pub fn decapsuler_cache(&self, r: &[u8; 32], kappa_masque: &[u8]) -> Zeroizing<[u8; 32]> {
        let ct_x = elligator_vers_point(r);
        let ss_x = Zeroizing::new(MontgomeryPoint(ct_x).mul_clamped(*self.sk_x).to_bytes());
        let mut kappa = [0u8; kemeleon::TAILLE_ENCODEE];
        kappa.copy_from_slice(kappa_masque);
        masquer(&mut kappa, &ss_x, &ct_x);
        let ct_m = kemeleon::decoder_chiffre(&kappa);
        let ss_m = self.dk_m.decapsulate_slice(&ct_m).expect("1088 octets");
        combiner(&ss_m, &ss_x[..], &ct_x, &self.pk[TAILLE_PK_M..])
    }
}

/// Combineur X-Wing (draft-11 § 5.3) : SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ XWingLabel).
fn combiner(ss_m: &[u8], ss_x: &[u8], ct_x: &[u8], pk_x: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut h = Sha3_256::new();
    Digest::update(&mut h, ss_m);
    Digest::update(&mut h, ss_x);
    Digest::update(&mut h, ct_x);
    Digest::update(&mut h, pk_x);
    Digest::update(&mut h, XWING_LABEL);
    Zeroizing::new(h.finalize().into())
}

fn cle_ml_kem(pk: &[u8; TAILLE_PK]) -> Option<EncapsulationKey768> {
    let cle = ml_kem::array::Array::try_from(&pk[..TAILLE_PK_M]).ok()?;
    EncapsulationKey768::new(&cle).ok()
}

/// Valide une clé publique (la partie ML-KEM doit être bien formée).
pub fn cle_publique_valide(pk: &[u8; TAILLE_PK]) -> bool {
    cle_ml_kem(pk).is_some()
}

/// X-Wing EncapsulateDerand standard : sert au vecteur de test officiel.
pub fn encapsuler_derand(pk: &[u8; TAILLE_PK], eseed: &[u8; 64]) -> ([u8; 32], Vec<u8>) {
    let ek_m = cle_ml_kem(pk).expect("clé publique valide");
    let pk_x = &pk[TAILLE_PK_M..];
    let mut ek_x = [0u8; 32];
    ek_x.copy_from_slice(&eseed[32..]);
    let ct_x = MontgomeryPoint::mul_base_clamped(ek_x).to_bytes();
    let ss_x = MontgomeryPoint(pk_x.try_into().unwrap()).mul_clamped(ek_x).to_bytes();
    let m = ml_kem::B32::try_from(&eseed[..32]).unwrap();
    let (ct_m, ss_m) = ek_m.encapsulate_deterministic(&m);
    let ss = combiner(&ss_m, &ss_x, &ct_x, pk_x);
    let mut ct = ct_m.to_vec();
    ct.extend_from_slice(&ct_x);
    (*ss, ct)
}

/// Encapsulation Janus (spec § 6.1). Renvoie (ss, représentant r, κ masqué).
pub fn encapsuler_cache(
    pk: &[u8; TAILLE_PK],
) -> Option<(Zeroizing<[u8; 32]>, [u8; 32], [u8; kemeleon::TAILLE_ENCODEE])> {
    let ek_m = cle_ml_kem(pk)?;
    let pk_x: [u8; 32] = pk[TAILLE_PK_M..].try_into().unwrap();

    let (r, ct_x, e) = ephemere_cache();
    // Le destinataire calcule clamp(sk)·P = clamp(sk)·(e·B + L) = e·clamp(sk)·B = e·pk_X,
    // car clamp(sk) est multiple de 8 et annule L.
    let ss_x = Zeroizing::new((&MontgomeryPoint(pk_x) * &*e).to_bytes());

    let mut m = ml_kem::B32::try_from(&alea::octets::<32>()[..]).unwrap();
    let (ct_m, ss_m) = ek_m.encapsulate_deterministic(&m);
    m.as_mut_slice().zeroize();

    let ss = combiner(&ss_m, &ss_x[..], &ct_x, &pk_x);
    let mut kappa = kemeleon::encoder_chiffre(&ct_m);
    masquer(&mut kappa, &ss_x, &ct_x);
    Some((ss, r, kappa))
}

const ET_MASQUE: &[u8] = b"janus/v1/masque";

/// κ ⊕= SHAKE256(« janus/v1/masque » ‖ ss_X ‖ ct_X), sur 1536 octets
/// (docs/04-preuve-deux-visages.md, § 7.2). κ masqué est pseudo-aléatoire si MLWE
/// tient (κ l'est déjà) OU si X25519 tient (le masque l'est) : la discrétion
/// devient hybride, comme la confidentialité. Le masquage est sa propre inverse.
fn masquer(kappa: &mut [u8; kemeleon::TAILLE_ENCODEE], ss_x: &[u8; 32], ct_x: &[u8; 32]) {
    let mut masque = Zeroizing::new([0u8; kemeleon::TAILLE_ENCODEE]);
    let mut xof = Shake256::default();
    xof.update(ET_MASQUE);
    xof.update(ss_x);
    xof.update(ct_x);
    xof.finalize_xof().read(&mut masque[..]);
    for (k, m) in kappa.iter_mut().zip(masque.iter()) {
        *k ^= m;
    }
}

/// Éphémère X25519 « caché » (docs/04-preuve-deux-visages.md, § 7.1 et hypothèse H6) :
/// - `e` uniforme modulo ℓ, et NON clampé : un scalaire clampé ne couvre que la
///   moitié du sous-groupe premier, ce qu'un ordinateur quantique sait tester ;
/// - `L` uniforme parmi les 8 points d'ordre faible, si bien que P = e·B + L est
///   uniforme sur toute la courbe ;
/// - on recommence tant que P n'a pas de représentant (environ un essai sur deux).
///
/// Renvoie (représentant r, ct_X = coordonnée u de P, e).
fn ephemere_cache() -> ([u8; 32], [u8; 32], Zeroizing<Scalar>) {
    loop {
        let e = Zeroizing::new(Scalar::from_bytes_mod_order_wide(&alea::octets::<64>()));
        // Le crate n'expose pas les points de torsion : L = (clamp(x)·B + L(x)) − clamp(x)·B,
        // où L(x) est choisi par les 3 bits de poids faible de x, que le clampage efface.
        let x = alea::octets::<32>();
        let l = Randomized::mul_base_clamped(x) - EdwardsPoint::mul_base_clamped(x);
        let u = (EdwardsPoint::mul_base(&e) + l).to_montgomery().to_bytes();
        let tweak = alea::octets::<1>()[0];
        if let Some(r) = Option::<[u8; 32]>::from(elligator::representant(&u, tweak)) {
            return (r, u, e);
        }
    }
}

/// Représentant Elligator 2 (bits hauts ignorés) → coordonnée u du point.
pub fn elligator_vers_point(r: &[u8; 32]) -> [u8; 32] {
    let p: Option<EdwardsPoint> = Randomized::from_representative(r).into();
    p.expect("toute chaîne a une image").to_montgomery().to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vecteur de test n° 1 de l'annexe C du draft-11 (seed, eseed, ss).
    #[test]
    fn vecteur_officiel_draft_11() {
        let seed: [u8; 32] =
            hex::decode("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
                .unwrap()
                .try_into()
                .unwrap();
        let eseed: [u8; 64] = hex::decode(concat!(
            "3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e235b8cc87",
            "3c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2"
        ))
        .unwrap()
        .try_into()
        .unwrap();
        let attendu = "d2df0522128f09dd8e2c92b1e905c793d8f57a54c3da25861f10bf4ca613e384";

        let id = Identite::depuis_graine(&seed);
        let (ss, ct) = encapsuler_derand(id.cle_publique(), &eseed);
        assert_eq!(hex::encode(ss), attendu, "encapsulation");
        let ct_x: [u8; 32] = ct[1088..].try_into().unwrap();
        assert_eq!(hex::encode(*id.decapsuler(&ct[..1088], &ct_x)), attendu, "décapsulation");
    }

    #[test]
    fn variante_cachee_donne_le_meme_secret() {
        let id = Identite::generer();
        for _ in 0..10 {
            let (ss, r, kappa) = encapsuler_cache(id.cle_publique()).unwrap();
            assert_eq!(*id.decapsuler_cache(&r, &kappa), *ss);
        }
        let autre = Identite::generer();
        let (ss, r, kappa) = encapsuler_cache(id.cle_publique()).unwrap();
        assert_ne!(*autre.decapsuler_cache(&r, &kappa), *ss);
    }

    /// Le point transmis doit bien être « sale » : sinon les représentants
    /// trahissent qu'ils proviennent du sous-groupe premier (voir le crate).
    #[test]
    fn ephemeres_sales() {
        // Un point aléatoire de la courbe n'est dans le sous-groupe premier
        // qu'une fois sur 8. Avec des éphémères propres, ce serait 100 % :
        // un distingueur immédiat.
        let id = Identite::generer();
        let essais = 400;
        let mut propres = 0;
        for _ in 0..essais {
            let (_, r, _) = encapsuler_cache(id.cle_publique()).unwrap();
            let p: Option<EdwardsPoint> = Randomized::from_representative(&r).into();
            if p.unwrap().is_torsion_free() {
                propres += 1;
            }
        }
        // Attendu ≈ 50 sur 400 ; on refuse tout ce qui s'en écarte nettement.
        assert!((20..=90).contains(&propres), "propres = {propres}/{essais}");
    }

    /// Le masque est bien appliqué : sans lui, κ se décode en un chiffré ML-KEM
    /// qui donne le bon secret ; avec lui seul, non. Et celui qui connaît ss_X
    /// (adversaire qui aurait cassé X25519) retrouve exactement l'encodage Kemeleon.
    #[test]
    fn kappa_masque_par_x25519() {
        let id = Identite::generer();
        let (ss, r, kappa_masque) = encapsuler_cache(id.cle_publique()).unwrap();
        // Décoder κ masqué sans le démasquer ne redonne pas le secret.
        let ct_x = elligator_vers_point(&r);
        assert_ne!(*id.decapsuler(&kemeleon::decoder_chiffre(&kappa_masque), &ct_x), *ss);
        // Avec ss_X, on démasque, et tout redevient cohérent.
        let ss_x = MontgomeryPoint(ct_x).mul_clamped(*id.sk_x).to_bytes();
        let mut kappa = kappa_masque;
        masquer(&mut kappa, &ss_x, &ct_x);
        assert_eq!(*id.decapsuler(&kemeleon::decoder_chiffre(&kappa), &ct_x), *ss);
        assert_eq!(*id.decapsuler_cache(&r, &kappa_masque), *ss);
    }

    /// Les 8 points d'ordre faible sont tous atteints, et rien d'autre.
    #[test]
    fn torsion_uniforme() {
        let mut vus = std::collections::HashSet::new();
        for _ in 0..400 {
            let x = alea::octets::<32>();
            let l = Randomized::mul_base_clamped(x) - EdwardsPoint::mul_base_clamped(x);
            assert!(l.is_small_order());
            vus.insert(l.compress().to_bytes());
        }
        assert_eq!(vus.len(), 8, "points d'ordre faible atteints : {}", vus.len());
    }

    /// Le test d'un adversaire capable de calculer des logarithmes discrets
    /// (docs/04-preuve-deux-visages.md, § 7.1) : un scalaire clampé vaut
    /// 2²⁵⁴ + 8k avec k < 2²⁵¹. Avec le vrai logarithme e, il calcule
    /// k = (e − 2²⁵⁴)·8⁻¹ mod ℓ et regarde si k < 2²⁵¹.
    #[test]
    fn le_scalaire_ephemere_couvre_tout_le_sous_groupe() {
        let mut deux_254 = [0u8; 32];
        deux_254[31] = 0x40;
        let s254 = Scalar::from_bytes_mod_order(deux_254);
        let inv8 = Scalar::from(8u64).invert();
        let dans_la_moitie_clampee = |e: &Scalar| ((e - s254) * inv8).to_bytes()[31] < 0x08;
        let n = 2000;
        // Témoin : l'ancien tirage clampé tombe TOUJOURS dans la moitié.
        let clampes = (0..n)
            .filter(|_| {
                let mut x = alea::octets::<32>();
                x[0] &= 248;
                x[31] &= 127;
                x[31] |= 64;
                dans_la_moitie_clampee(&Scalar::from_bytes_mod_order(x))
            })
            .count();
        assert_eq!(clampes, n, "le témoin doit être détecté à 100 %");
        // Janus : environ une fois sur deux, comme un point aléatoire.
        let janus = (0..n).filter(|_| dans_la_moitie_clampee(&ephemere_cache().2)).count();
        assert!((850..1150).contains(&janus), "{janus} sur {n} dans la moitié clampée");
    }

    /// Le point transmis est bien e·B + L : multiplier par 8 retrouve 8e·B.
    #[test]
    fn le_point_transmis_correspond_au_scalaire() {
        for _ in 0..50 {
            let (r, u, e) = ephemere_cache();
            assert_eq!(elligator_vers_point(&r), u);
            let p: Option<EdwardsPoint> = Randomized::from_representative(&r).into();
            let huit_e = Scalar::from(8u64) * *e;
            let attendu = EdwardsPoint::mul_base(&huit_e).to_montgomery().to_bytes();
            assert_eq!(p.unwrap().mul_by_cofactor().to_montgomery().to_bytes(), attendu);
        }
    }
}
