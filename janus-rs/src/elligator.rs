//! Inverse de la carte Elligator 2 pour Curve25519, sur un point QUELCONQUE.
//!
//! Pourquoi ce module (docs/04-preuve-deux-visages.md, § 7.1) : le crate
//! `curve25519-elligator2` ne sait calculer le représentant que d'un point
//! `clamp(x)·B + L`, avec un scalaire clampé. Ces scalaires ne couvrent que la
//! moitié du sous-groupe premier, ce qu'un adversaire capable de calculer des
//! logarithmes discrets (ordinateur quantique) sait tester. Janus tire donc
//! `e` uniformément modulo ℓ et calcule ici le représentant de `e·B + L`.
//!
//! Formules (Bernstein, Hamburg, Krasnova, Lange, 2013), identiques à celles du
//! crate pour rester compatibles avec sa carte directe (RFC 9380, § 6.7.1, Z = 2) :
//!   u représentable  ⇔  −2·u·(u + A) est un carré non nul
//!   r = t / √(−2·u·(u + A)),  avec t = u ou t = u + A selon le bit 0 de `tweak`
//!   r est ramené dans [0, (p − 1)/2], puis les 2 bits de poids fort reçoivent
//!   les bits 6 et 7 de `tweak`.
//!
//! L'arithmétique modulo p = 2²⁵⁵ − 19 vient de fiat-crypto (code généré et
//! prouvé correct, en temps constant). Les exposants sont publics et fixes :
//! les exponentiations sont en temps constant vis-à-vis de la base.

use fiat_crypto::curve25519_64::{
    fiat_25519_add, fiat_25519_carry, fiat_25519_carry_mul, fiat_25519_carry_square, fiat_25519_from_bytes,
    fiat_25519_loose_field_element, fiat_25519_opp, fiat_25519_relax, fiat_25519_selectznz,
    fiat_25519_tight_field_element, fiat_25519_to_bytes,
};
use subtle::{Choice, ConstantTimeEq, CtOption};

/// Élément de F_p, p = 2²⁵⁵ − 19.
#[derive(Clone, Copy)]
struct Fe(fiat_25519_tight_field_element);

const fn octets_le(premier: u8, dernier: u8) -> [u8; 32] {
    let mut b = [0xffu8; 32];
    b[0] = premier;
    b[31] = dernier;
    b
}
/// p − 2 = 2²⁵⁵ − 21 (inversion par Fermat).
const EXP_INVERSE: [u8; 32] = octets_le(0xeb, 0x7f);
/// (p + 3) / 8 = 2²⁵² − 2 (racine carrée, p ≡ 5 mod 8).
const EXP_RACINE: [u8; 32] = octets_le(0xfe, 0x0f);
/// (p − 1) / 4 = 2²⁵³ − 5 : 2^((p−1)/4) est une racine carrée de −1.
const EXP_SQRT_M1: [u8; 32] = octets_le(0xfb, 0x1f);

impl Fe {
    fn depuis_octets(b: &[u8; 32]) -> Fe {
        let mut b = *b;
        b[31] &= 0x7f;
        let mut o = fiat_25519_tight_field_element([0; 5]);
        fiat_25519_from_bytes(&mut o, &b);
        Fe(o)
    }

    fn petit(n: u32) -> Fe {
        let mut b = [0u8; 32];
        b[..4].copy_from_slice(&n.to_le_bytes());
        Fe::depuis_octets(&b)
    }

    /// Forme canonique (< p), sur 32 octets petit-boutistes.
    fn octets(&self) -> [u8; 32] {
        let mut o = [0u8; 32];
        fiat_25519_to_bytes(&mut o, &self.0);
        o
    }

    fn lache(&self) -> fiat_25519_loose_field_element {
        let mut l = fiat_25519_loose_field_element([0; 5]);
        fiat_25519_relax(&mut l, &self.0);
        l
    }

    fn resserrer(l: &fiat_25519_loose_field_element) -> Fe {
        let mut o = fiat_25519_tight_field_element([0; 5]);
        fiat_25519_carry(&mut o, l);
        Fe(o)
    }

    fn mul(&self, b: &Fe) -> Fe {
        let mut o = fiat_25519_tight_field_element([0; 5]);
        fiat_25519_carry_mul(&mut o, &self.lache(), &b.lache());
        Fe(o)
    }

    fn carre(&self) -> Fe {
        let mut o = fiat_25519_tight_field_element([0; 5]);
        fiat_25519_carry_square(&mut o, &self.lache());
        Fe(o)
    }

    fn add(&self, b: &Fe) -> Fe {
        let mut l = fiat_25519_loose_field_element([0; 5]);
        fiat_25519_add(&mut l, &self.0, &b.0);
        Fe::resserrer(&l)
    }

    fn neg(&self) -> Fe {
        let mut l = fiat_25519_loose_field_element([0; 5]);
        fiat_25519_opp(&mut l, &self.0);
        Fe::resserrer(&l)
    }

    /// `a` si `c` vaut 0, `b` si `c` vaut 1, sans branchement.
    fn choisir(a: &Fe, b: &Fe, c: Choice) -> Fe {
        let mut o = [0u64; 5];
        fiat_25519_selectznz(&mut o, c.unwrap_u8(), &a.0 .0, &b.0 .0);
        Fe(fiat_25519_tight_field_element(o))
    }

    fn egal(&self, b: &Fe) -> Choice {
        self.octets().ct_eq(&b.octets())
    }

    /// self^exp, exposant public : même suite d'opérations pour toute base.
    fn puissance(&self, exp: &[u8; 32]) -> Fe {
        let mut r = Fe::petit(1);
        for i in (0..256).rev() {
            r = r.carre();
            let m = r.mul(self);
            r = Fe::choisir(&r, &m, Choice::from((exp[i / 8] >> (i % 8)) & 1));
        }
        r
    }

    /// (est un carré non nul, 1/√self).
    fn inverse_racine(&self) -> (Choice, Fe) {
        let w = self.puissance(&EXP_INVERSE); // 1/self (0 si self = 0)
        let x = w.puissance(&EXP_RACINE);
        let x2 = x.carre();
        let direct = x2.egal(&w);
        let tordu = x2.egal(&w.neg());
        let sqrt_m1 = Fe::petit(2).puissance(&EXP_SQRT_M1);
        let x = Fe::choisir(&x, &x.mul(&sqrt_m1), tordu);
        let nul = self.egal(&Fe::petit(0));
        ((direct | tordu) & !nul, x)
    }
}

/// Coefficient A de la courbe de Montgomery v² = u³ + A·u² + u.
const A: u32 = 486_662;

/// Représentant Elligator 2 du point de coordonnée `u` (32 octets, forme
/// canonique), ou rien si `u` n'est pas représentable (environ une fois sur deux).
/// Compatible avec `Randomized::from_representative` du crate (carte directe).
pub fn representant(u: &[u8; 32], tweak: u8) -> CtOption<[u8; 32]> {
    let u = Fe::depuis_octets(u);
    let u_plus_a = u.add(&Fe::petit(A));
    let t = u.mul(&u_plus_a);
    let den = t.add(&t).neg(); // −2·u·(u + A)
    let (carre, s) = den.inverse_racine();
    let num = Fe::choisir(&u, &u_plus_a, Choice::from(tweak & 1));
    let r = num.mul(&s);
    // Racine « positive » : 2r mod p est pair exactement quand r ≤ (p − 1)/2.
    let impair = Choice::from(r.add(&r).octets()[0] & 1);
    let r = Fe::choisir(&r, &r.neg(), impair);
    let mut b = r.octets();
    b[31] |= tweak & 0xc0;
    CtOption::new(b, carre)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alea;
    use curve25519_elligator2::{EdwardsPoint, MapToPointVariant, Randomized};

    #[test]
    fn arithmetique_de_base() {
        let m1 = Fe::petit(2).puissance(&EXP_SQRT_M1).carre();
        assert!(bool::from(m1.egal(&Fe::petit(1).neg())), "√−1 faux");
        let x = Fe::petit(123_456_789);
        assert!(bool::from(x.mul(&x.puissance(&EXP_INVERSE)).egal(&Fe::petit(1))), "inverse faux");
        let (ok, s) = Fe::petit(4).inverse_racine();
        assert!(bool::from(ok) && bool::from(s.carre().mul(&Fe::petit(4)).egal(&Fe::petit(1))));
        assert!(!bool::from(Fe::petit(2).inverse_racine().0), "2 n'est pas un carré modulo p");
        assert!(!bool::from(Fe::petit(0).inverse_racine().0));
        assert!(bool::from(x.add(&x.neg()).egal(&Fe::petit(0))));
    }

    /// Sur les points que le crate sait représenter, on doit donner exactement
    /// le même représentant, octet pour octet, avec le même `tweak`.
    #[test]
    fn identique_au_crate_sur_ses_points() {
        let (mut compares, mut representables) = (0, 0);
        for _ in 0..2000 {
            let x = alea::octets::<32>();
            let tweak = alea::octets::<1>()[0];
            let u = Randomized::mul_base_clamped(x).to_montgomery().to_bytes();
            let attendu: Option<[u8; 32]> = Randomized::to_representative(&x, tweak).into();
            let obtenu: Option<[u8; 32]> = representant(&u, tweak).into();
            assert_eq!(attendu, obtenu, "désaccord avec le crate");
            compares += 1;
            representables += obtenu.is_some() as u32;
        }
        assert!((800..1200).contains(&representables), "{representables} représentables sur {compares}");
    }

    /// Aller-retour sur des points quelconques (scalaire uniforme modulo ℓ).
    #[test]
    fn aller_retour_sur_points_quelconques() {
        use curve25519_elligator2::Scalar;
        let mut reussis = 0;
        for _ in 0..1000 {
            let e = Scalar::from_bytes_mod_order_wide(&alea::octets::<64>());
            let u = EdwardsPoint::mul_base(&e).to_montgomery().to_bytes();
            let tweak = alea::octets::<1>()[0];
            if let Some(r) = Option::<[u8; 32]>::from(representant(&u, tweak)) {
                assert_eq!(r[31] & 0xc0, tweak & 0xc0);
                let p: Option<EdwardsPoint> = Randomized::from_representative(&r).into();
                assert_eq!(p.unwrap().to_montgomery().to_bytes(), u, "aller-retour faux");
                reussis += 1;
            }
        }
        assert!(reussis > 400);
    }
}
