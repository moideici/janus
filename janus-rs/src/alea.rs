//! Aléa : uniquement celui du système d'exploitation (cartographie § 2.1).
//!
//! Pour produire des vecteurs de test reproductibles (spec § 13.1), les tests
//! internes peuvent remplacer temporairement l'aléa par un flux SHAKE256 issu
//! d'une graine. Ce mécanisme n'existe que dans les binaires de test
//! (`cfg(test)`) : il est absent du programme réel.

pub fn remplir(buf: &mut [u8]) {
    #[cfg(test)]
    if deterministe::remplir(buf) {
        return;
    }
    getrandom::fill(buf).expect("générateur du système indisponible");
}

pub fn octets<const L: usize>() -> [u8; L] {
    let mut b = [0u8; L];
    remplir(&mut b);
    b
}

/// Entier uniforme dans [0, borne) par rejet (sans biais).
pub fn uniforme_u32(borne: u32) -> u32 {
    assert!(borne > 0);
    let zone = u32::MAX - (u32::MAX % borne);
    loop {
        let x = u32::from_le_bytes(octets::<4>());
        if x < zone {
            return x % borne;
        }
    }
}

/// Entier uniforme dans [0, max] par rejet, en tirant juste assez de bits.
pub fn uniforme_u64_jusqua(max: u64) -> u64 {
    if max == u64::MAX {
        return u64::from_le_bytes(octets::<8>());
    }
    let bits = 64 - max.leading_zeros();
    let masque = (1u64 << bits) - 1;
    loop {
        let x = u64::from_le_bytes(octets::<8>()) & masque;
        if x <= max {
            return x;
        }
    }
}

#[cfg(test)]
pub mod deterministe {
    use shake::{ExtendableOutput, Shake256, Shake256Reader, Update, XofReader};
    use std::cell::RefCell;

    thread_local! {
        static FLUX: RefCell<Option<Shake256Reader>> = const { RefCell::new(None) };
    }

    pub(super) fn remplir(buf: &mut [u8]) -> bool {
        FLUX.with(|f| match f.borrow_mut().as_mut() {
            Some(lecteur) => {
                lecteur.read(buf);
                true
            }
            None => false,
        })
    }

    /// Exécute `f` avec un aléa entièrement déterminé par `graine` (fil courant).
    pub fn avec_graine<T>(graine: &[u8], f: impl FnOnce() -> T) -> T {
        let mut x = Shake256::default();
        x.update(b"janus/v0/vecteurs-de-test");
        x.update(graine);
        FLUX.with(|fl| *fl.borrow_mut() = Some(x.finalize_xof()));
        let r = f();
        FLUX.with(|fl| *fl.borrow_mut() = None);
        r
    }
}
