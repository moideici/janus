//! Hygiène mémoire (exigence J-10) : le seul module qui contient du code `unsafe`.
//!
//! Trois protections, toutes « au mieux » : un échec n'empêche jamais Janus de
//! fonctionner, il ôte seulement une défense en profondeur.
//! - **Verrouillage en mémoire vive** (`mlock`, `VirtualLock`) des secrets de longue
//!   durée : identité, mots de passe. Ils ne partent pas dans le fichier d'échange.
//!   Les gros tampons de clair ne sont verrouillés que si le système l'accepte
//!   (les limites sont basses : souvent 8 Mio sous Linux, quelques centaines de Kio
//!   sous Windows). Contre l'échange, la vraie parade reste un fichier d'échange chiffré.
//! - **Pas de fichier core** (`RLIMIT_CORE = 0`), et sous Linux, processus non
//!   « dumpable » : un autre programme du même utilisateur ne peut plus lire sa
//!   mémoire par ptrace.
//! - **Lecture sans copie oubliée** : `lire_tout` agrandit un tampon secret sans
//!   laisser derrière lui les anciennes copies, que `Vec` libérerait sans les effacer.
//!
//! Le verrouillage porte sur des pages entières. Deux secrets voisins peuvent partager
//! une page : déverrouiller l'un déverrouille alors la page de l'autre. Les secrets
//! verrouillés vivent donc dans des allocations à eux (Box, String, Vec).

#![allow(unsafe_code)]

use std::io::{self, Read};
use zeroize::Zeroizing;

/// Une région de mémoire verrouillée tant que le verrou vit.
///
/// À placer APRÈS la valeur qu'il protège dans une structure : les champs sont
/// détruits dans l'ordre de déclaration, donc la valeur est effacée (zeroize)
/// avant que ses pages ne soient déverrouillées.
#[derive(Debug)]
pub struct Verrou {
    adresse: usize,
    taille: usize,
    actif: bool,
}

impl Verrou {
    /// Verrouille la mémoire occupée par `valeur`. Pour une `String` ou un `Vec`,
    /// passer le contenu (`s.as_bytes()`, `&v[..]`), pas la structure elle-même.
    pub fn sur<T: ?Sized>(valeur: &T) -> Verrou {
        let adresse = std::ptr::from_ref(valeur).cast::<u8>() as usize;
        let taille = std::mem::size_of_val(valeur);
        let actif = taille > 0 && sys::verrouiller(adresse, taille);
        Verrou { adresse, taille, actif }
    }

    /// Vrai si le système a accepté le verrouillage.
    pub fn actif(&self) -> bool {
        self.actif
    }
}

impl Drop for Verrou {
    fn drop(&mut self) {
        if self.actif {
            sys::deverrouiller(self.adresse, self.taille);
        }
    }
}

/// Un texte secret (mot de passe), effacé à la destruction et verrouillé en mémoire.
pub struct TexteSecret {
    texte: Zeroizing<String>,
    _verrou: Verrou,
}

impl TexteSecret {
    pub fn new(texte: Zeroizing<String>) -> TexteSecret {
        let verrou = Verrou::sur(texte.as_bytes());
        TexteSecret { texte, _verrou: verrou }
    }
}

impl std::ops::Deref for TexteSecret {
    type Target = str;
    fn deref(&self) -> &str {
        &self.texte
    }
}

/// Lit tout `entree` dans un tampon effacé à la destruction. Contrairement à
/// `read_to_end`, chaque agrandissement copie le contenu dans un tampon neuf puis
/// EFFACE l'ancien : aucune copie partielle du secret ne reste dans le tas.
pub fn lire_tout<R: Read>(entree: &mut R) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut tampon = Zeroizing::new(Vec::with_capacity(1 << 16));
    let mut morceau = Zeroizing::new([0u8; 1 << 16]);
    loop {
        let n = match entree.read(&mut morceau[..]) {
            Ok(0) => return Ok(tampon),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if tampon.len() + n > tampon.capacity() {
            let mut neuf = Zeroizing::new(Vec::with_capacity((tampon.len() + n).next_power_of_two()));
            neuf.extend_from_slice(&tampon);
            tampon = neuf; // l'ancien tampon est effacé ici
        }
        tampon.extend_from_slice(&morceau[..n]);
    }
}

/// Durcit le processus : pas de fichier core, et sous Linux, pas de lecture de sa
/// mémoire par un autre processus du même utilisateur (ptrace).
pub fn durcir_processus() {
    sys::durcir();
}

#[cfg(unix)]
mod sys {
    use std::ffi::{c_int, c_void};

    #[repr(C)]
    struct Rlimit {
        courant: u64,
        maximum: u64,
    }

    // RLIMIT_CORE vaut 4 sous Linux comme sous macOS ; rlim_t y fait 64 bits.
    const RLIMIT_CORE: c_int = 4;
    #[cfg(target_os = "linux")]
    const PR_SET_DUMPABLE: c_int = 4;

    unsafe extern "C" {
        fn mlock(adresse: *const c_void, taille: usize) -> c_int;
        fn munlock(adresse: *const c_void, taille: usize) -> c_int;
        fn setrlimit(ressource: c_int, limite: *const Rlimit) -> c_int;
        #[cfg(target_os = "linux")]
        fn prctl(option: c_int, arg2: std::ffi::c_ulong, arg3: std::ffi::c_ulong, arg4: std::ffi::c_ulong, arg5: std::ffi::c_ulong) -> c_int;
    }

    pub fn verrouiller(adresse: usize, taille: usize) -> bool {
        // SAFETY : mlock ne lit ni n'écrit la mémoire ; il agit sur les pages de la
        // région [adresse, adresse + taille), qui appartient à une valeur vivante.
        unsafe { mlock(adresse as *const c_void, taille) == 0 }
    }

    pub fn deverrouiller(adresse: usize, taille: usize) {
        // SAFETY : même région que celle verrouillée, encore allouée (voir Verrou).
        unsafe {
            munlock(adresse as *const c_void, taille);
        }
    }

    pub fn durcir() {
        if cfg!(target_pointer_width = "64") {
            let zero = Rlimit { courant: 0, maximum: 0 };
            // SAFETY : setrlimit lit une structure valide qui vit pendant l'appel.
            unsafe {
                setrlimit(RLIMIT_CORE, &zero);
            }
        }
        #[cfg(target_os = "linux")]
        // SAFETY : PR_SET_DUMPABLE prend un entier ; les autres arguments sont ignorés.
        unsafe {
            prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
        }
    }
}

#[cfg(windows)]
mod sys {
    use std::ffi::c_void;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn VirtualLock(adresse: *const c_void, taille: usize) -> i32;
        fn VirtualUnlock(adresse: *const c_void, taille: usize) -> i32;
    }

    pub fn verrouiller(adresse: usize, taille: usize) -> bool {
        // SAFETY : VirtualLock ne lit ni n'écrit la mémoire ; la région appartient à
        // une valeur vivante.
        unsafe { VirtualLock(adresse as *const c_void, taille) != 0 }
    }

    pub fn deverrouiller(adresse: usize, taille: usize) {
        // SAFETY : même région que celle verrouillée, encore allouée.
        unsafe {
            VirtualUnlock(adresse as *const c_void, taille);
        }
    }

    /// Windows n'écrit pas de fichier core ; les rapports d'erreur (WER) relèvent
    /// de la configuration du système.
    pub fn durcir() {}
}

#[cfg(not(any(unix, windows)))]
mod sys {
    pub fn verrouiller(_: usize, _: usize) -> bool {
        false
    }
    pub fn deverrouiller(_: usize, _: usize) {}
    pub fn durcir() {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verrouillage_d_un_petit_secret() {
        let secret = Box::new([7u8; 64]);
        let v = Verrou::sur(&*secret);
        // Linux et Windows acceptent toujours quelques octets ; macOS aussi en général.
        if cfg!(any(target_os = "linux", windows)) {
            assert!(v.actif(), "le verrouillage d'un petit secret devrait réussir");
        }
        drop(v);
        assert!(!Verrou::sur(&[0u8; 0][..]).actif(), "une région vide n'est pas verrouillée");
    }

    #[test]
    fn lire_tout_redonne_l_entree() {
        for n in [0usize, 1, 65_535, 65_536, 65_537, 1_000_003] {
            let donnees: Vec<u8> = (0..n).map(|k| (k * 31 + 7) as u8).collect();
            let lu = lire_tout(&mut &donnees[..]).unwrap();
            assert_eq!(&lu[..], &donnees[..], "n = {n}");
        }
    }

    #[test]
    fn texte_secret() {
        let t = TexteSecret::new(Zeroizing::new("mot de passe".to_string()));
        assert_eq!(&*t, "mot de passe");
        durcir_processus();
    }
}
