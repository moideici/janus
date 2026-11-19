//! Ligne de commande du prototype Janus v1 (deux visages).
//!
//!   janus cles <fichier-identité>                 crée une identité, affiche la clé publique
//!   janus publique <fichier-identité>             réaffiche la clé publique
//!   janus chiffrer <destinataires> <entrée> <sortie> [--cache <destinataires> <entrée-secrète>]
//!   janus dechiffrer (-i <fichier-identité>… | -m) <entrée> <sortie>
//!   janus inspect <fichier>…                       ce qu'un tiers voit d'un fichier, sans clé
//!
//! <destinataires> : -r <clé publique>, -R <fichier de clés>, répétables, ou -m (mot de passe).
//! Tout ce qui suit --cache décrit le visage caché. `dechiffrer` ouvre le visage qui
//! correspond à l'identifiant donné et ne signale jamais l'existence de l'autre.
//!
//! Les fichiers sont traités en flux : la mémoire utilisée ne dépend pas de leur taille.
//! Pour les tests automatiques seulement, les variables JANUS_MDP et JANUS_MDP_CACHE
//! fournissent les mots de passe sans les demander.

use janus::cles;
use janus::format::{self, Destinataires, Ouverture, Visage};
use janus::xwing::{Identite, TAILLE_PK};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use zeroize::Zeroizing;

const AVERTISSEMENT: &str =
    "Prototype de recherche : format non figé, ne pas l'utiliser pour de vrais secrets.";
const TAMPON: usize = 1 << 20;

fn usage() -> ExitCode {
    eprintln!(
        "{AVERTISSEMENT}\n\nUsage :\n  janus cles <fichier-identité>\n  janus publique <fichier-identité>\n  \
         janus chiffrer (-r <clé> | -R <fichier-clé> | -m)… <entrée> <sortie> \
         [--cache (-r <clé> | -R <fichier-clé> | -m)… <entrée-secrète>]\n  \
         janus dechiffrer (-i <fichier-identité> | -m)… <entrée> <sortie>\n  \
         janus inspect <fichier>…"
    );
    ExitCode::from(2)
}

fn lire_mdp(variable: &str, invite: &str, confirmer: bool) -> Result<Zeroizing<String>, String> {
    if let Ok(m) = std::env::var(variable) {
        return Ok(Zeroizing::new(m));
    }
    let m = Zeroizing::new(rpassword::prompt_password(format!("{invite} : ")).map_err(|e| e.to_string())?);
    if confirmer {
        let m2 = Zeroizing::new(rpassword::prompt_password("Confirmer : ").map_err(|e| e.to_string())?);
        if *m != *m2 {
            return Err("les deux mots de passe diffèrent".into());
        }
    }
    if m.is_empty() {
        return Err("mot de passe vide".into());
    }
    Ok(m)
}

/// J-06 : on écrit dans un fichier temporaire voisin, puis on renomme seulement
/// si tout a réussi. En cas d'échec, le fichier temporaire est supprimé.
fn ecrire_atomique(sortie: &Path, ecrire: impl FnOnce(&mut File) -> Result<(), String>) -> Result<(), String> {
    if sortie.exists() {
        return Err(format!("{} existe déjà, je ne l'écrase pas", sortie.display()));
    }
    let mut tmp = PathBuf::from(sortie);
    tmp.set_extension("janus-tmp");
    let res = (|| {
        let mut f = File::create_new(&tmp).map_err(|e| format!("{} : {e}", tmp.display()))?;
        ecrire(&mut f)?;
        f.sync_all().map_err(|e| e.to_string())?;
        drop(f);
        fs::rename(&tmp, sortie).map_err(|e| e.to_string())
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res
}

/// Destinataires et fichiers d'un visage, lus sur la ligne de commande.
#[derive(Default)]
struct Arguments {
    cles: Vec<[u8; TAILLE_PK]>,
    identites: Vec<Identite>,
    mdp: bool,
    positionnels: Vec<String>,
}

fn analyser(args: &[String], chiffrer: bool) -> Result<Arguments, String> {
    let mut a = Arguments::default();
    let mut it = args.iter();
    while let Some(x) = it.next() {
        match x.as_str() {
            "-r" if chiffrer => {
                let t = it.next().ok_or("-r attend une clé")?;
                a.cles.push(cles::publique_depuis_texte(t).ok_or("clé publique illisible")?);
            }
            "-R" if chiffrer => {
                let t = lire_texte(Path::new(it.next().ok_or("-R attend un fichier")?))?;
                for ligne in t.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#')) {
                    a.cles.push(cles::publique_depuis_texte(ligne).ok_or("clé publique illisible")?);
                }
            }
            "-i" if !chiffrer => {
                a.identites.push(lire_identite(Path::new(it.next().ok_or("-i attend un fichier")?))?);
            }
            "-m" => a.mdp = true,
            _ => a.positionnels.push(x.clone()),
        }
    }
    if a.mdp && !a.cles.is_empty() {
        return Err("un mot de passe ne se combine pas avec des clés dans un même visage (règle R1)".into());
    }
    Ok(a)
}

fn ouvrir_entree(chemin: &str) -> Result<(BufReader<File>, u64), String> {
    let f = File::open(chemin).map_err(|e| format!("{chemin} : {e}"))?;
    let taille = f.metadata().map_err(|e| e.to_string())?.len();
    Ok((BufReader::with_capacity(TAMPON, f), taille))
}

fn chiffrer(args: &[String]) -> Result<(), String> {
    let (avant, apres) = match args.iter().position(|a| a == "--cache") {
        Some(p) => (&args[..p], Some(&args[p + 1..])),
        None => (args, None),
    };
    let principal = analyser(avant, true)?;
    let [entree, sortie] = principal.positionnels.as_slice() else {
        return Err("il faut une entrée et une sortie".into());
    };
    let cache = apres.map(|a| analyser(a, true)).transpose()?;
    let entree_cachee = match &cache {
        Some(c) => match c.positionnels.as_slice() {
            [e] => Some(e.clone()),
            _ => return Err("--cache attend ses destinataires puis une seule entrée".into()),
        },
        None => None,
    };

    let m1;
    let dest1 = if principal.mdp {
        m1 = lire_mdp("JANUS_MDP", "Mot de passe du leurre", true)?;
        Destinataires::MotDePasse(m1.as_bytes())
    } else {
        Destinataires::Cles(&principal.cles)
    };
    let (mut lecteur1, longueur1) = ouvrir_entree(entree)?;
    let m2;
    let mut lecteur2 = None;
    let mut visage_cache = None;
    if let (Some(c), Some(e)) = (&cache, &entree_cachee) {
        let dest2 = if c.mdp {
            m2 = lire_mdp("JANUS_MDP_CACHE", "Mot de passe du visage caché", true)?;
            Destinataires::MotDePasse(m2.as_bytes())
        } else {
            Destinataires::Cles(&c.cles)
        };
        let (l, n) = ouvrir_entree(e)?;
        lecteur2 = Some(l);
        visage_cache = Some((dest2, n));
    }
    ecrire_atomique(Path::new(sortie), |f| {
        let mut w = BufWriter::with_capacity(TAMPON, &mut *f);
        let principal = Visage { entree: &mut lecteur1, longueur: longueur1, dest: dest1 };
        let cache = match (visage_cache, lecteur2.as_mut()) {
            (Some((dest, longueur)), Some(l)) => Some(Visage { entree: l, longueur, dest }),
            _ => None,
        };
        format::chiffrer_flux(principal, cache, &mut w).map_err(|e| e.to_string())?;
        w.flush().map_err(|e| e.to_string())
    })
}

fn dechiffrer(args: &[String]) -> Result<(), String> {
    let a = analyser(args, false)?;
    let [entree, sortie] = a.positionnels.as_slice() else {
        return Err("il faut une entrée et une sortie".into());
    };
    let m;
    let ouv = if a.mdp {
        m = lire_mdp("JANUS_MDP", "Mot de passe", false)?;
        Ouverture::MotDePasse(m.as_bytes())
    } else if a.identites.is_empty() {
        return Err("il faut -i <identité> ou -m".into());
    } else {
        Ouverture::Identites(&a.identites)
    };
    let (mut lecteur, taille) = ouvrir_entree(entree)?;
    ecrire_atomique(Path::new(sortie), |f| {
        let mut w = BufWriter::with_capacity(TAMPON, &mut *f);
        format::dechiffrer_flux(&mut lecteur, taille, ouv, &mut w).map_err(|e| e.to_string())?;
        w.flush().map_err(|e| e.to_string())
    })
}

fn executer(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("cles") if args.len() == 2 => {
            let id = Identite::generer();
            let pub_txt = cles::publique_vers_texte(id.cle_publique());
            let contenu = Zeroizing::new(format!(
                "# Identité Janus (PROTOTYPE). Clé publique :\n# {pub_txt}\n{}\n",
                *cles::secrete_vers_texte(&id)
            ));
            ecrire_atomique(Path::new(&args[1]), |f| f.write_all(contenu.as_bytes()).map_err(|e| e.to_string()))?;
            println!("{pub_txt}");
            Ok(())
        }
        Some("publique") if args.len() == 2 => {
            let id = lire_identite(Path::new(&args[1]))?;
            println!("{}", cles::publique_vers_texte(id.cle_publique()));
            Ok(())
        }
        Some("inspect") if args.len() >= 2 => {
            for (i, chemin) in args[1..].iter().enumerate() {
                let mut f = File::open(chemin).map_err(|e| format!("{chemin} : {e}"))?;
                let rapport = janus::inspect::inspecter(&mut f).map_err(|e| format!("{chemin} : {e}"))?;
                if i > 0 {
                    println!();
                }
                println!("══ {chemin}");
                print!("{rapport}");
            }
            Ok(())
        }
        Some("chiffrer") => chiffrer(&args[1..]),
        Some("dechiffrer") => dechiffrer(&args[1..]),
        _ => Err(String::new()),
    }
}

/// Lit un fichier de clés en UTF-8 ou en UTF-16 (avec BOM) : la redirection `>`
/// de Windows PowerShell 5 écrit en UTF-16, et un utilisateur ne doit pas s'en soucier.
fn lire_texte(chemin: &Path) -> Result<Zeroizing<String>, String> {
    let octets = Zeroizing::new(fs::read(chemin).map_err(|e| format!("{} : {e}", chemin.display()))?);
    let illisible = || format!("{} : encodage de texte non reconnu", chemin.display());
    let utf16 = |o: &[u8], le: bool| {
        let unites: Vec<u16> = o
            .chunks_exact(2)
            .map(|p| if le { u16::from_le_bytes([p[0], p[1]]) } else { u16::from_be_bytes([p[0], p[1]]) })
            .collect();
        String::from_utf16(&unites).map_err(|_| illisible())
    };
    let texte = match octets.as_slice() {
        [0xFF, 0xFE, reste @ ..] => utf16(reste, true)?,
        [0xFE, 0xFF, reste @ ..] => utf16(reste, false)?,
        [0xEF, 0xBB, 0xBF, reste @ ..] => String::from_utf8(reste.to_vec()).map_err(|_| illisible())?,
        o => String::from_utf8(o.to_vec()).map_err(|_| illisible())?,
    };
    Ok(Zeroizing::new(texte))
}

fn lire_identite(chemin: &Path) -> Result<Identite, String> {
    let t = lire_texte(chemin)?;
    t.lines()
        .find(|l| l.starts_with(cles::PREFIXE_SECRETE))
        .and_then(cles::secrete_depuis_texte)
        .ok_or_else(|| format!("{} : identité illisible", chemin.display()))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match executer(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) if e.is_empty() => usage(),
        Err(e) => {
            eprintln!("janus : {e}");
            ExitCode::FAILURE
        }
    }
}
