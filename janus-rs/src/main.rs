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
use janus::format::{self, Destinataires, MAX_CACHES, Ouverture, Visage};
use janus::xwing::{Identite, TAILLE_PK};
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use zeroize::Zeroizing;

const AVERTISSEMENT: &str =
    "Prototype de recherche : format non figé, ne pas l'utiliser pour de vrais secrets.";
const TAMPON: usize = 1 << 20;

/// Version du programme et du format, affichée par `janus --version`.
fn version() -> String {
    format!(
        "janus {} (format Janus v1, aperçu non figé : un fichier chiffré avec cette version \
         pourrait ne plus s'ouvrir avec une version suivante)",
        env!("CARGO_PKG_VERSION")
    )
}

const AIDE: &str = "\
Usage :
  janus cles <fichier-identité>
      Crée une identité (clé secrète) dans le fichier et affiche la clé publique.
  janus publique <fichier-identité>
      Réaffiche la clé publique d'une identité.
  janus chiffrer <destinataires> <entrée> <sortie> [--cache <destinataires> <entrée-secrète>]
      Chiffre <entrée> (le visage principal, ou leurre). Avec --cache, cache en plus
      <entrée-secrète> dans le même fichier (le visage caché). Le secret doit tenir
      dans la réserve : 1/16 de la taille du leurre, et au moins 64 Kio.
  janus dechiffrer (-i <fichier-identité>… | -m) <entrée> <sortie>
      Ouvre le visage qui correspond à l'identifiant donné. N'indique jamais si un
      autre visage existe.
  janus modifier <ouverture> [--leurre <fichier>] <ancien> <nouveau> --cache <ouverture> [--secret <fichier>]
      Rechiffre un fichier à plusieurs visages avec un aléa neuf, en exigeant
      l'identifiant de CHAQUE visage, pour n'en perdre aucun. --leurre et --secret
      remplacent le contenu d'un visage ; sinon il est conservé.
      <ouverture> : -m (même mot de passe), ou -i <identité> plus d'éventuelles
      clés -r/-R : le visage est rechiffré pour l'identité et ces clés.
  janus inspect <fichier>…
      Montre ce qu'un tiers apprend d'un fichier sans clé (Janus, gpg, age, ZIP, 7-Zip…).
  janus --version | --help

<destinataires> :
  -r <clé publique>     clé publique en argument (répétable)
  -R <fichier>          clés publiques lues dans un fichier, une par ligne (répétable)
  -m                    mot de passe, demandé au clavier ; seul dans son visage
  16 destinataires au plus, pour tous les visages réunis.

<entrée> ou <sortie> valant - : entrée standard ou sortie standard.
  Avec dechiffrer … -, tout est déchiffré et vérifié EN MÉMOIRE avant d'écrire
  quoi que ce soit, et aucun fichier en clair n'est créé sur le disque :
  janus dechiffrer -m coffre.janus - | less

Exemples :
  janus cles moi.cle > moi.pub
  janus chiffrer -R moi.pub photo.jpg photo.janus
  janus chiffrer -m vacances.zip coffre.janus --cache -m journal.txt
  janus dechiffrer -m coffre.janus sortie
  janus modifier -m --leurre vacances2.zip coffre.janus coffre2.janus --cache -m

Documentation : https://docs.moideici.tech/janus/";

fn usage() -> ExitCode {
    eprintln!("{AVERTISSEMENT}\n\n{AIDE}");
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

/// Ce que la ligne de commande autorise selon la commande.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Chiffrer,
    Dechiffrer,
    Modifier,
}

/// Destinataires, identités et fichiers d'un visage, lus sur la ligne de commande.
#[derive(Default)]
struct Arguments {
    cles: Vec<[u8; TAILLE_PK]>,
    identites: Vec<Identite>,
    mdp: bool,
    /// `modifier` seulement : nouveau contenu du visage (--leurre ou --secret).
    contenu: Option<String>,
    positionnels: Vec<String>,
}

fn analyser(args: &[String], mode: Mode) -> Result<Arguments, String> {
    let mut a = Arguments::default();
    let mut it = args.iter();
    while let Some(x) = it.next() {
        match x.as_str() {
            "-r" if mode != Mode::Dechiffrer => {
                let t = it.next().ok_or("-r attend une clé")?;
                a.cles.push(cles::publique_depuis_texte(t).ok_or("clé publique illisible")?);
            }
            "-R" if mode != Mode::Dechiffrer => {
                let t = lire_texte(Path::new(it.next().ok_or("-R attend un fichier")?))?;
                for ligne in t.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#')) {
                    a.cles.push(cles::publique_depuis_texte(ligne).ok_or("clé publique illisible")?);
                }
            }
            "-i" if mode != Mode::Chiffrer => {
                a.identites.push(lire_identite(Path::new(it.next().ok_or("-i attend un fichier")?))?);
            }
            "--leurre" | "--secret" if mode == Mode::Modifier => {
                a.contenu = Some(it.next().ok_or(format!("{x} attend un fichier"))?.clone());
            }
            "-m" => a.mdp = true,
            _ => a.positionnels.push(x.clone()),
        }
    }
    if a.mdp && (!a.cles.is_empty() || !a.identites.is_empty()) {
        return Err("un mot de passe ne se combine pas avec des clés dans un même visage (règle R1)".into());
    }
    Ok(a)
}

/// Une entrée : un fichier lu en flux, ou l'entrée standard (`-`), lue
/// entièrement en mémoire car Janus doit connaître sa longueur à l'avance.
enum Entree {
    Fichier(BufReader<File>),
    Memoire(Cursor<Zeroizing<Vec<u8>>>),
}

impl Read for Entree {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Entree::Fichier(f) => f.read(buf),
            Entree::Memoire(m) => m.read(buf),
        }
    }
}

fn ouvrir_entree(chemin: &str) -> Result<(Entree, u64), String> {
    if chemin == "-" {
        let mut v = Zeroizing::new(Vec::new());
        io::stdin().lock().read_to_end(&mut v).map_err(|e| format!("entrée standard : {e}"))?;
        let n = v.len() as u64;
        return Ok((Entree::Memoire(Cursor::new(v)), n));
    }
    let f = File::open(chemin).map_err(|e| format!("{chemin} : {e}"))?;
    let taille = f.metadata().map_err(|e| e.to_string())?.len();
    Ok((Entree::Fichier(BufReader::with_capacity(TAMPON, f)), taille))
}

/// Variables d'environnement (tests seulement) et invites des mots de passe, par visage.
const MDP_ENV: [&str; 4] = ["JANUS_MDP", "JANUS_MDP_CACHE", "JANUS_MDP_CACHE2", "JANUS_MDP_CACHE3"];
const MDP_INVITE: [&str; 4] = [
    "Mot de passe du leurre",
    "Mot de passe du visage caché",
    "Mot de passe du 2e visage caché",
    "Mot de passe du 3e visage caché",
];

/// Découpe `… --cache … --cache …` en segments : le visage principal, puis chaque visage caché.
fn segments(args: &[String]) -> (&[String], Vec<&[String]>) {
    let mut parts = args.split(|a| a == "--cache");
    let premier = parts.next().unwrap_or(&[]);
    (premier, parts.collect())
}

fn chiffrer(args: &[String]) -> Result<(), String> {
    let (avant, apres) = segments(args);
    let principal = analyser(avant, Mode::Chiffrer)?;
    let [entree, sortie] = principal.positionnels.as_slice() else {
        return Err("il faut une entrée et une sortie".into());
    };
    let (entree, sortie) = (entree.clone(), sortie.clone());
    let caches: Vec<Arguments> = apres.iter().map(|s| analyser(s, Mode::Chiffrer)).collect::<Result<_, _>>()?;
    if caches.len() > MAX_CACHES {
        return Err(format!("{MAX_CACHES} visage(s) caché(s) au plus"));
    }
    let mut entrees = vec![entree];
    for c in &caches {
        match c.positionnels.as_slice() {
            [e] => entrees.push(e.clone()),
            _ => return Err("--cache attend ses destinataires puis une seule entrée".into()),
        }
    }
    if entrees.iter().filter(|e| *e == "-").count() > 1 {
        return Err("une seule entrée peut venir de l'entrée standard (-)".into());
    }

    let mut specs = vec![principal];
    specs.extend(caches);
    let mdps: Vec<Option<Zeroizing<String>>> = specs
        .iter()
        .enumerate()
        .map(|(i, s)| if s.mdp { lire_mdp(MDP_ENV[i], MDP_INVITE[i], true).map(Some) } else { Ok(None) })
        .collect::<Result<_, _>>()?;
    let mut lecteurs = Vec::new();
    for e in &entrees {
        lecteurs.push(ouvrir_entree(e)?);
    }
    let mut ecrire = |w: &mut dyn Write| -> Result<(), String> {
        let mut visages = Vec::new();
        for ((s, m), (lecteur, longueur)) in specs.iter().zip(&mdps).zip(lecteurs.iter_mut()) {
            let dest = match m {
                Some(m) => Destinataires::MotDePasse(m.as_bytes()),
                None => Destinataires::Cles(&s.cles),
            };
            visages.push(Visage { entree: lecteur, longueur: *longueur, dest });
        }
        let principal = visages.remove(0);
        let mut w = BufWriter::with_capacity(TAMPON, w);
        format::chiffrer_flux(principal, visages, &mut w).map_err(|e| e.to_string())?;
        w.flush().map_err(|e| e.to_string())
    };
    if sortie == "-" {
        // Un chiffré tronqué ne s'ouvrira pas : écrire en flux sur la sortie standard est sans risque.
        ecrire(&mut io::stdout().lock())
    } else {
        ecrire_atomique(Path::new(&sortie), |f| ecrire(f))
    }
}

fn dechiffrer(args: &[String]) -> Result<(), String> {
    let a = analyser(args, Mode::Dechiffrer)?;
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
    if sortie == "-" {
        // Ouverture EN MÉMOIRE : rien n'est écrit tant que tout n'est pas vérifié
        // (docs/06, § 5), et aucun fichier en clair n'est créé sur le disque.
        let mut clair = Zeroizing::new(Vec::new());
        format::dechiffrer_flux(&mut lecteur, taille, ouv, &mut *clair).map_err(|e| e.to_string())?;
        let mut out = io::stdout().lock();
        out.write_all(&clair).and_then(|_| out.flush()).map_err(|e| format!("sortie standard : {e}"))
    } else {
        ecrire_atomique(Path::new(sortie), |f| {
            let mut w = BufWriter::with_capacity(TAMPON, &mut *f);
            format::dechiffrer_flux(&mut lecteur, taille, ouv, &mut w).map_err(|e| e.to_string())?;
            w.flush().map_err(|e| e.to_string())
        })
    }
}

/// `janus modifier` : rechiffre un fichier à plusieurs visages en exigeant TOUS
/// les identifiants, pour qu'aucun visage caché ne soit perdu (piège 10.2), et
/// en conseillant de changer aussi le leurre (piège 10.1).
fn modifier(args: &[String]) -> Result<(), String> {
    let (avant, apres) = segments(args);
    if apres.is_empty() {
        return Err("modifier exige l'identifiant de chaque visage caché (--cache) : sans eux, le nouveau \
                    fichier les perdrait. Pour un fichier à un seul visage, chiffre simplement à nouveau"
            .into());
    }
    let principal = analyser(avant, Mode::Modifier)?;
    let [ancien, nouveau] = principal.positionnels.as_slice() else {
        return Err("il faut l'ancien fichier puis le nouveau".into());
    };
    let (ancien, nouveau) = (ancien.clone(), nouveau.clone());
    let mut specs = vec![principal];
    for s in apres {
        let a = analyser(s, Mode::Modifier)?;
        if !a.positionnels.is_empty() {
            return Err("après --cache : l'identifiant du visage caché, puis éventuellement --secret <fichier>".into());
        }
        specs.push(a);
    }
    if specs.len() > MAX_CACHES + 1 {
        return Err(format!("{MAX_CACHES} visage(s) caché(s) au plus"));
    }
    let fichier = fs::read(&ancien).map_err(|e| format!("{ancien} : {e}"))?;
    let mdps: Vec<Option<Zeroizing<String>>> = specs
        .iter()
        .enumerate()
        .map(|(i, s)| if s.mdp { lire_mdp(MDP_ENV[i], MDP_INVITE[i], false).map(Some) } else { Ok(None) })
        .collect::<Result<_, _>>()?;

    // 1. Ouvrir chaque visage, et vérifier que chacun est bien à sa place.
    let mut contenus = Vec::new();
    for (i, (s, m)) in specs.iter().zip(&mdps).enumerate() {
        let quel = if i == 0 { "le leurre".to_string() } else { format!("le visage caché n° {i}") };
        let ouv = match m {
            Some(m) => Ouverture::MotDePasse(m.as_bytes()),
            None if s.identites.is_empty() => return Err(format!("{quel} : il faut -i <identité> ou -m")),
            None => Ouverture::Identites(&s.identites),
        };
        let (clair, est_principal) = format::dechiffrer_visage(&fichier, ouv).map_err(|e| format!("{quel} : {e}"))?;
        if est_principal != (i == 0) {
            return Err(if i == 0 {
                "l'identifiant donné en premier n'ouvre pas le leurre (visage principal)".into()
            } else {
                format!("l'identifiant de {quel} ouvre le leurre, pas un visage caché")
            });
        }
        contenus.push(clair);
    }
    // 2. Remplacer les contenus demandés.
    for (i, s) in specs.iter().enumerate() {
        if let Some(c) = &s.contenu {
            contenus[i] = Zeroizing::new(fs::read(c).map_err(|e| format!("{c} : {e}"))?);
        }
    }
    if specs[0].contenu.is_none() {
        eprintln!(
            "Attention : le leurre n'a pas changé. Quelqu'un qui verrait l'ancienne et la nouvelle version \
             pourrait se demander pourquoi un leurre identique a été rechiffré. Mieux vaut le modifier aussi (--leurre)."
        );
    }
    // 3. Destinataires : le même mot de passe, ou l'identité donnée plus les clés ajoutées.
    let cles: Vec<Vec<[u8; TAILLE_PK]>> = specs
        .iter()
        .map(|s| s.identites.iter().map(|id| *id.cle_publique()).chain(s.cles.iter().copied()).collect())
        .collect();
    if specs.iter().any(|s| !s.identites.is_empty()) {
        eprintln!(
            "Note : Janus ne connaît pas les autres destinataires éventuels d'un visage à clé. Le nouveau fichier \
             est chiffré pour l'identité donnée, plus les clés ajoutées avec -r ou -R."
        );
    }
    let mut lecteurs: Vec<&[u8]> = contenus.iter().map(|c| &c[..]).collect();
    let mut visages = Vec::new();
    for (i, lecteur) in lecteurs.iter_mut().enumerate() {
        let dest = match &mdps[i] {
            Some(m) => Destinataires::MotDePasse(m.as_bytes()),
            None => Destinataires::Cles(&cles[i]),
        };
        visages.push(Visage { entree: lecteur, longueur: contenus[i].len() as u64, dest });
    }
    let principal = visages.remove(0);
    ecrire_atomique(Path::new(&nouveau), |f| {
        let mut w = BufWriter::with_capacity(TAMPON, &mut *f);
        format::chiffrer_flux(principal, visages, &mut w).map_err(|e| e.to_string())?;
        w.flush().map_err(|e| e.to_string())
    })?;
    eprintln!("{nouveau} : {} visage(s) rechiffré(s) avec un aléa neuf.", specs.len());
    Ok(())
}

fn executer(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("--version" | "-V") => {
            println!("{}", version());
            Ok(())
        }
        Some("--help" | "-h" | "aide") => {
            println!("{}\n{AVERTISSEMENT}\n\n{AIDE}", version());
            Ok(())
        }
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
        Some("modifier") => modifier(&args[1..]),
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
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&p| if le { u16::from_le_bytes(p) } else { u16::from_be_bytes(p) })
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
