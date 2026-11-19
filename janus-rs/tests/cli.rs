//! Tests de la ligne de commande `janus`, en lançant le vrai binaire :
//! entrée et sortie standard (ouverture en mémoire) et `janus modifier`.
//! Les mots de passe passent par JANUS_MDP et JANUS_MDP_CACHE (réservés aux tests).

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

fn janus() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_janus"));
    for v in ["JANUS_MDP", "JANUS_MDP_CACHE", "JANUS_MDP_CACHE2", "JANUS_MDP_CACHE3"] {
        c.env_remove(v);
    }
    c
}

/// Dossier de travail propre à un test.
fn dossier(nom: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("janus-cli-{nom}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn lancer(c: &mut Command, entree: Option<&[u8]>) -> Output {
    c.stdin(if entree.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut p = c.spawn().unwrap();
    if let Some(e) = entree {
        p.stdin.take().unwrap().write_all(e).unwrap();
    }
    p.wait_with_output().unwrap()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn entree_et_sortie_standard() {
    let d = dossier("tube");
    let clair: Vec<u8> = (0..200_000u32).map(|i| (i * 7 + 3) as u8).collect();
    let f = d.join("x.janus");
    // Chiffrer depuis l'entrée standard.
    let o = lancer(janus().args(["chiffrer", "-m", "-"]).arg(&f).env("JANUS_MDP", "tube"), Some(&clair));
    assert!(o.status.success(), "{}", stderr(&o));
    // Déchiffrer vers la sortie standard (ouverture en mémoire).
    let o = lancer(janus().args(["dechiffrer", "-m"]).arg(&f).arg("-").env("JANUS_MDP", "tube"), None);
    assert!(o.status.success(), "{}", stderr(&o));
    assert_eq!(o.stdout, clair);
    // Chiffré sur la sortie standard, puis relu depuis l'entrée standard.
    let o = lancer(janus().args(["chiffrer", "-m", "-", "-"]).env("JANUS_MDP", "tube2"), Some(b"bonjour"));
    assert!(o.status.success(), "{}", stderr(&o));
    let chiffre = o.stdout;
    let o = lancer(janus().args(["dechiffrer", "-m", "-", "-"]).env("JANUS_MDP", "tube2"), Some(&chiffre));
    assert_eq!(o.stdout, b"bonjour", "{}", stderr(&o));
    // Mauvais mot de passe : rien sur la sortie standard, pas même un préfixe.
    let o = lancer(janus().args(["dechiffrer", "-m"]).arg(&f).arg("-").env("JANUS_MDP", "faux"), None);
    assert!(!o.status.success());
    assert!(o.stdout.is_empty(), "une ouverture ratée ne doit rien écrire");
    // Dernier bloc du visage abîmé : l'ouverture échoue après avoir vérifié tous
    // les blocs précédents, et pourtant rien ne sort (docs/06, § 5). (Le dernier
    // octet du FICHIER est dans la réserve : le modifier ne gênerait pas le leurre.)
    let mut abime = std::fs::read(&f).unwrap();
    let fin_visage = janus::format::H + janus::format::taille_chiffree(clair.len() as u64) as usize;
    abime[fin_visage - 1] ^= 1;
    let o = lancer(janus().args(["dechiffrer", "-m", "-", "-"]).env("JANUS_MDP", "tube"), Some(&abime));
    assert!(!o.status.success());
    assert!(o.stdout.is_empty(), "un fichier abîmé ne doit rien laisser sortir");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn modifier_garde_tous_les_visages() {
    let d = dossier("modifier");
    let (leurre, secret, leurre2) = (d.join("leurre.bin"), d.join("secret.txt"), d.join("leurre2.bin"));
    std::fs::write(&leurre, vec![1u8; 300_000]).unwrap();
    std::fs::write(&secret, b"le code est 4217").unwrap();
    std::fs::write(&leurre2, vec![2u8; 310_000]).unwrap();
    let (v1, v2, v3) = (d.join("v1.janus"), d.join("v2.janus"), d.join("v3.janus"));
    let mdp = |c: &mut Command| {
        c.env("JANUS_MDP", "plage").env("JANUS_MDP_CACHE", "coffre");
    };

    let mut c = janus();
    c.args(["chiffrer", "-m"]).arg(&leurre).arg(&v1).args(["--cache", "-m"]).arg(&secret);
    mdp(&mut c);
    assert!(lancer(&mut c, None).status.success());

    // Sans --cache : refus, pour ne pas perdre le visage caché.
    let o = lancer(janus().args(["modifier", "-m"]).arg(&v1).arg(&v2).env("JANUS_MDP", "plage"), None);
    assert!(!o.status.success() && stderr(&o).contains("--cache"), "{}", stderr(&o));
    assert!(!v2.exists());

    // Identifiants inversés : refus.
    let mut c = janus();
    c.args(["modifier", "-m"]).arg(&v1).arg(&v2).args(["--cache", "-m"]);
    c.env("JANUS_MDP", "coffre").env("JANUS_MDP_CACHE", "plage");
    let o = lancer(&mut c, None);
    assert!(!o.status.success() && stderr(&o).contains("leurre"), "{}", stderr(&o));

    // Changer seulement le secret : accepté, avec l'avertissement sur le leurre.
    let nouveau_secret = d.join("secret2.txt");
    std::fs::write(&nouveau_secret, b"le code est 9999").unwrap();
    let mut c = janus();
    c.args(["modifier", "-m"]).arg(&v1).arg(&v2).args(["--cache", "-m", "--secret"]).arg(&nouveau_secret);
    mdp(&mut c);
    let o = lancer(&mut c, None);
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(stderr(&o).contains("le leurre n'a pas changé"), "{}", stderr(&o));
    let ouvrir = |f: &PathBuf, m: &str| lancer(janus().args(["dechiffrer", "-m"]).arg(f).arg("-").env("JANUS_MDP", m), None).stdout;
    assert_eq!(ouvrir(&v2, "plage"), vec![1u8; 300_000]);
    assert_eq!(ouvrir(&v2, "coffre"), b"le code est 9999");
    assert_ne!(std::fs::read(&v1).unwrap(), std::fs::read(&v2).unwrap(), "tout doit être rechiffré");

    // Changer le leurre : pas d'avertissement, le secret est conservé.
    let mut c = janus();
    c.args(["modifier", "-m", "--leurre"]).arg(&leurre2).arg(&v2).arg(&v3).args(["--cache", "-m"]);
    mdp(&mut c);
    let o = lancer(&mut c, None);
    assert!(o.status.success() && !stderr(&o).contains("n'a pas changé"), "{}", stderr(&o));
    assert_eq!(ouvrir(&v3, "plage"), vec![2u8; 310_000]);
    assert_eq!(ouvrir(&v3, "coffre"), b"le code est 9999");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn version_et_aide() {
    let o = lancer(janus().arg("--version"), None);
    assert!(o.status.success() && String::from_utf8_lossy(&o.stdout).contains(env!("CARGO_PKG_VERSION")));
    let o = lancer(janus().arg("--help"), None);
    assert!(o.status.success() && String::from_utf8_lossy(&o.stdout).contains("modifier"));
}

/// QB-3 : trois --cache dans une seule commande, et modifier sur quatre visages.
#[test]
fn quatre_visages_en_ligne_de_commande() {
    let d = dossier("quatre");
    let leurre = d.join("leurre.bin");
    std::fs::write(&leurre, vec![5u8; 500_000]).unwrap();
    let secrets: Vec<PathBuf> = (0..3).map(|j| d.join(format!("s{j}.txt"))).collect();
    for (j, s) in secrets.iter().enumerate() {
        std::fs::write(s, format!("secret numéro {j}")).unwrap();
    }
    let mdp = |c: &mut Command| {
        c.env("JANUS_MDP", "zero").env("JANUS_MDP_CACHE", "un").env("JANUS_MDP_CACHE2", "deux").env("JANUS_MDP_CACHE3", "trois");
    };
    let (v1, v2) = (d.join("v1.janus"), d.join("v2.janus"));
    let mut c = janus();
    c.args(["chiffrer", "-m"]).arg(&leurre).arg(&v1);
    for s in &secrets {
        c.args(["--cache", "-m"]).arg(s);
    }
    mdp(&mut c);
    let o = lancer(&mut c, None);
    assert!(o.status.success(), "{}", stderr(&o));
    let ouvrir = |f: &PathBuf, m: &str| lancer(janus().args(["dechiffrer", "-m"]).arg(f).arg("-").env("JANUS_MDP", m), None).stdout;
    assert_eq!(ouvrir(&v1, "zero"), vec![5u8; 500_000]);
    for (j, m) in ["un", "deux", "trois"].iter().enumerate() {
        assert_eq!(ouvrir(&v1, m), format!("secret numéro {j}").into_bytes());
    }
    // Un quatrième --cache est refusé.
    let mut c = janus();
    c.args(["chiffrer", "-m"]).arg(&leurre).arg(d.join("trop.janus"));
    for s in secrets.iter().chain(std::iter::once(&secrets[0])) {
        c.args(["--cache", "-m"]).arg(s);
    }
    mdp(&mut c);
    assert!(!lancer(&mut c, None).status.success());
    // Piège de QB-3 : modifier ne PEUT PAS savoir combien de visages cachés existent
    // (ce serait trahir le déni). Avec deux identifiants cachés sur trois, il réussit,
    // prévient que seuls les visages donnés sont conservés, et le troisième est perdu.
    let mut c = janus();
    c.args(["modifier", "-m"]).arg(&v1).arg(&v2).args(["--cache", "-m", "--cache", "-m"]);
    mdp(&mut c);
    let o = lancer(&mut c, None);
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(stderr(&o).contains("seuls les 3 visages donnés"), "{}", stderr(&o));
    assert_eq!(ouvrir(&v2, "deux"), "secret numéro 1".as_bytes());
    assert!(ouvrir(&v2, "trois").is_empty(), "le visage non fourni à modifier est perdu");
    let _ = std::fs::remove_dir_all(&d);
}

/// Q7 : parcours complet par clé (identité Bech32m), et identité de l'aperçu
/// v0.1.0-alpha toujours lisible (la paire de clés ne change pas).
#[test]
fn cles_bech32m_de_bout_en_bout() {
    let d = dossier("cles");
    let (id, clair, chiffre) = (d.join("moi.cle"), d.join("clair.txt"), d.join("c.janus"));
    let o = lancer(janus().arg("cles").arg(&id), None);
    assert!(o.status.success(), "{}", stderr(&o));
    let publique = String::from_utf8(o.stdout).unwrap();
    assert!(publique.starts_with("janus1"));
    let fichier_id = std::fs::read_to_string(&id).unwrap();
    assert!(fichier_id.lines().any(|l| l.starts_with("JANUS-SECRET-KEY-1") && l.len() == 76));

    let o = lancer(janus().arg("publique").arg(&id), None);
    assert_eq!(String::from_utf8(o.stdout).unwrap(), publique);

    std::fs::write(&clair, b"contenu par cle").unwrap();
    let o = lancer(janus().args(["chiffrer", "-r", publique.trim()]).arg(&clair).arg(&chiffre), None);
    assert!(o.status.success(), "{}", stderr(&o));
    let o = lancer(janus().args(["dechiffrer", "-i"]).arg(&id).arg(&chiffre).arg("-"), None);
    assert!(o.status.success(), "{}", stderr(&o));
    assert_eq!(o.stdout, b"contenu par cle");

    // Identité de l'aperçu, graine [7; 32] : base64url(graine ‖ SHA-256(préfixe ‖ graine)[..4]).
    let ancienne = d.join("ancienne.cle");
    std::fs::write(
        &ancienne,
        "# Identité Janus (PROTOTYPE)\nJANUS-SECRET-V0-BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBweWpeyT\n",
    )
    .unwrap();
    let o = lancer(janus().arg("publique").arg(&ancienne), None);
    assert!(o.status.success(), "identité de l'aperçu illisible : {}", stderr(&o));
    assert!(String::from_utf8(o.stdout).unwrap().starts_with("janus1"));
    let _ = std::fs::remove_dir_all(&d);
}
