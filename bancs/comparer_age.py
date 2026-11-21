#!/usr/bin/env python3
"""Compare Janus with age: size overhead, throughput, and what a third party sees.

Usage:
  python bancs/comparer_age.py --age path/to/age.exe [--gio 1]

Needs the release build of Janus (janus-rs/target/release/janus[.exe]) and the
official age binary. Everything happens in a temporary directory, which is
deleted afterwards. Prints Markdown tables (docs/10-evaluation.md).
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
EXE = ".exe" if os.name == "nt" else ""
JANUS = RACINE / "janus-rs" / "target" / "release" / f"janus{EXE}"


def lancer(cmd, env=None, entree=None):
    e = dict(os.environ)
    e.update(env or {})
    r = subprocess.run([str(c) for c in cmd], env=e, input=entree, capture_output=True)
    if r.returncode != 0:
        raise RuntimeError(f"{cmd[0]} : {r.stderr.decode(errors='replace').strip()}")
    return r.stdout.decode(errors="replace")


def chrono(fonction, repetitions=3):
    """Meilleur de `repetitions` mesures, en secondes (le disque et le cache varient)."""
    meilleur = float("inf")
    for _ in range(repetitions):
        t0 = time.perf_counter()
        fonction()
        meilleur = min(meilleur, time.perf_counter() - t0)
    return meilleur


def ecrire_aleatoire(chemin, n):
    with open(chemin, "wb") as f:
        restant = n
        while restant:
            k = min(restant, 1 << 24)
            f.write(os.urandom(k))
            restant -= k


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--age", required=True, help="binaire age (et age-keygen à côté)")
    p.add_argument("--gio", type=float, default=1.0, help="taille du fichier de débit, en Gio")
    a = p.parse_args()
    age = Path(a.age)
    age_keygen = age.with_name(f"age-keygen{EXE}")
    if not JANUS.exists():
        sys.exit(f"compile d'abord Janus : {JANUS}")

    d = Path(tempfile.mkdtemp(prefix="janus-age-"))
    try:
        # Clés.
        cle_age = d / "age.cle"
        lancer([age_keygen, "-o", cle_age])
        pub_age = [l.split(": ")[1] for l in cle_age.read_text().splitlines() if l.startswith("# public key")][0]
        cle_janus = d / "janus.cle"
        pub_janus = lancer([JANUS, "cles", cle_janus]).strip()
        mdp = {"JANUS_MDP": "correct horse battery staple"}

        version_age = lancer([age, "--version"]).strip()
        version_janus = lancer([JANUS, "--version"]).split(" (")[0]
        print(f"age {version_age} ; {version_janus}\n")

        # 1. Surcoût de taille.
        print("### Taille du fichier chiffré (surcoût en octets, et en % du clair)\n")
        print("| Clair | age, 1 clé X25519 | Janus, 1 clé | Janus, mot de passe | Janus, leurre + 1 visage caché |")
        print("|---|---|---|---|---|")
        for n in [0, 100, 10 * 1024, 1 << 20, 100 << 20]:
            clair = d / f"clair-{n}"
            ecrire_aleatoire(clair, n)
            secret = d / "secret"
            ecrire_aleatoire(secret, min(1000, n))
            sorties = {}
            f = d / f"a-{n}.age"
            lancer([age, "-r", pub_age, "-o", f, clair])
            sorties["age"] = f.stat().st_size
            f = d / f"k-{n}.janus"
            lancer([JANUS, "chiffrer", "-r", pub_janus, clair, f])
            sorties["cle"] = f.stat().st_size
            f = d / f"m-{n}.janus"
            lancer([JANUS, "chiffrer", "-m", clair, f], env=mdp)
            sorties["mdp"] = f.stat().st_size
            f = d / f"v-{n}.janus"
            lancer([JANUS, "chiffrer", "-m", clair, f, "--cache", "-m", secret],
                   env={**mdp, "JANUS_MDP_CACHE": "autre phrase de passe"})
            sorties["visages"] = f.stat().st_size

            def cellule(taille):
                surcout = taille - n
                pct = f" ({100 * surcout / n:.1f} %)" if n >= 10 * 1024 else ""
                return f"+{surcout:,}{pct}".replace(",", " ")

            nom = {0: "0 o", 100: "100 o", 10240: "10 Kio", 1 << 20: "1 Mio", 100 << 20: "100 Mio"}[n]
            print(f"| {nom} | {cellule(sorties['age'])} | {cellule(sorties['cle'])} | "
                  f"{cellule(sorties['mdp'])} | {cellule(sorties['visages'])} |")
            for x in d.glob(f"?-{n}.*"):
                x.unlink()
            clair.unlink()

        # 2. Débit, de bout en bout (disque compris).
        n = int(a.gio * (1 << 30))
        gros = d / "gros"
        ecrire_aleatoire(gros, n)
        print(f"\n### Débit de bout en bout, {a.gio:g} Gio, clé publique (meilleur de 3)\n")
        print("| Outil | Chiffrer | Déchiffrer |")
        print("|---|---|---|")

        def age_chiffrer():
            (d / "g.age").unlink(missing_ok=True)
            lancer([age, "-r", pub_age, "-o", d / "g.age", gros])

        def age_dechiffrer():
            (d / "g.age.out").unlink(missing_ok=True)
            lancer([age, "-d", "-i", cle_age, "-o", d / "g.age.out", d / "g.age"])

        def janus_chiffrer():
            (d / "g.janus").unlink(missing_ok=True)
            lancer([JANUS, "chiffrer", "-r", pub_janus, gros, d / "g.janus"])

        def janus_dechiffrer():
            (d / "g.janus.out").unlink(missing_ok=True)
            lancer([JANUS, "dechiffrer", "-i", cle_janus, d / "g.janus", d / "g.janus.out"])

        for nom, chiffrer, dechiffrer in [("age", age_chiffrer, age_dechiffrer),
                                          ("Janus", janus_chiffrer, janus_dechiffrer)]:
            tc, td = chrono(chiffrer), chrono(dechiffrer)
            print(f"| {nom} | {tc:.2f} s ({a.gio / tc * 1024:.0f} Mio/s) | {td:.2f} s ({a.gio / td * 1024:.0f} Mio/s) |")
        for x in ["g.age", "g.age.out", "g.janus", "g.janus.out", "gros"]:
            (d / x).unlink(missing_ok=True)

        # 3. Temps d'une ouverture (en-tête seulement : clair d'un octet).
        petit = d / "petit"
        ecrire_aleatoire(petit, 1)
        lancer([age, "-r", pub_age, "-o", d / "p.age", petit])
        lancer([JANUS, "chiffrer", "-r", pub_janus, petit, d / "p.janus"])
        lancer([JANUS, "chiffrer", "-m", petit, d / "pm.janus"], env=mdp)

        def ouvrir(cmd, sortie, env=None):
            def f():
                (d / sortie).unlink(missing_ok=True)
                lancer(cmd + [d / sortie], env=env)
            return f

        print("\n### Ouverture d'un petit fichier, processus compris (meilleur de 5)\n")
        print("| Opération | Durée |")
        print("|---|---|")
        print(f"| age, clé X25519 | {1000 * chrono(lambda: lancer([age, '-d', '-i', cle_age, '-o', d / 'p.out', d / 'p.age']), 5):.0f} ms |")
        print(f"| Janus, clé X-Wing (16 emplacements essayés) | "
              f"{1000 * chrono(ouvrir([JANUS, 'dechiffrer', '-i', cle_janus, d / 'p.janus'], 'p1.out'), 5):.0f} ms |")
        print(f"| Janus, mot de passe (Argon2id 64 Mio) | "
              f"{1000 * chrono(ouvrir([JANUS, 'dechiffrer', '-m', d / 'pm.janus'], 'p2.out', mdp), 5):.0f} ms |")

        # 4. Ce qu'un tiers apprend.
        print("\n### Ce que voit `janus inspect`, sans aucune clé\n")
        for f in ["p.age", "p.janus"]:
            print(f"```\n{lancer([JANUS, 'inspect', d / f]).strip()}\n```\n")
    finally:
        shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    main()
