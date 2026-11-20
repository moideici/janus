#!/usr/bin/env python3
"""Cross-implementation test for Janus v1.

Every implementation (the Rust reference and the clients) encrypts, and every
implementation decrypts what the others wrote:
  1. a password-only file;
  2. a file for a public key created by the decrypting implementation;
  3. a decoy with two hidden faces (one password, one public key), each face
     opened separately;
and a wrong password must fail everywhere.

Usage:  python clients/interop.py [names...]     (default: every implementation found)
Build the clients first (see each README); missing ones are skipped.
"""

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
EXE = ".exe" if os.name == "nt" else ""


def commande_client(nom):
    c = RACINE / "clients"
    candidats = {
        "python": ([sys.executable, str(c / "python" / "janus.py")], c / "python" / "janus.py"),
        "typescript": (["node", str(c / "typescript" / "janus.ts")], c / "typescript" / "janus.ts"),
        "csharp": (["dotnet", str(c / "csharp" / "Janus" / "bin" / "Release" / "net10.0" / "Janus.dll")],
                   c / "csharp" / "Janus" / "bin" / "Release" / "net10.0" / "Janus.dll"),
        "java": (["java", "-jar", str(c / "java" / "out" / "janus.jar")], c / "java" / "out" / "janus.jar"),
    }
    cmd, fichier = candidats[nom]
    return cmd if fichier.exists() else None


def lancer(cmd, env=None, attendu=0):
    e = dict(os.environ)
    e.update(env or {})
    r = subprocess.run(cmd, capture_output=True, env=e, timeout=600)
    if attendu is not None and r.returncode != attendu:
        raise RuntimeError(f"{' '.join(map(str, cmd))}\n  code {r.returncode}\n  {r.stderr.decode(errors='replace').strip()}")
    return r


class Rust:
    nom = "rust"

    def __init__(self):
        self.bin = str(RACINE / "janus-rs" / "target" / "release" / f"janus{EXE}")

    def disponible(self):
        return Path(self.bin).exists()

    def keygen(self, id_fichier):
        return lancer([self.bin, "cles", id_fichier]).stdout.decode().strip()

    def encrypt(self, sortie, visages):
        """faces: [(input, ("pass", password) | ("to", public_key))], the first one is the decoy."""
        args, env = [self.bin, "chiffrer"], {}
        variables = ["JANUS_MDP", "JANUS_MDP_CACHE", "JANUS_MDP_CACHE2", "JANUS_MDP_CACHE3"]
        for n, (entree, (genre, valeur)) in enumerate(visages):
            if n:
                args.append("--cache")
            if genre == "pass":
                args.append("-m")
                env[variables[n]] = valeur
            else:
                args += ["-r", valeur]
            args.append(entree)
            if n == 0:
                args.append(sortie)
        lancer(args, env)

    def decrypt(self, entree, sortie, cred, attendu=0):
        genre, valeur = cred
        if genre == "pass":
            return lancer([self.bin, "dechiffrer", "-m", entree, sortie], {"JANUS_MDP": valeur}, attendu)
        return lancer([self.bin, "dechiffrer", "-i", valeur, entree, sortie], None, attendu)


class Client:
    def __init__(self, nom):
        self.nom = nom
        self.cmd = commande_client(nom)

    def disponible(self):
        return self.cmd is not None

    def keygen(self, id_fichier):
        return lancer(self.cmd + ["keygen", id_fichier]).stdout.decode().strip()

    def encrypt(self, sortie, visages):
        args = self.cmd + ["encrypt", sortie]
        for n, (entree, (genre, valeur)) in enumerate(visages):
            if n:
                args.append("--hidden")
            args.append(entree)
            args += ["--pass", valeur] if genre == "pass" else ["--to", valeur]
        lancer(args)

    def decrypt(self, entree, sortie, cred, attendu=0):
        genre, valeur = cred
        option = ["--pass", valeur] if genre == "pass" else ["--id", valeur]
        return lancer(self.cmd + ["decrypt", entree, sortie] + option, None, attendu)


def empreinte(chemin):
    return hashlib.sha256(Path(chemin).read_bytes()).hexdigest()


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    impls = [Rust()] + [Client(n) for n in ("python", "typescript", "csharp", "java")]
    voulus = set(sys.argv[1:])
    if voulus:
        impls = [i for i in impls if i.nom in voulus]
    actives = [i for i in impls if i.disponible()]
    for i in impls:
        if not i.disponible():
            print(f"(not found, skipped: {i.nom})")
    if len(actives) < 2:
        print("At least two implementations are needed.")
        return 1

    d = Path(tempfile.mkdtemp(prefix="janus-interop-"))
    echecs = 0
    try:
        leurre = d / "leurre.bin"
        leurre.write_bytes(os.urandom(200_000))  # 4 STREAM blocks
        secret1 = d / "secret1.txt"
        secret1.write_bytes(b"premier secret " * 100)
        secret2 = d / "secret2.bin"
        secret2.write_bytes(os.urandom(5_000))
        # One identity per implementation, created by it.
        ids = {}
        for i in actives:
            idf = str(d / f"{i.nom}.cle")
            ids[i.nom] = (idf, i.keygen(idf))

        n = 0
        for e in actives:
            for r in actives:
                id_r, pk_r = ids[r.nom]
                cas = [
                    ("password", [(str(secret1), ("pass", "correct horse"))],
                     [(("pass", "correct horse"), secret1)]),
                    ("public key", [(str(leurre), ("to", pk_r))], [(("id", id_r), leurre)]),
                    ("decoy + 2 hidden faces",
                     [(str(leurre), ("pass", "leurre")), (str(secret1), ("pass", "visage-1")),
                      (str(secret2), ("to", pk_r))],
                     [(("pass", "leurre"), leurre), (("pass", "visage-1"), secret1), (("id", id_r), secret2)]),
                ]
                for titre, visages, ouvertures in cas:
                    n += 1
                    chiffre = str(d / f"{e.nom}-{r.nom}-{n}.janus")
                    t0 = time.time()
                    try:
                        e.encrypt(chiffre, visages)
                        for k, (cred, attendu) in enumerate(ouvertures):
                            sortie = d / f"{e.nom}-{r.nom}-{n}-{k}.out"
                            r.decrypt(chiffre, str(sortie), cred)
                            if empreinte(sortie) != empreinte(attendu):
                                raise RuntimeError(f"wrong plaintext for {cred[0]}")
                        faux = d / f"{e.nom}-{r.nom}-{n}-faux.out"
                        res = r.decrypt(chiffre, str(faux), ("pass", "mauvais"), attendu=None)
                        if res.returncode == 0 or faux.exists():
                            raise RuntimeError("a wrong password opened the file")
                        print(f"ok    {e.nom:>10} -> {r.nom:<10} {titre} ({time.time() - t0:.1f} s)")
                    except Exception as x:  # noqa: BLE001
                        echecs += 1
                        print(f"FAIL  {e.nom:>10} -> {r.nom:<10} {titre}\n  {x}")
        print(f"\n{n - echecs}/{n} combinations passed ({len(actives)} implementations: "
              f"{', '.join(i.nom for i in actives)})")
    finally:
        shutil.rmtree(d, ignore_errors=True)
    return 1 if echecs else 0


if __name__ == "__main__":
    sys.exit(main())
