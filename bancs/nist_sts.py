#!/usr/bin/env python3
"""Prepare a NIST SP 800-22 (STS) input made of real Janus files.

  python bancs/nist_sts.py sortie.bin [--flux 100]

Writes `flux` × 1 000 000 bits (12.5 MB for 100), the concatenation of whole
Janus files (header, slots, reserve, padding, faces): half encrypted to public
keys, half to a password with a hidden face. Every plaintext is all zeros, the
worst case for a format whose ciphertext must look random. Then run the NIST
`assess` program on it (docs/10-evaluation.md, § 2).
"""

import argparse
import os
import subprocess
import tempfile
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
JANUS = RACINE / "janus-rs" / "target" / "release" / ("janus.exe" if os.name == "nt" else "janus")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("sortie")
    p.add_argument("--flux", type=int, default=100)
    a = p.parse_args()
    besoin = a.flux * 1_000_000 // 8
    d = Path(tempfile.mkdtemp(prefix="janus-sts-"))
    cle = d / "id.cle"
    pub = subprocess.run([JANUS, "cles", cle], capture_output=True, check=True).stdout.decode().strip()
    zeros = d / "zeros"
    zeros.write_bytes(bytes(100 * 1024))
    secret = d / "secret"
    secret.write_bytes(bytes(3000))
    env = dict(os.environ, JANUS_MDP="leurre-sts", JANUS_MDP_CACHE="cache-sts")
    total, n = 0, 0
    with open(a.sortie, "wb") as sortie:
        while total < besoin:
            f = d / f"{n}.janus"
            if n % 2 == 0:
                cmd = [JANUS, "chiffrer", "-r", pub, zeros, f]
            else:
                cmd = [JANUS, "chiffrer", "-m", zeros, f, "--cache", "-m", secret]
            subprocess.run(cmd, env=env, capture_output=True, check=True)
            octets = f.read_bytes()
            octets = octets[: besoin - total]
            sortie.write(octets)
            total += len(octets)
            f.unlink()
            n += 1
    print(f"{a.sortie} : {total} octets, {n} fichiers Janus ({a.flux} flux de 1 000 000 bits)")


if __name__ == "__main__":
    main()
