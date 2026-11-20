# Janus : durcissement de l'implémentation

*20 novembre 2026.*

Les preuves (documents 04 à 06) disent ce que le **format** garantit. Ce document décrit ce qui protège l'**implémentation** : contre ses propres bogues, contre ce que la machine laisse traîner, et contre une chaîne d'approvisionnement compromise. Aucune de ces mesures ne remplace un audit externe.

## 1. Le code

| Mesure | Ce qu'elle apporte | Où |
|---|---|---|
| `#![deny(unsafe_code)]` | Aucun code `unsafe` dans Janus, sauf un module de 150 lignes qui appelle le système pour verrouiller la mémoire. Chaque bloc y est justifié par un commentaire `SAFETY` | `src/lib.rs`, `src/main.rs`, `src/memoire.rs` |
| Clippy sans aucun avertissement | Les erreurs courantes sont refusées à chaque poussée | CI |
| Temps constant | Kemeleon, Elligator, Bech32m (identités), ouverture : dudect ne détecte aucune fuite (document 04, § 7) | `examples/dudect.rs` |

## 2. La mémoire

Les secrets passent par la mémoire vive. Trois risques, trois parades, toutes « au mieux » : si le système refuse, Janus fonctionne quand même, avec une défense de moins.

| Risque | Parade |
|---|---|
| Un secret part dans le **fichier d'échange** (swap) et reste sur le disque | Identité (graine, clés ML-KEM et X25519) et mots de passe **verrouillés en mémoire vive** (`mlock` sous Linux et macOS, `VirtualLock` sous Windows). Le clair d'une ouverture en mémoire (`dechiffrer … -`) est verrouillé si le système l'accepte : les limites sont basses (souvent 8 Mio sous Linux). Pour les gros fichiers, la vraie parade est un fichier d'échange chiffré |
| Un plantage écrit un **fichier core** avec toute la mémoire | `RLIMIT_CORE = 0` sous Linux et macOS. Windows n'écrit pas de fichier core ; ses rapports d'erreur (WER) relèvent de la configuration du système |
| Un autre programme du même utilisateur **lit la mémoire** de Janus (ptrace) | Sous Linux, le processus se déclare non « dumpable » (`PR_SET_DUMPABLE = 0`) |
| Des **copies oubliées** du clair restent dans le tas | Tous les secrets sont effacés à la destruction (`zeroize`). Un défaut a été corrigé : en lisant l'entrée standard, ou en ouvrant en mémoire, le tampon grandissait par réallocations, et chaque ancienne copie était libérée **sans être effacée**. Le tampon est désormais alloué une fois, ou agrandi en effaçant l'ancien (`memoire::lire_tout`) |

Limites : le compilateur peut laisser des copies temporaires sur la pile, et la bibliothèque Argon2id alloue ses 64 Mio sans les verrouiller. Le verrouillage porte sur des pages entières.

## 3. Le fuzzing

Deux niveaux :
- **Par mutations, en Rust stable** (`tests/fuzz.rs`) : 2 000 mutations de fichiers valides à chaque `cargo test`, et 80 000 lors des campagnes longues (`JANUS_FUZZ_ITER`).
- **Guidé par la couverture** (`fuzz/`, cargo-fuzz et libFuzzer, avec AddressSanitizer) : le fuzzer observe les branches du code qu'il atteint, et garde les entrées qui en découvrent de nouvelles. Six cibles :

| Cible | Entrée | Propriété vérifiée |
|---|---|---|
| `ouvrir_cle` | un fichier quelconque, en partant des vecteurs de test | jamais de panique ; un succès ne rend jamais plus d'octets que le fichier |
| `muter` | un leurre (et parfois un visage caché), puis des mutations et troncatures | l'ouverture échoue, ou rend **exactement** le leurre d'origine |
| `cles_texte` | un texte quelconque | tout texte accepté se réencode à l'identique ; jamais une clé publique et une identité à la fois |
| `kemeleon` | 1536 ou 1088 octets quelconques | toute chaîne se décode ; tout chiffré fait l'aller-retour |
| `elligator` | un point quelconque `e·B + L` | le représentant redonne exactement le point |
| `inspect` | un fichier quelconque | `janus inspect`, l'analyseur le plus exposé, ne panique jamais |

Sous cargo-fuzz seulement (`cfg(fuzzing)`), Argon2id prend des paramètres minuscules : avec 64 Mio par essai, les fichiers à mot de passe seraient des milliers de fois plus lents à explorer. Le programme et les tests ordinaires n'en sont pas affectés.

**En continu :** chaque nuit, la CI fuzze chaque cible pendant 10 minutes (`.github/workflows/fuzz.yml`), en reprenant le corpus de la nuit précédente. Un plantage fait échouer la tâche, avec l'entrée fautive jointe.

**Première campagne (20 novembre 2026, Windows, AddressSanitizer) :**

| Cible | Durée | Essais | Branches couvertes | Plantages |
|---|---|---|---|---|
| `ouvrir_cle` | 4 min | 5 734 | 1 282 | 0 |
| `muter` | 4 min | 82 744 | 1 257 | 0 |
| `cles_texte` | 1 min 30 | 3 430 184 | 575 | 0 |
| `kemeleon` | 1 min 30 | 67 254 | 89 | 0 |
| `elligator` | 1 min 30 | 283 155 | 441 | 0 |
| `inspect` | 1 min 30 | 175 798 | 1 259 | 0 |

`ouvrir_cle` est lente (une vingtaine d'essais par seconde) : chaque essai lit un fichier d'environ 90 Kio et fait 32 décapsulations X-Wing. Le fuzzing nocturne lui donne plus de temps au fil des nuits, puisque le corpus est conservé.

Pour lancer une cible soi-même (chaîne nightly) :

```bash
cd janus-rs
cargo +nightly fuzz run -O muter -- -max_total_time=600
cargo +nightly fuzz run -O ouvrir_cle fuzz/corpus/ouvrir_cle vecteurs -- -max_len=200000
```

Sous Windows, ajouter au `PATH` le dossier de Visual Studio qui contient `clang_rt.asan_dynamic-x86_64.dll` (`VC\Tools\MSVC\<version>\bin\Hostx64\x64`).

## 4. La chaîne d'approvisionnement

| Mesure | Ce qu'elle vérifie | Où |
|---|---|---|
| `cargo-deny`, à chaque poussée | aucune dépendance avec une faille connue (base RustSec), retirée ou abandonnée ; licences compatibles avec la MIT ; crates.io uniquement, aucun dépôt git | `janus-rs/deny.toml` |
| `Cargo.lock` et `--locked` | les versions exactes des dépendances sont figées et vérifiées | CI, release |
| Aucune dépendance dans les clients | les quatre clients n'utilisent que leur plateforme (et `cryptography` pour Python) | `clients/` |

## 5. Les releases

**Builds reproductibles.** La version de rustc est épinglée (`janus-rs/rust-toolchain.toml`), les dépendances aussi (`Cargo.lock`), et les chemins de compilation sont neutralisés (`--remap-path-prefix`). Le binaire Linux est donc identique octet pour octet quel que soit le dossier ou la machine : la CI le vérifie à chaque poussée en compilant deux fois, dans deux dossiers. Chacun peut ainsi recompiler une release et comparer son empreinte à celle publiée, sans faire confiance à GitHub. (Les binaires Windows et macOS contiennent des métadonnées propres à leur machine de compilation et ne sont pas garantis reproductibles.)

```bash
cd janus-rs
RUSTFLAGS="--remap-path-prefix=$(cd .. && pwd)=/janus --remap-path-prefix=$HOME/.cargo=/cargo" \
  cargo build --release --locked
sha256sum target/release/janus      # à comparer au binaire de l'archive Linux
```

**Releases signées.** Chaque fichier d'une release (archives et `SHA256SUMS.txt`) reçoit une **attestation de provenance Sigstore**, produite par GitHub Actions sans clé à gérer. Elle prouve que le fichier a été produit par le workflow `release.yml`, depuis ce dépôt et cette étiquette, et non déposé à la main :

```bash
gh attestation verify janus-v0.2.0-alpha-x86_64-unknown-linux-gnu.tar.gz --repo moideici/janus
```

La v0.1.0-alpha, publiée avant cette mesure, n'a pas d'attestation.

## 6. Ce qui reste

- Un **audit externe** du code.
- Le fuzzing de l'**ouverture à mot de passe avec les vrais paramètres** d'Argon2id n'est fait que par mutations (`tests/fuzz.rs`), pas par couverture.
- La **vérification formelle** du code (par exemple avec hax et F\*, ou en remplaçant ML-KEM par libcrux, vérifié formellement), qui irait au-delà des tests.
