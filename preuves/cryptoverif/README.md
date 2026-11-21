# Modèles CryptoVerif

Vérification par machine du **KEM caché** de Janus v1 : X-Wing avec un éphémère X25519 « sale », le chiffré ML-KEM masqué par un flux qui dépend de `ss_X`, et le combineur d'X-Wing. Le contexte, les abstractions et la lecture des résultats sont dans [docs/09-preuves-renforcees.md](../../docs/09-preuves-renforcees.md), § 2 et § 4.

| Modèle | Chemin | Hypothèses | Résultat |
|---|---|---|---|
| [`kem_cache_mlkem.ocv`](kem_cache_mlkem.ocv) | ML-KEM, post-quantique | ML-KEM IND-CCA2, SHA3 PRF de clé `ss_M` ; aucun oracle aléatoire ; X25519 entièrement compromis | `All queries proved.` |
| [`kem_cache_gdh.ocv`](kem_cache_gdh.ocv) | X25519, classique | gap-DH, oracles aléatoires, C2PRI d'ML-KEM ; secret d'ML-KEM compromis | `All queries proved.` |

## Lancer

CryptoVerif 2.13, installé avec opam (Linux, macOS, ou WSL sous Windows) :

```bash
opam switch create janus ocaml-base-compiler.4.14.2
opam install cryptoverif
cryptoverif kem_cache_mlkem.ocv
cryptoverif kem_cache_gdh.ocv
```

Si `cryptoverif` ne trouve pas sa bibliothèque, ajouter `-lib $(opam var bin)/default`.

Chaque modèle se vérifie automatiquement, sans indication de preuve, en quelques secondes. CryptoVerif affiche la suite de jeux, puis la borne finale de l'avantage de l'adversaire.
