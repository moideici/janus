# Journal des versions

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/), et les numéros de version suivent [SemVer](https://semver.org/lang/fr/). Tant que la version reste en 0.x, **le format de fichier peut changer d'une version à l'autre**.

## [Non publié]

## [0.1.0-alpha] — 2026-11-19

Premier aperçu public. Format **Janus v1**, non figé.

### Ajouté
- **Format v1 à deux visages :**
  - deux étiquettes d'en-tête, un sel Argon2id commun et 16 emplacements de 1632 octets ;
  - une réserve de taille fixe, `max(64 Kio, L/16)` ;
  - un visage caché à une position aléatoire.
- **Encapsulation X-Wing cachée :**
  - Kemeleon pour ML-KEM-768 ;
  - Elligator 2 avec un éphémère X25519 **uniforme modulo ℓ**, grâce à un inverse d'Elligator 2 maison (`fiat-crypto`) ;
  - masquage de `κ` par un flux dérivé de X25519, qui rend la discrétion hybride.
- **Corps :** STREAM ChaCha20-Poly1305 traité en parallèle et en flux, à mémoire bornée. Taille tirée dans l'intervalle PADMÉ.
- **Ligne de commande `janus` :** `cles`, `publique`, `chiffrer` (avec `--cache`), `dechiffrer`, `inspect`, `--version` et `--help`.
- **`janus inspect` :** radiographie défensive des fichiers age, gpg, ZIP, 7-Zip, LUKS, KeePass, `openssl enc`, Ansible Vault et Janus.
- **Vérifications :** 56 tests, 7 vecteurs de test publiés, fuzzing par mutations, banc d'essai, mesure de temps constant (dudect).
- **Documentation :** cartographie, spécification, conception des deux visages, et preuves de déni, d'intégrité et de confidentialité active (IND-RCCA).
- **Outillage :** intégration continue sous Linux, Windows et macOS, et workflow de release avec empreintes SHA-256.

### Corrigé, avant publication, grâce aux preuves
- L'éphémère X25519 était tiré avec un scalaire clampé, que l'on pouvait reconnaître avec un ordinateur quantique.
- La discrétion des emplacements à clé reposait sur MLWE seul.
- Les visages étaient dédoublonnés sur la seule clé, au lieu du triplet (clé, début, longueur).
- Le temps d'ouverture dépendait du nombre d'emplacements déballés.

[Non publié]: https://github.com/moideici/janus/compare/v0.1.0-alpha...HEAD
[0.1.0-alpha]: https://github.com/moideici/janus/releases/tag/v0.1.0-alpha
