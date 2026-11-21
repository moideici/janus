# Journal des versions

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/), et les numéros de version suivent [SemVer](https://semver.org/lang/fr/). Tant que la version reste en 0.x, **le format de fichier peut changer d'une version à l'autre**.

## [Non publié]

## [0.2.0-alpha] — 2026-11-21

Format **Janus v1**, candidat au gel. **Incompatible avec la v0.1.0-alpha** (voir « Modifié »).

### Ajouté
- **Spécification normative en anglais** (`spec/janus-v1.md`), autonome : elle suffit pour écrire une autre implémentation.
- **Quatre clients indépendants** (`clients/`) en Python, TypeScript, C# et Java, écrits à partir de la spécification seule, sans aucun téléchargement. Ils ouvrent tous les vecteurs, et les cinq implémentations s'ouvrent mutuellement leurs fichiers (`clients/interop.py`, 75 combinaisons sur 75). Ce sont des clients d'interopérabilité, pas en temps constant.
- Intégration continue : tests des quatre clients et interopérabilité croisée.
- **Preuves renforcées** ([docs/09](docs/09-preuves-renforcees.md)) : IND-CCA du KEM caché (Q2), avec le lemme du cofacteur, **vérifié par CryptoVerif** par ses deux chemins (`preuves/cryptoverif/`) ; la vérification a fait apparaître l'hypothèse C2PRI d'ML-KEM pour le chemin X25519. Face à un ordinateur quantique, le chemin ML-KEM de toutes les preuves vaut sans oracle aléatoire ; Argon2id dans le QROM.
- **Durcissement** ([docs/08](docs/08-durcissement.md)) :
  - `#![deny(unsafe_code)]`, sauf un petit module (`memoire.rs`) d'appels système ;
  - identité et mots de passe verrouillés en mémoire vive (`mlock`, `VirtualLock`) ; pas de fichier core ; sous Linux, processus non lisible par ptrace ;
  - fuzzing guidé par la couverture (cargo-fuzz, six cibles), chaque nuit en CI ;
  - cargo-deny en CI : failles connues, licences, provenance des dépendances ;
  - rustc épinglé et chemins neutralisés : le binaire Linux est reproductible, vérifié en CI ;
  - attestations de provenance Sigstore sur chaque fichier de release.
- **Entrée et sortie standard (`-`)** pour `chiffrer` et `dechiffrer`. `dechiffrer … -` ouvre **en mémoire** : rien n'est écrit avant que tout soit vérifié, et aucun fichier en clair n'est créé sur le disque.
- **`janus modifier`** : rechiffre un fichier à plusieurs visages en exigeant l'identifiant de chacun, pour n'en perdre aucun, et avertit si le leurre ne change pas.
- La bibliothèque accepte une **liste** de visages cachés (`chiffrer_flux`), et `dechiffrer_visage` indique si le visage ouvert est le leurre.
- Tests de la ligne de commande (`tests/cli.rs`).

### Corrigé
- **Bourrage (Q4)** : l'analyse exacte de la fuite de la taille (`examples/fuite_bourrage.rs`) a montré que tirer `F` dans `[Ref, PADMÉ(Ref)]` fuyait 0,8 bit de plus en moyenne, et 3 à 4 bits de plus au pire, que PADMÉ. `F` est désormais uniforme dans tout le « seau » PADMÉ de `Ref` : fuite exactement égale à celle de PADMÉ, surcoût moyen 2,2 % au lieu de 0,6 %. Seul le chiffrement change ; les vecteurs de test sont régénérés.
- En lisant l'entrée standard, ou en ouvrant un fichier en mémoire (`dechiffrer … -`), le tampon grandissait par réallocations : chaque ancienne copie du clair était libérée **sans être effacée**. Le tampon est désormais alloué une fois, ou agrandi en effaçant l'ancien.
- Les secrets partagés intermédiaires d'ML-KEM et l'aléa de Kemeleon sont maintenant effacés après usage.

### Modifié (format : les fichiers de la v0.1.0-alpha ne s'ouvrent plus)
- **Format v1 candidat au gel.** Toutes les questions de format sont tranchées (tableau dans `docs/07-plan-release.md`). Aucun changement n'est plus prévu, sauf faille trouvée par une relecture ou un audit ; gel définitif en v1.0.
- **Q7 : clés en Bech32m**, comme age. Identité `JANUS-SECRET-KEY-1…` (76 caractères, majuscules), clé publique `janus1…` (minuscules). Nouveaux vecteurs `vecteurs/cles.json`. Les fichiers d'identité de l'aperçu (`JANUS-SECRET-V0-…`) restent lisibles : la paire de clés ne change pas, seul son texte change. Les anciennes clés publiques `janus-pub-v0-…` ne sont plus acceptées ; `janus publique moi.cle` donne la nouvelle.
- **QI-1 : pas d'étiquette sur tout le corps** en v1 (document 06, § 6).
- Une clé publique dont la partie X25519 n'est pas canonique est refusée (elle n'est jamais produite par la génération de clés, et le destinataire n'aurait pas pu ouvrir le fichier). Une même clé répétée dans un visage est refusée.
- `janus cles --help` affichait l'aide… après avoir créé un fichier nommé `--help` : corrigé, et `--help` est reconnu après n'importe quelle commande.
- **QB-3 : 4 étiquettes d'en-tête au lieu de 2.** Un fichier contient un leurre et jusqu'à **3 visages cachés**, qui se partagent la réserve. Avoir livré deux identifiants ne prouve plus qu'on a tout livré. L'en-tête passe de 26 208 à 26 272 octets. Les vecteurs de test sont régénérés, avec un nouveau fichier `quatre-visages.janus`.
- `chiffrer` accepte jusqu'à trois `--cache`, et `modifier` autant d'identifiants cachés.
- Engagement : au plus 4 clés par fichier ; oracle de partition : au plus 4 mots de passe testés par ouverture (documents 05 et 06).

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
