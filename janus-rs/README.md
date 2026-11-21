# janus-rs : prototype de Janus v1 (deux visages)

> ⚠️ **Prototype de recherche.** Le format v1 est candidat au gel (pas encore définitivement gelé) et le code n'a fait l'objet d'aucun audit externe. **Ne l'utilise pas pour de vrais secrets.**

Ce dossier implémente la spécification [docs/02-spec-v0.md](../docs/02-spec-v0.md), modifiée par la conception des deux visages [docs/03-deux-visages.md](../docs/03-deux-visages.md). Un fichier peut s'ouvrir sur un **leurre** avec un premier identifiant et sur un **secret** avec un second. Tous les fichiers ont la même forme, qu'ils cachent un second visage ou non.

## Commandes

Toutes se lancent depuis `janus-rs/`.

| Action | Commande |
|---|---|
| Compiler | `cargo build --release` |
| Lancer les 70 tests | `cargo test --release` |
| Banc d'essai | `cargo run --release --example banc` |
| Test de temps constant | `cargo run --release --example dudect` |
| Longue campagne de fuzzing | `JANUS_FUZZ_ITER=100000 cargo test --release --test fuzz -- --nocapture` |
| Créer une identité | `target/release/janus cles moi.cle > moi.pub` |
| Chiffrer pour une clé publique | `target/release/janus chiffrer -R moi.pub photo.jpg photo.janus` |
| Déchiffrer | `target/release/janus dechiffrer -i moi.cle photo.janus photo.jpg` |
| Chiffrer par mot de passe | `target/release/janus chiffrer -m notes.txt notes.janus` |
| **Deux visages** : un leurre et un secret | `target/release/janus chiffrer -m vacances.zip coffre.janus --cache -m journal.txt` |
| Ouvrir le visage qui correspond au mot de passe saisi | `target/release/janus dechiffrer -m coffre.janus sortie` |
| Ouvrir **en mémoire**, sans fichier en clair sur le disque | `target/release/janus dechiffrer -m coffre.janus - \| less` |
| Rechiffrer en gardant tous les visages, et en changeant le leurre | `target/release/janus modifier -m --leurre vacances2.zip coffre.janus coffre2.janus --cache -m` |
| Voir ce qu'un tiers apprend d'un fichier | `target/release/janus inspect photo.janus archive.zip lettre.gpg` |

Précisions sur la ligne de commande :
- `-r <clé>` passe une clé publique en argument, `-R <fichier>` la lit dans un fichier. On peut les répéter, jusqu'à 16 destinataires au total pour les deux visages. `janus publique moi.cle` réaffiche la clé publique d'une identité.
- Tout ce qui suit `--cache` décrit le visage caché : ses destinataires (`-r`, `-R` ou `-m`), puis son fichier. Le secret doit tenir dans la **réserve** : 1/16 de la taille du leurre, et au moins 64 Kio. Sinon, Janus refuse et indique la capacité disponible.
- `dechiffrer` ne signale **jamais** l'existence d'un autre visage.
- Les fichiers de clés peuvent être en UTF-8 ou en UTF-16 : la redirection `>` de PowerShell fonctionne directement.
- Les fichiers sont traités **en flux**, à mémoire bornée (environ 42 Mio, plus 64 Mio pour Argon2 avec un mot de passe, quelle que soit leur taille).
- Le résultat est écrit dans un fichier temporaire, renommé seulement si tout est valide. Un fichier refusé ne laisse aucune trace.

## Organisation du code

| Fichier | Rôle | Spec |
|---|---|---|
| `src/format.rs` | Format v1 : 4 étiquettes, sel commun, emplacements, réserve, un leurre et jusqu'à 3 visages cachés en STREAM par lots parallèles, ouverture en flux | 03-deux-visages § 3 à 7 |
| `src/xwing.rs` | X-Wing draft-11 et encapsulation cachée (point sale uniforme, Elligator 2, Kemeleon, masquage de κ) | § 3.1, 6 |
| `src/kemeleon.rs` | Kemeleon draft-02, **en temps constant** | § 6 |
| `src/elligator.rs` | Inverse d'Elligator 2 pour un point quelconque, en temps constant (`fiat-crypto`) : permet un scalaire éphémère uniforme, non clampé | § 6, 04-preuve § 7.1 |
| `src/cles.rs` | Encodage texte des clés : Bech32m, en temps constant pour l'identité | Q7 |
| `src/inspect.rs` | `janus inspect` : radiographie défensive (age, gpg, ZIP, 7-Zip, LUKS, KeePass, openssl, Janus) | § 7, piste H |
| `src/alea.rs` | Aléa du système uniquement ; flux déterministe réservé aux tests | § 2 |
| `src/vecteurs.rs` | Génération et vérification des vecteurs de test | § 13.1 |
| `vecteurs/` | 8 fichiers `.janus` de référence, dont un à deux et un à quatre visages, et `manifeste.json` | § 13.1 |
| `tests/format.rs` | Allers-retours, fichiers piégés, statistiques, flux | § 13.2 |
| `tests/visages.rs` | Deux visages : ouverture, règles R3 et R5, capacité, taille, vue de l'adversaire contraint | 03-deux-visages § 13 |
| `tests/fuzz.rs` | Fuzzing par mutations, sur des fichiers à un et à deux visages | § 13.3 |
| `tests/inspect.rs`, `tests/echantillons/` | Tests d'`inspect`, sur de vrais fichiers gpg et 7-Zip produits avec des clés jetables | § 13.3 |
| `examples/dudect.rs` | Mesure de temps constant | § 13.3 |

## Ce qui est vérifié

### Conformité
- **X-Wing** : le vecteur de test officiel n° 1 du draft-11 est reproduit.
- **Kemeleon** :
  - les intervalles d'antécédents, calculés sans énumération, coïncident exactement avec Z_q pour tous les c ;
  - leurs tailles sont celles du draft (3 ou 4, et 208 ou 209) ;
  - le décodage donne les mêmes chiffres qu'une implémentation de référence en num-bigint.
- **Division par q sans l'instruction `div`** : vérifiée exhaustivement jusqu'à 2^22, aux bornes de chaque multiple de q, et sur un million de tirages jusqu'à 2^44.

### Temps constant (dudect, 20 000 mesures, seuil |t| = 4,5)

| Fonction mesurée | Temps médian | \|t\| max | Verdict |
|---|---|---|---|
| **Témoin** : décodage num-bigint | 167 µs | **13 274** | fuite détectée |
| Kemeleon.DecodeCtxt | 227 µs | 0,92 | aucune fuite détectée |
| Kemeleon.EncodeCtxt | 31 µs | 0,97 | aucune fuite détectée |
| Ouverture d'un emplacement (valide ou aléatoire) | 359 µs | 2,17 | aucune fuite détectée |
| Ouverture du leurre, fichier sans ou avec visage caché (1 000 mesures) | 8,1 ms | 1,34 | aucune fuite détectée |
| Inverse d'Elligator 2 maison (10 000 mesures, deux passages) | 26 µs | 1,13 | aucune fuite détectée |
| Ouverture ratée : un emplacement se déballe mais les étiquettes sont fausses, ou rien ne se déballe (2 000 mesures). Avant le correctif de docs/05 § 7.3 : \|t\| = 2,85 | 12 ms | 1,50 | aucune fuite détectée |

Le témoin prouve que la mesure sait repérer une fuite.

*Leçon de méthode.* Dans une première version du banc, chaque entrée était préparée juste avant sa mesure. Préparer une entrée aléatoire (tirage, multiplication de base) perturbe les caches, et la mesure suivante en est ralentie. Résultat : deux fausses alertes, dont une sur Kemeleon, dont le code n'avait pas changé (|t| = 27,8). Toutes les entrées sont maintenant préparées avant les mesures, et les alertes ont disparu. Les autres lignes signifient « rien de détecté avec ce nombre de mesures », pas « preuve d'absence ».

### Discrétion
- **Éphémère X25519 uniforme, y compris face à un ordinateur quantique** : on donne au test le vrai logarithme discret du scalaire, ce que seul un ordinateur quantique saurait calculer.
  - L'ancien tirage clampé tombait dans la moitié testée 2 000 fois sur 2 000.
  - Le nouveau y tombe environ une fois sur deux, comme un point aléatoire.
  - Notre inverse d'Elligator 2 coïncide octet pour octet avec celui du crate sur les points que le crate sait traiter.
- **Discrétion hybride** : le chiffré ML-KEM encodé (`κ`) est masqué par un flux dérivé du secret X25519. Un emplacement à clé ne devient reconnaissable que si MLWE **et** X25519 tombent tous les deux. C'est la même garantie que pour la confidentialité ([docs/04-preuve-deux-visages.md](../docs/04-preuve-deux-visages.md), § 7.2). Le χ² des `κ` masqués vaut 261, pour environ 255 attendus.
- Un test du χ² repère sans peine les chiffrés ML-KEM bruts (χ² = 3129, pour environ 1023 attendus). Il ne distingue ni Kemeleon ni les fichiers Janus de l'aléa (χ² ≈ 265, pour environ 255 attendus).
- Les éphémères sont bien « sales » : environ 1 sur 8 seulement est dans le sous-groupe premier.
- La taille est uniforme dans le seau PADMÉ de Ref (docs/09, § 1) et indépendante du nombre de destinataires.

### Deux visages
- **Chaque identifiant ouvre son visage, et seulement le sien**, avec toutes les combinaisons : deux mots de passe, deux jeux de clés, mot de passe et clé dans les deux sens.
- **Vue de l'adversaire contraint** : avec la clé du leurre, tout ce qu'il ne peut pas ouvrir (l'autre étiquette, les emplacements, la réserve) a la même loi avec ou sans secret. Test d'homogénéité du χ² sur 7,5 millions d'octets, avec un secret fait de zéros (le pire cas) : χ² = 265,8, p = 0,31. Le même test détecte un écart de 2 % s'il en existe un. Repris après QB-3 en mélangeant des fichiers à 1 et à 3 visages cachés : χ² = 249,6, p = 0,58.
- **La taille ne dépend que du leurre** : mêmes bornes, même moyenne, avec ou sans secret.
- **Règles** : même mot de passe ou même clé pour les deux visages refusés, plus de 16 destinataires au total refusés. Un en-tête piégé où un même mot de passe ouvre une même clé à deux positions est signalé comme « plusieurs visages ». La capacité de la réserve est **exacte** : un secret de la taille maximale passe, un octet de plus est refusé.
- **Intégrité par visage** : modifier la réserve ne gêne pas le leurre (c'est voulu), mais ferme le secret. Toute troncature ou tout ajout ferme les deux visages, car la taille totale est couverte par les étiquettes.
- **Ligne de commande** : sur 2 Gio de leurre, le leurre et le secret ressortent identiques. Un mauvais mot de passe ne laisse aucune trace.

### Robustesse
- **Corpus piégé** : bits inversés, troncatures (y compris pile entre deux lots), ajouts, blocs échangés ou dupliqués, `début` ou `longueur` falsifiés dans un en-tête authentique, emplacement greffé, fichier aléatoire. Tous sont refusés par l'unique message « impossible de déchiffrer ».
- **Fuzzing par mutations** : 50 000 mutations de 10 types (dont des greffes entre fichiers), sur des fichiers à un et à deux visages, relancées le 19 novembre 2026 après l'éphémère uniforme, le masquage de κ et les correctifs d'intégrité. Durée : 8 min 14 s.
  - Aucune panique, et **jamais un autre clair** que l'original.
  - 11 339 mutations ont été acceptées. Toutes ne touchaient que la réserve ou l'étiquette de l'autre visage, ce que le test vérifie octet par octet.
  - Repris après QB-3 : 30 000 mutations, dont un fichier à quatre visages (5 min 39 s). Aucune panique, jamais un autre clair ; 6 200 acceptées, toutes limitées à la réserve ou aux étiquettes des autres visages.
- **Vecteurs de test** : 8 fichiers de référence, dont un à deux visages et un à quatre visages, publiés avec tous leurs mots de passe. Chacun s'ouvre avec les clés indiquées dans le manifeste, et notre chiffrement, avec un aléa déterministe, les reproduit octet pour octet. Tout changement involontaire du format fait échouer les tests.
- **Fichier de 2 Gio abîmé au milieu** : refusé, sans laisser ni sortie ni fichier temporaire.

## `janus inspect` : ce qu'un tiers voit

`inspect` lit un fichier **sans clé**, sans rien déchiffrer ni écrire. Il dit ce que le fichier révèle : l'outil, les destinataires, les algorithmes, la taille du clair et la part d'aléa. Sur les échantillons de `tests/echantillons/` :

| Fichier | Outil | Destinataires | Algorithmes | Taille du clair | Noms de fichiers |
|---|---|---|---|---|---|
| gpg, 2 clés | visible | **identifiants de clé** en clair | visibles | à quelques octets près | non |
| gpg, mot de passe | visible | 1 mot de passe | AES-256, SHA-512 sur 24 Mo | à quelques octets près | non |
| age (construit à la main) | visible | nombre et type, étiquette des clés SSH | visibles | **exacte** | non |
| ZIP ZipCrypto | visible | sans objet | ZipCrypto, **cassé** | exacte, fichier par fichier, avec le CRC-32 | **en clair** |
| ZIP AES-256 | visible | sans objet | visibles | exacte, fichier par fichier | **en clair** |
| 7-Zip sans `-mhe` | visible | sans objet | non analysés | non analysée | lisibles par `7z l` |
| **Janus** | **rien** | **rien** | **rien** | une plage (environ 3 % de 512 Mio) | non |

Pour un fichier sans signature, `inspect` teste l'hypothèse « fichier Janus v1 » : la taille est-elle possible, et le contenu indiscernable de l'aléa (χ² global et χ² par bloc de 4 Kio) ? Si oui, il calcule la plage de taille du leurre et la capacité d'un éventuel visage caché, dont il ne peut rien dire de plus. Il précise que cela **ne prouve pas** que le fichier vient de Janus.

Garanties testées :
- aucun faux positif sur 14 000 fichiers aléatoires, y compris en imposant chacun des 256 premiers octets possibles ;
- aucune panique sur des échantillons tronqués à chaque longueur et abîmés 3 000 fois chacun ;
- 512 Mio analysés en 0,4 s.

## Performances

Windows 11, 16 cœurs logiques. **Attention aux comparaisons entre deux jours** : le 18 novembre au soir, Argon2id seul prenait 117 ms, contre 83 ms le matin, à code identique. La machine était donc environ 40 % plus lente lors des mesures v1.

### Opérations sur l'en-tête (v1, soir)

| Opération | Durée |
|---|---|
| Encapsulation cachée, par destinataire (avec l'éphémère uniforme) | 0,32 ms |
| Ouverture par clé (16 emplacements, Kemeleon en temps constant, 16 étiquettes toujours calculées) | 8,8 ms |
| Ouverture par mot de passe (un Argon2id, puis 16 essais d'AEAD) | 125 à 140 ms, dont 117 ms d'Argon2id |
| Chiffrement pour 16 destinataires | 6,0 ms |

### De bout en bout, disque compris

| Opération | Durée | Pic mémoire |
|---|---|---|
| v1, chiffrer 2 Gio pour une clé | 2,3 s | 42 Mio |
| v1, déchiffrer ces 2 Gio | 2,2 s | 42 Mio |
| v1, chiffrer 2 Gio de leurre et un secret, par mots de passe | 2,6 s | 72 Mio, dont 64 pour Argon2id |
| v1, ouvrir le secret caché dans ce fichier | 0,7 s | 73 Mio |
| *v0, matin : chiffrer 2 Gio* | *1,45 s* | *26 Mio* |
| *v0, matin : déchiffrer 2 Gio* | *1,62 s* | *26 Mio* |
| gpg 2.4.9 (AES-256, sans compression), matin : chiffrer 256 Mio | 1,71 s | |
| gpg 2.4.9, matin : déchiffrer 256 Mio | 1,59 s | |

La v1 écrit 6 % d'octets en plus (la réserve). Même avec la machine ralentie, Janus traite 2 Gio dans un temps proche de celui que gpg mettait pour 256 Mio. age n'est pas installé : cette comparaison reste à faire.

## Limites connues

- **Aucun audit externe.**
- Le fuzzing tourne en Rust stable par mutations. `cargo-fuzz` (avec mesure de couverture) demande la toolchain nightly, qui n'est pas installée.
- **Preuves papier** : déni ([docs/04](../docs/04-preuve-deux-visages.md)), intégrité ([docs/05](../docs/05-preuve-integrite.md)) et confidentialité face aux fichiers piégés ([docs/06](../docs/06-preuve-confidentialite-active.md)). Aucune n'est vérifiée par machine ni relue par un tiers.
- **IND-RCCA, pas IND-CCA** : on peut fabriquer une autre version d'un fichier qui donne exactement le même clair, en modifiant la réserve ou l'étiquette de l'autre visage. On ne peut pas en fabriquer une qui donne un clair lié. C'est inévitable avec deux visages (docs/06, § 1).
- **`dechiffrer_flux` écrit les lots vérifiés au fur et à mesure** : un programme qui l'utilise doit jeter toute la sortie si la fonction échoue. La ligne de commande et `dechiffrer` le font déjà (docs/06, § 5).
- **Prix du déni** :
  - un auteur malveillant peut faire lire des contenus différents (quatre au plus) à plusieurs destinataires d'**un même fichier** : pour vérifier qu'on a lu la même chose, il faut comparer l'empreinte du clair ;
  - un tiers peut effacer le secret en écrasant la réserve, sans que le leurre le détecte : garde une copie.
 Les pièges d'usage sont décrits au § 10 de ce document : plusieurs versions d'un même fichier, rechiffrement du seul leurre qui efface le secret, traces laissées par le système.
- Ouvrir le secret oblige à lire tout le leurre qui le précède (le format se lit en flux, sans saut). C'est sans conséquence pour la discrétion : l'adversaire contraint n'ouvre que le leurre, et cette ouverture prend le même temps avec ou sans secret.
- `ml-kem` et `curve25519-elligator2` effacent leurs secrets à la destruction, mais les copies faites par le système (fichier d'échange, vidage mémoire) ne sont pas maîtrisées.
- L'entrée standard (`-`) est lue entièrement en mémoire, car Janus doit connaître la longueur du clair avant d'écrire l'en-tête. De même, `dechiffrer … -` garde tout le clair en mémoire jusqu'à la fin de la vérification. Ces deux modes conviennent donc aux fichiers qui tiennent en mémoire.
- `inspect` reconnaît les formats par leur structure, sans les décoder entièrement : il ne décompresse pas l'en-tête 7z et n'analyse pas le JSON de LUKS2 ni l'en-tête KeePass. Pour age, les tests portent sur des fichiers construits à la main, car age n'est pas installé.
