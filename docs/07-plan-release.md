# Janus : plan de release

*19 novembre 2026.*

## Pourquoi pas de release aujourd'hui

Une release invite d'autres personnes à utiliser l'outil, et à garder des fichiers chiffrés avec lui. Pour un outil de chiffrement, cela engage. Il manque trois choses.

1. **Le format bouge encore.**
   - Il a changé trois fois depuis le 18 novembre : passage aux deux visages, éphémère uniforme, masquage de `κ`. Les vecteurs de test ont été régénérés à chaque fois.
   - ~~L'encodage texte des clés est provisoire (Q7). Un choix reste ouvert : étiquette sur tout le corps ou non (QI-1).~~ *Tout est tranché depuis le 19 novembre 2026 : 4 étiquettes (QB-3), clés en Bech32m (Q7), pas d'étiquette sur tout le corps (QI-1). Le format v1 est candidat au gel.*
   - Un fichier chiffré aujourd'hui pourrait ne plus s'ouvrir demain.
2. **Les tests n'ont tourné que sur une seule machine Windows.** Il n'y a ni intégration continue, ni compilation pour Linux et macOS.
3. **Il manque des éléments de base pour un outil distribué :**
   - `janus --version` ;
   - une aide complète ;
   - un journal des versions (`CHANGELOG`) ;
   - une politique de signalement des failles (`SECURITY.md`) ;
   - des binaires produits par l'intégration continue.

Aucune de ces raisons n'est une faiblesse cryptographique connue. Les preuves (documents 04 à 06) et les tests (70, dont 50 000 puis, après QB-3, 30 000 mutations de fuzzing) sont en place. Ce qui manque relève de la stabilité et de l'outillage.

## Gel du format v1 (19 novembre 2026)

Toutes les questions de format sont tranchées. Le format v1 est **candidat au gel** : aucun changement n'est plus prévu, et il ne bougerait encore que si une relecture ou un audit y trouvait une faille. Il ne sera définitivement gelé qu'en v1.0.

| Question | Décision | Où |
|---|---|---|
| QB-1 Réserve | `max(64 Kio, ⌈L₁/16⌉)` | 03, § 5 |
| QB-2 Option « sans réserve » | Non | 03, § 14 |
| QB-3 Nombre d'étiquettes | 4 : un leurre et jusqu'à 3 visages cachés | 03, § 14 |
| QB-4 v1 remplace v0 | Oui | 03, § 14 |
| QI-1 Étiquette sur tout le corps | Non | 06, § 6 |
| Q3 Version de Kemeleon | `draft-irtf-cfrg-kemeleon-02`, figée par les vecteurs | 02, § 12 |
| Q5 Nombre d'emplacements | 16 | 02, § 12 |
| Q6 Argon2id | 64 Mio, t = 3, p = 4 | 02, § 3.2 |
| Q7 Encodage des clés | Bech32m, préfixes `janus` et `JANUS-SECRET-KEY-` | 02, § 3.1 |
| Q10 Ordre des octets de Kemeleon | Gros-boutiste | 02, § 12 |

**Spécification et implémentations indépendantes (20 novembre 2026).** Le format est décrit en anglais dans [`spec/janus-v1.md`](../spec/janus-v1.md). Quatre clients (Python, TypeScript, C#, Java) ont été écrits à partir de ce seul texte : tous ouvrent les vecteurs de test, et les cinq implémentations s'ouvrent mutuellement leurs fichiers. Leurs retours ont servi à préciser la spécification (vecteur X-Wing complet, décodage de `pk_X`, règles R1 à R5 au complet, fichiers de clés).

~~Restent ouvertes des questions de preuve : Q2, Q4, vérification par machine, QROM.~~ *Traitées le 21 novembre 2026 dans [09-preuves-renforcees.md](09-preuves-renforcees.md)* : Q4 a conduit au bourrage « seau » (le chiffrement seul change) ; Q2 est prouvé et vérifié par CryptoVerif ; le chemin ML-KEM se passe de l'oracle aléatoire. Reste à vérifier par machine le fichier entier, et surtout à faire relire.

## Les étapes

### v0.1.0-alpha : « aperçu » (objectif : très bientôt)

Une **pré-release** GitHub, marquée comme telle, pour essayer Janus et le critiquer. Elle n'est pas destinée à de vrais secrets.

| Travail | Critère de fin | État (19 novembre 2026) |
|---|---|---|
| Intégration continue GitHub Actions : compilation, 56 tests, `clippy`, sous Linux, Windows et macOS | Les trois systèmes sont au vert | **Fait** : au vert sur les trois systèmes (`.github/workflows/ci.yml`) |
| `janus --version` et `janus --help`, avec la mention du format (« Janus v1, aperçu non figé ») | Les deux commandes répondent | **Fait** |
| Binaires Linux, Windows et macOS produits par l'intégration continue à chaque étiquette `v*`, avec leurs empreintes SHA-256 | Le premier tag produit les trois binaires | **Fait** (`.github/workflows/release.yml`), déclenché par l'étiquette `v0.1.0-alpha` |
| `CHANGELOG.md` et `SECURITY.md` | Les deux fichiers sont présents | **Fait** |
| Notes de version claires : aperçu, format non figé, aucun audit, compatibilité non garantie | Texte relu | **Fait** ([`notes-de-version/v0.1.0-alpha.md`](notes-de-version/v0.1.0-alpha.md)) |
| Vérification des licences des dépendances (MIT, Apache-2.0 ou BSD) | Liste jointe aux notes | **Fait** ([`licences-dependances.md`](licences-dependances.md)) : 65 crates, toutes compatibles |

**Ce qui déclenche la release :** tous les critères ci-dessus remplis, puis ton accord explicite. *Accord donné le 19 novembre 2026 : étiquette `v0.1.0-alpha` posée.*

### v0.2.0-alpha : stabiliser ce qui touche l'utilisateur

*Publiée le 21 novembre 2026* ([notes de version](notes-de-version/v0.2.0-alpha.md)), avec en plus la spécification en anglais, quatre clients indépendants, le durcissement et les preuves renforcées. Restent de cette étape : la batterie NIST STS et la comparaison avec age.

- ~~**Figer l'encodage texte des clés** (Q7)~~ **Fait** : Bech32m, préfixes `janus` et `JANUS-SECRET-KEY-`, vecteurs dans `janus-rs/vecteurs/cles.json`.
- **Lire l'entrée standard et écrire sur la sortie standard**, pour chiffrer dans un tube.
- ~~**Trancher QB-3**~~ **Fait** : 4 étiquettes, jusqu'à 3 visages cachés. ~~QI-1~~ **Tranché** : pas d'étiquette sur tout le corps en v1 (document 06, § 6).
- ~~**Lire l'entrée standard et écrire sur la sortie standard**~~ **Fait**, avec l'ouverture en mémoire et `janus modifier`.
- **Statistiques et fuzzing :** passer la batterie NIST STS. ~~Lancer `cargo-fuzz` avec mesure de couverture~~ **Fait** (20 novembre 2026) : six cibles, chaque nuit en CI, avec le reste du durcissement ([08-durcissement.md](08-durcissement.md)).
- **Comparer avec age** : débit, taille des fichiers, et ce que révèle `janus inspect`.

### v0.9.0-beta : candidat au gel du format

- **Format v1 déclaré candidat au gel :** vecteurs de test définitifs, publiés et signés.
- **Vérification par machine :** modéliser dans CryptoVerif les preuves 04 à 06, ou au moins les étapes G₁ à G₇.
- **Relecture :** demander l'avis de cryptographes, par exemple sur le forum CFRG ou auprès des auteurs de Kemeleon et d'X-Wing.

### v1.0.0 : format gelé

- **Audit externe** du code et du format.
- **Format gelé :** tout changement ultérieur passera par un format v2, avec de nouvelles étiquettes de dérivation (J-09).
- **Compatibilité garantie :** un fichier chiffré en v1.0 s'ouvrira avec toutes les versions 1.x.

## Ce qui est prêt dès maintenant

- Le code, les 56 tests, les preuves, les vecteurs de test et la documentation sont publics sur [github.com/moideici/janus](https://github.com/moideici/janus).
- La documentation en ligne est sur [docs.moideici.tech/janus](https://docs.moideici.tech/janus/).
- Chacun peut compiler et essayer Janus : `cargo build --release`.
