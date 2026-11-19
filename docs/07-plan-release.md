# Janus : plan de release

*19 novembre 2026.*

## Pourquoi pas de release aujourd'hui

Une release invite d'autres personnes à utiliser l'outil, et à garder des fichiers chiffrés avec lui. Pour un outil de chiffrement, cela engage. Il manque trois choses.

1. **Le format bouge encore.**
   - Il a changé trois fois depuis le 18 novembre : passage aux deux visages, éphémère uniforme, masquage de `κ`. Les vecteurs de test ont été régénérés à chaque fois.
   - L'encodage texte des clés est provisoire (spec, question Q7).
   - Deux choix restent ouverts : 2 ou 4 étiquettes (QB-3), étiquette sur tout le corps ou non (QI-1).
   - Un fichier chiffré aujourd'hui pourrait ne plus s'ouvrir demain.
2. **Les tests n'ont tourné que sur une seule machine Windows.** Il n'y a ni intégration continue, ni compilation pour Linux et macOS.
3. **Il manque des éléments de base pour un outil distribué :**
   - `janus --version` ;
   - une aide complète ;
   - un journal des versions (`CHANGELOG`) ;
   - une politique de signalement des failles (`SECURITY.md`) ;
   - des binaires produits par l'intégration continue.

Aucune de ces raisons n'est une faiblesse cryptographique connue. Les preuves (documents 04 à 06) et les tests (56, dont 50 000 mutations de fuzzing) sont en place. Ce qui manque relève de la stabilité et de l'outillage.

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

- **Figer l'encodage texte des clés** (Q7) : préfixes versionnés et somme de contrôle définitive.
- **Lire l'entrée standard et écrire sur la sortie standard**, pour chiffrer dans un tube.
- **Trancher QB-3** (2 ou 4 étiquettes) et **QI-1** (étiquette sur tout le corps).
- **Statistiques et fuzzing :** passer la batterie NIST STS, et lancer `cargo-fuzz` avec mesure de couverture (il faut la chaîne d'outils nightly, à installer avec ton accord).
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
