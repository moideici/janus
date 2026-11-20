# Janus

[![CI](https://github.com/moideici/janus/actions/workflows/ci.yml/badge.svg)](https://github.com/moideici/janus/actions/workflows/ci.yml)

**Un format de chiffrement de fichiers post-quantique, indistinguable de l'aléa, et à deux visages.**

> ⚠️ **Prototype de recherche.** Le format v1 est candidat au gel mais pas encore définitivement gelé, le code n'a eu aucun audit externe, et les preuves de sécurité n'ont été relues par personne. **Ne l'utilise pas pour de vrais secrets.** Voir le [plan de release](docs/07-plan-release.md).

📖 Documentation complète : **[docs.moideici.tech/janus](https://docs.moideici.tech/janus/)**

## Ce que Janus fait autrement

| | gpg | age | **Janus** |
|---|---|---|---|
| Post-quantique hybride (ML-KEM-768 + X25519) | non (2.4) | en option | **oui, toujours** |
| L'outil se reconnaît au premier octet | oui | oui | **non : tout le fichier ressemble à de l'aléa** |
| Le nombre de destinataires se voit | oui, avec leurs identifiants | oui | **non** (16 emplacements toujours présents) |
| La taille du clair se lit | à quelques octets près | exactement | **à quelques pour cent près** (bourrage PADMÉ aléatoire, et réserve) |
| Un même fichier s'ouvre sur plusieurs contenus | non | non | **oui : un leurre et jusqu'à 3 secrets** |
| Engagement de clé | non | oui | **oui** |

**Les deux visages.** Un fichier s'ouvre sur un leurre avec un premier mot de passe, et sur le vrai contenu avec un second. Si quelqu'un te force à donner ton mot de passe, tu donnes celui du leurre. Il ne peut pas **prouver** qu'un second visage existe, parce que **tous** les fichiers Janus ont la même forme, qu'ils en contiennent un ou non.

```bash
cd janus-rs
cargo build --release
./target/release/janus chiffrer -m vacances.zip coffre.janus --cache -m journal.txt
./target/release/janus dechiffrer -m coffre.janus sortie          # ouvre le visage du mot de passe saisi
./target/release/janus inspect coffre.janus archive.zip lettre.gpg  # ce qu'un tiers voit, sans clé
```

## Contenu du dépôt

| Dossier | Contenu |
|---|---|
| [`janus-rs/`](janus-rs/README.md) | Le prototype en Rust : bibliothèque, ligne de commande `janus`, 67 tests, vecteurs de test, banc d'essai, test de temps constant (dudect) |
| [`spec/janus-v1.md`](spec/janus-v1.md) | **La spécification normative du format, en anglais** : tout ce qu'il faut pour écrire une autre implémentation |
| [`clients/`](clients/README.md) | Quatre implémentations indépendantes écrites à partir de la spécification seule (Python, TypeScript, C#, Java), et le test d'interopérabilité croisée |
| [`docs/`](docs/) | La conception et les preuves, de la cartographie au plan de release (voir ci-dessous) |

### Documents

| N° | Document | Sujet |
|---|---|---|
| 01 | [Cartographie](docs/01-cartographie.md) | Menaces, exigences J-01 à J-11, failles connues ailleurs, pistes d'innovation, décisions |
| 02 | [Spécification v0](docs/02-spec-v0.md) | Le format de base : X-Wing caché, Kemeleon, Elligator 2, STREAM, PADMÉ |
| 03 | [Deux visages](docs/03-deux-visages.md) | Le format v1 : réserve, 4 étiquettes (un leurre et jusqu'à 3 visages cachés), pièges d'usage |
| 04 | [Preuve de déni](docs/04-preuve-deux-visages.md) | Séquence de jeux. La preuve a révélé, puis fait corriger, une faiblesse quantique |
| 05 | [Preuve d'intégrité](docs/05-preuve-integrite.md) | Engagement, cohérence par visage, absence d'oracle de partition |
| 06 | [Preuve de confidentialité active](docs/06-preuve-confidentialite-active.md) | IND-RCCA, et pourquoi IND-CCA strict est impossible avec deux visages |
| 07 | [Plan de release](docs/07-plan-release.md) | Ce qui manque avant une première version, et dans quel ordre |

## Ce qui est vérifié

- **Conformité :** le vecteur de test officiel d'X-Wing (draft-11) est reproduit, et Kemeleon est comparé à une implémentation de référence.
- **Spécification complète :** quatre clients écrits à partir de [la spécification](spec/janus-v1.md) seule, sans lire le code Rust, ouvrent tous les vecteurs de test. Chacune des cinq implémentations ouvre les fichiers de toutes les autres (75 combinaisons sur 75, vérifiées par l'intégration continue).
- **Discrétion :** les fichiers passent le test du χ², alors que les chiffrés ML-KEM bruts sont détectés. L'éphémère X25519 est uniforme, même face à un adversaire capable de calculer des logarithmes discrets.
- **Déni :** ce que voit l'adversaire contraint suit la même loi avec ou sans secret (test d'homogénéité, p = 0,58 en mélangeant des fichiers à 1 et à 3 visages cachés).
- **Temps constant :** dudect ne détecte aucune fuite sur Kemeleon, Elligator, la décapsulation ou l'ouverture. Le test lui-même sait repérer une fuite : il la détecte sur un témoin volontairement vulnérable.
- **Robustesse :** 80 000 mutations de fuzzing (50 000, puis 30 000 après QB-3, dont un fichier à quatre visages) ne produisent jamais de panique, ni d'autre clair que l'original.

Les détails et les limites sont dans [janus-rs/README.md](janus-rs/README.md).

## Versions, sécurité, licence

- [Journal des versions](CHANGELOG.md) et [plan de release](docs/07-plan-release.md).
- Pour signaler une faille, voir la [politique de sécurité](SECURITY.md).
- Licence [MIT](LICENSE). Celles des dépendances sont listées dans [docs/licences-dependances.md](docs/licences-dependances.md).
