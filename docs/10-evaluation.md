# Janus : évaluation face à age, et batterie NIST STS

*21 novembre 2026, Janus 0.2.0-alpha, Windows 11, 16 cœurs logiques.*

Ce document répond aux deux dernières demandes de l'étape v0.2.0-alpha du [plan de release](07-plan-release.md) : comparer Janus à age, l'outil de chiffrement de fichiers moderne de référence, et passer la batterie statistique du NIST sur des fichiers Janus. Il décrit aussi les vecteurs de test ajoutés.

## 1. Janus face à age

Outils : **age v1.2.1**, binaire officiel, et **Janus 0.2.0-alpha**. Script : [`bancs/comparer_age.py`](../bancs/comparer_age.py). Mêmes clairs, aléatoires, pour les deux outils.

### 1.1 Taille du fichier chiffré

Surcoût en octets, et en pourcentage du clair :

| Clair | age, 1 clé X25519 | Janus, 1 clé | Janus, mot de passe | Janus, leurre + 1 visage caché |
|---|---|---|---|---|
| 0 o | +200 | +92 638 | +92 474 | +92 788 |
| 100 o | +200 | +92 185 | +93 941 | +93 633 |
| 10 Kio | +200 (2,0 %) | +93 636 (914 %) | +93 044 (909 %) | +92 518 (904 %) |
| 1 Mio | +440 (0,04 %) | +101 929 (9,7 %) | +121 892 (11,6 %) | +104 235 (9,9 %) |
| 100 Mio | +25 784 (0,03 %) | +8 662 280 (8,3 %) | +9 754 225 (9,3 %) | +9 521 017 (9,1 %) |

**Lecture.**
- age ajoute environ 200 octets, plus 16 octets par bloc de 64 Kio. Janus ajoute un **coût fixe d'environ 92 Ko** (l'en-tête de 26 Ko, plus la réserve minimale de 64 Kio), puis **8 à 9 % du clair** (la réserve de 1/16, et le seau PADMÉ).
- La taille d'un fichier Janus est **tirée au hasard** dans le seau. Deux chiffrements du même clair n'ont donc pas la même taille, d'où les écarts entre colonnes (par exemple 9,7 % et 11,6 % pour 1 Mio).
- Ajouter un visage caché **ne change pas la loi de la taille** : il vit dans la réserve. C'est le cœur du déni.
- **Conclusion :** Janus n'est pas fait pour chiffrer de petits fichiers, où age est imbattable. Il vise les archives et les documents, où quelques pour cent de taille achètent la discrétion et le déni.

### 1.2 Débit

1 Gio de bout en bout, disque compris, pour une clé publique (meilleur de 3) :

| Outil | Chiffrer | Déchiffrer |
|---|---|---|
| age | 1,23 s (831 Mio/s) | 1,35 s (760 Mio/s) |
| Janus | 1,28 s (798 Mio/s) | 1,38 s (742 Mio/s) |

**Lecture.** Les débits sont pratiquement identiques. Janus écrit 8 % d'octets en plus, mais il chiffre en parallèle sur tous les cœurs.

### 1.3 Ouverture d'un petit fichier

Processus compris, meilleur de 5 :

| Opération | Durée |
|---|---|
| age, clé X25519 | 27 ms |
| Janus, clé X-Wing (16 emplacements toujours essayés) | 46 ms |
| Janus, mot de passe (Argon2id, 64 Mio) | 147 ms |

**Lecture.** Janus essaie toujours les 16 emplacements et les 4 étiquettes, pour ne rien révéler par le temps. Il fait de plus une décapsulation ML-KEM par emplacement. Cela coûte une vingtaine de millisecondes de plus qu'age, sans conséquence à l'usage. Pour un mot de passe, age utilise scrypt avec un facteur de travail réglé pour environ une seconde ; non mesuré ici, car age ne lit la phrase de passe qu'au clavier.

### 1.4 Ce qu'un tiers apprend

C'est la différence de fond. `janus inspect`, sans aucune clé, sur un fichier d'un octet chiffré par chacun des deux outils :

| | age | Janus |
|---|---|---|
| L'outil | **oui** : le fichier commence par `age-encryption.org/v1` en clair | non : aucun format reconnu |
| Le nombre de destinataires | **oui** : une strophe par destinataire | non : 16 emplacements toujours présents |
| Leur type (clé, mot de passe, SSH, greffon) | **oui** | non |
| La partie éphémère X25519 | **lisible**, en base64, et distinguable de l'aléa | cachée par Elligator 2, uniforme |
| La taille du clair | **exactement** (1 octet) | une plage (« entre 0 et 336 octets ») |
| La présence d'un visage caché | sans objet | impossible à savoir (« jusqu'à 3 autres visages ») |
| Test du χ² sur les octets | sans objet (en-tête en texte) | p = 0,88 : indiscernable de l'aléa |

age ne prétend pas cacher ces informations ; ce n'est pas son objectif. Ce tableau montre simplement ce que Janus apporte de plus, au prix de la taille.

**Post-quantique.** age v1.2.1 n'a pas de destinataire post-quantique intégré (il passe par des greffons). Janus est toujours hybride : X-Wing, soit ML-KEM-768 et X25519.

## 2. Batterie NIST STS

Outil : **NIST SP 800-22, sts-2.1.2**, le programme officiel du NIST, compilé tel quel. Script de préparation : [`bancs/nist_sts.py`](../bancs/nist_sts.py).

**Entrée.** 100 séquences d'un million de bits (12,5 Mo), faites de **63 fichiers Janus entiers**, mis bout à bout : en-têtes, emplacements, réserves, marge de taille et corps. La moitié sont chiffrés pour une clé publique, l'autre moitié par mot de passe, avec un visage caché. **Tous les clairs sont nuls** : c'est le pire cas pour un format dont chaque octet doit paraître aléatoire.

**Résultat : les 188 sous-tests passent, aucun n'est signalé en échec.**

| Test | Sous-tests | p-valeur d'uniformité la plus basse | Proportion de séquences réussies la plus basse |
|---|---|---|---|
| Frequency | 1 | 0,72 | 100/100 |
| BlockFrequency | 1 | 0,80 | 97/100 |
| CumulativeSums | 2 | 0,92 | 99/100 |
| Runs | 1 | 0,62 | 96/100 |
| LongestRun | 1 | 0,55 | 97/100 |
| Rank | 1 | 0,11 | 99/100 |
| FFT | 1 | 0,60 | 98/100 |
| NonOverlappingTemplate | 148 | 0,0005 | 96/100 |
| OverlappingTemplate | 1 | 0,98 | 100/100 |
| Universal | 1 | 0,92 | 100/100 |
| ApproximateEntropy | 1 | 0,70 | 98/100 |
| RandomExcursions | 8 | 0,030 | 63/65 |
| RandomExcursionsVariant | 18 | 0,0005 | 64/65 |
| Serial | 2 | 0,076 | 99/100 |
| LinearComplexity | 1 | 0,49 | 99/100 |

**Lecture.**
- Seuils du NIST pour ces effectifs : au moins 96 séquences sur 100 (61 sur 65 pour les excursions), et une p-valeur d'uniformité d'au moins 0,0001. Tous les tests sont au-dessus.
- Avec 188 sous-tests, quelques p-valeurs basses sont attendues par hasard. Les deux plus basses (0,0005) restent cinq fois au-dessus du seuil.
- Les tests d'excursions ne s'appliquent qu'aux séquences qui ont assez de cycles : 65 sur 100 ici, ce qui est normal.

**Ce que cela prouve, et ce que cela ne prouve pas.** Une batterie statistique ne détecte que des défauts grossiers (biais, motifs, structure répétée), et elle n'en a trouvé aucun. Elle ne prouve pas l'indistinguabilité, qui est l'objet du [document 04](04-preuve-deux-visages.md). Elle vérifie que l'implémentation ne trahit pas la preuve par un défaut visible, par exemple un champ resté en clair ou un bourrage nul.

## 3. Vecteurs de test complétés

Un neuvième vecteur, `janus-rs/vecteurs/visages-cles.janus`, couvre les deux cas qui manquaient :
- un **visage caché ouvert par une clé** (et non par un mot de passe), derrière un leurre lui-même à clés (deux destinataires), avec un second visage caché à mot de passe ;
- l'erreur **« plusieurs visages »** : les identités du leurre et du visage caché, données ensemble, doivent la provoquer.

Le manifeste décrit ces cas par deux nouveaux champs, `identite` dans un visage caché et `plusieurs_visages` ([spec, § 10](../spec/janus-v1.md)). Les cinq implémentations les vérifient, et les clients échouent désormais sur tout champ inconnu du manifeste, au lieu de l'ignorer.
