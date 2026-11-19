# Janus : cartographie avant la spécification

> **But.** Avant d'écrire la moindre ligne de spécification, décider :
> - ce qu'on garde tel quel ;
> - ce qu'on doit construire nous-mêmes ;
> - ce qu'on est libre de choisir ;
> - où ça casse chez les autres, et où ça pourrait casser chez nous ;
> - où l'on peut réellement apporter du neuf.
>
> Les termes techniques renvoient aux chapitres du cours (`node cours/serve.mjs`, puis http://localhost:8642).

---

## 0. La règle d'or

**On n'invente pas de primitive. On invente une composition, un format et des propriétés.**

L'histoire est sans appel :
- presque tous les algorithmes de chiffrement « maison » ont été cassés ;
- presque toutes les grandes failles des vingt dernières années (EFAIL, ZIP, nonces réutilisés dans TLS, *invisible salamanders*) se trouvent dans la **colle** entre des primitives solides, pas dans les primitives elles-mêmes.

C'est donc à la fois l'endroit où l'on peut innover et celui où il faut être le plus rigoureux.

> Image : les primitives sont des briques certifiées, Janus est l'architecture. On ne cuit pas nos propres briques. On peut dessiner un bâtiment inédit, à condition de faire les calculs de structure, c'est-à-dire les preuves.

---

## 1. Contre qui ? (mini modèle de menace)

Sans adversaire défini, le mot « faille » n'a pas de sens. Voici ceux qu'on considère.

| # | Adversaire | Ce qu'il peut faire | Janus v0 |
|---|---|---|---|
| A1 | **Voleur passif** | Copier le fichier (cloud, clé USB, sauvegarde) | Protégé |
| A2 | **Stockage malveillant** | Modifier, tronquer, réordonner des blocs, mélanger deux fichiers | Détecté. Seule exception : remplacer *tout* le fichier par une ancienne version valide, ce qu'aucun format ne peut voir sans mémoire extérieure |
| A3 | **Collecteur quantique** | Stocker aujourd'hui, déchiffrer dans 15 ans (ch. 7) | Protégé (hybride) |
| A4 | **Destinataire malhonnête** | Il lit le fichier, c'est normal. Il ne doit pas pouvoir faire croire aux autres que tu as écrit autre chose | Partiel, voir piste E |
| A5 | **Observateur de métadonnées** (FAI, douane, scanner de disque) | Voir qu'un fichier est chiffré, avec quel outil, sa taille, le nombre de destinataires (ch. 9) | C'est la piste A |
| A6 | **Coercition** | Te forcer à donner le mot de passe | Partiel, piste B |
| A7 | **Voisin de processeur** | Mesurer des temps ou des caches sur la même machine (ch. 11) | Bibliothèques en temps constant |
| A8 | **Chaîne d'approvisionnement** | Piéger une dépendance | Hygiène : peu de dépendances, versions verrouillées |

**Hors de portée de tout format** (on le documente au lieu de le promettre) :
- une machine compromise au moment où tu tapes le mot de passe ou lis le clair ;
- un mot de passe « 123456 » ;
- la perte de toutes tes clés.

---

## 2. Ce qu'on ne touchera pas, et pourquoi

### 2.1 Les primitives

| Rôle | Choix | Pourquoi on n'y touche pas |
|---|---|---|
| Chiffrement symétrique | ChaCha20 (AES-256 en option) | 15 ans et plus de cryptanalyse publique. Changer quoi que ce soit, même le nombre de tours, ne fait rien gagner et peut tout faire perdre |
| Authentification | Poly1305, HMAC-SHA-256 | Idem |
| Hachage | SHA-256, SHA-3 | Idem |
| Échange classique | X25519 (RFC 7748) | Conçu pour limiter les pièges d'implémentation |
| Post-quantique | ML-KEM-768 (FIPS 203), ML-DSA-65 (FIPS 204) si on signe | Standardisés, très étudiés |
| Mots de passe | Argon2id (RFC 9106) | Gagnant d'une compétition ouverte, coûteux en mémoire |
| Dérivation | HKDF-SHA-256 (RFC 5869) | Simple et prouvé |
| Aléa | Celui du système (`getrandom`) | Debian 2008 : un patch « inoffensif » a réduit l'aléa d'OpenSSL à environ 32 000 clés possibles |

### 2.2 Leurs implémentations

Notre `crypto.js` du cours est **juste mais pas en temps constant**. En production, on n'écrit pas nos primitives, parce que même le code des experts fuit :
- **KyberSlash (2024)** : une division dont la durée dépend du secret, présente jusque dans l'implémentation de référence de Kyber ;
- **Clangover (2024)** : un code source correct, dans lequel le compilateur a lui-même introduit un branchement secret.

On utilise donc des bibliothèques auditées et, quand elles existent, vérifiées formellement (libcrux pour ML-KEM, RustCrypto). Notre travail consiste à les **choisir**, à **verrouiller leurs versions** et à les **tester** contre les vecteurs officiels.

### 2.3 Les combineurs qui ont déjà une spécification

Pour mélanger X25519 et ML-KEM, on prend **X-Wing** (draft CFRG, avec preuve), pas notre propre mélange. Les KEM ont des propriétés de « liaison » subtiles (Cremers *et al.*, 2024) qu'un combineur naïf peut perdre.

---

## 3. Ce qu'on doit toucher (personne ne le fera à notre place)

Ce ne sont pas des options mais des responsabilités. Chacune deviendra une exigence numérotée `J-xx` de la spec.

| Id | Exigence | Pourquoi |
|---|---|---|
| J-01 | **Format binaire strict et canonique.** Une grammaire, un seul encodage valide par fichier, des longueurs bornées, et un refus de tout le reste | Si deux programmes lisent le même fichier différemment, l'un d'eux sera trompé |
| J-02 | **Tout l'en-tête est authentifié** | Labo 6.1, bouton « Altérer » |
| J-03 | **Séparation des domaines.** Chaque clé dérivée a une étiquette unique contenant la version (`janus/v0/…`). Jamais une même clé pour deux usages | Labo 4.2 |
| J-04 | **Nonces construits, pas tirés au hasard.** Une clé de fichier neuve par fichier, puis un compteur et un drapeau « dernier » | Labos 2.2 et 8.1. Avec une clé neuve par fichier, le compteur suffit (c'est ce que fait age) |
| J-05 | **Engagement de clé explicite.** Une valeur d'engagement dérivée de la clé de fichier, vérifiée avant tout déchiffrement (ou la transformation CTX) | GCM, ChaCha20-Poly1305 et AEGIS ne le garantissent pas (ch. 9) |
| J-06 | **Jamais de clair non vérifié.** Aucun bloc n'est rendu avant que son tag soit validé. Un dernier bloc manquant est une erreur, pas un « fichier un peu plus court » | EFAIL, et labo 8.1 sur la troncature |
| J-07 | **Une seule erreur**, « impossible de déchiffrer », sans dire pourquoi, et autant que possible en temps uniforme | Labo 11.1. Un message qui en dit trop est un oracle |
| J-08 | **Paramètres bornés** : mémoire Argon2id, nombre de destinataires, taille d'en-tête | Un fichier piégé qui exige 64 Gio de mémoire est un déni de service. Un mot de passe avec 1 itération est une passoire |
| J-09 | **Aucune agilité d'algorithme.** `v0` correspond à une suite fixe, sans champ « algorithme ». Une nouvelle suite fait une nouvelle version | JWT `alg: none`, attaques par rétrogradation |
| J-10 | **Hygiène mémoire.** Effacer clés et mots de passe après usage, et ne jamais mettre un secret dans un journal ou un message | Vidages mémoire, fichiers d'échange, rapports de plantage |
| J-11 | **Spécification écrite et vecteurs de test** | Tout ce qui n'est pas écrit sera implémenté de deux façons différentes |

---

## 4. Ce qu'on peut toucher (nos libertés de conception)

| Choix | Options | Penchant actuel | Enjeu |
|---|---|---|---|
| AEAD du contenu | ChaCha20-Poly1305, XChaCha20-Poly1305, AES-256-GCM(-SIV), AEGIS-256 | ChaCha20-Poly1305 avec nonce compteur. XChaCha si l'on fait de l'édition (piste F), parce qu'il faut alors des nonces aléatoires | Maturité contre vitesse (AEGIS est plus rapide mais encore en draft) |
| Taille des blocs | 16 Kio à 1 Mio | 64 Kio, comme age | Surcoût (16 octets de tag par bloc) contre mémoire et finesse de l'accès aléatoire |
| Bourrage | Aucun, PADMÉ, tailles fixes | PADMÉ par défaut (au plus 12 % de surcoût, labo 9.2) | Discrétion contre place |
| Compression | Non, ou avant chiffrement | **Non par défaut** | Compresser avant de chiffrer fait fuir le contenu par la taille (CRIME 2012, BREACH 2013) |
| Encodage | Binaire, texte (armure) | Binaire, plus une option texte | Pratique contre discrétion |
| Types de destinataire | Clé publique, mot de passe, part de seuil, clé matérielle | Les deux premiers en v0 | Complexité |
| Signature | Aucune, ou hybride Ed25519 + ML-DSA | Optionnelle | Entre en conflit avec le déni (voir § 6) |
| Paramètres Argon2id | Mémoire, passes | À calibrer (environ 0,5 à 1 s sur une machine moyenne) | Sécurité contre confort |
| Langage | Rust, Go, C | **Rust** | Sûreté mémoire et bonnes bibliothèques |

---

## 5. Failles connues chez les autres, et leçon pour Janus

| Faille | Où | Ce qui s'est passé | Leçon pour Janus |
|---|---|---|---|
| Nonce GCM réutilisé, *forbidden attack* (Böck *et al.*, 2016) | Serveurs TLS | Un nonce utilisé deux fois livre la clé d'authentification, et donc la falsification | J-04 |
| **EFAIL** (2018) | Courriels PGP et S/MIME | Chiffré malléable, clair rendu avant vérification, puis exfiltration par HTML | J-06 |
| Collisions SHA-1 (*SHA-1 is a Shambles*, 2020) | Signatures de clés PGP | Collision à préfixe choisi pour environ 45 000 $ | J-09, aucun algorithme faible conservé « pour compatibilité » |
| ZipCrypto (Biham et Kocher, 1994) | ZIP « avec mot de passe » | 12 octets de clair connus suffisent pour tout casser (outil bkcrack) | Aucun vieil algorithme |
| WinZip AES (Kohno, 2004) | ZIP chiffré | Failles de composition, noms de fichiers en clair | J-02, métadonnées chiffrées |
| **Invisible salamanders** (2018) | Pièces jointes de Messenger | Un même chiffré donne deux images selon la clé, ce qui contourne le signalement d'abus | J-05 |
| Oracles de partitionnement (2021) | Shadowsocks | Des milliers de mots de passe testés par requête, faute d'engagement | J-05 |
| Fuite des coffres LastPass (2022) | Gestionnaire de mots de passe | Coffres volés, URL en clair, très peu d'itérations sur d'anciens comptes | J-08, et tout chiffrer, métadonnées comprises |
| JWT `alg: none` (2015) | Jetons web | L'attaquant choisit l'algorithme, y compris « aucun » | J-09 |
| KyberSlash et Clangover (2024) | Implémentations de ML-KEM | Fuites temporelles | § 2.2 et tests de temps constant (dudect) |
| **Transfert subreptice** (Davis, 2001) | Signer puis chiffrer, dans PGP et S/MIME | Bob rechiffre pour Charlie le « je t'aime » signé d'Alice, et Charlie croit qu'Alice lui écrit | Si l'on signe (piste E), on signe aussi l'identité des destinataires |
| OpenSSL Debian (2008) | Génération de clés | Aléa réduit à environ 32 000 possibilités | § 2.1 |
| Porte dérobée xz-utils (2024) | Dépendance de compression | Un mainteneur infiltré pendant deux ans | A8 |
| Métadonnées d'age | age | Le texte `age-encryption.org/v1`, le type et le nombre de destinataires, la taille à quelques octets près sont visibles. C'est un choix assumé par age, pas un bug | Notre terrain : piste A |
| Pas d'expéditeur chez age | age | N'importe quel destinataire peut fabriquer un autre fichier valide pour les autres. C'est documenté | Piste E |
| Volumes cachés TrueCrypt (Czeskis *et al.*, 2008) | Chiffrement de disque | Raccourcis, fichiers récents et indexation trahissent le volume caché | Piste B : le format ne suffit jamais seul |

---

## 6. Là où des failles sont possibles chez nous

### 6.1 Risques généraux

- **Parseur** : débordements, ou deux encodages acceptés. Parade : Rust, fuzzing (cargo-fuzz), grammaire canonique.
- **Deux implémentations qui divergent** (Rust et JS, par exemple). Parade : vecteurs de test communs et un corpus partagé de fichiers piégés.
- **Sortie en flux** : l'application appelante écrit des blocs déjà vérifiés, puis le fichier s'arrête avant la fin. Il faut une API difficile à mal utiliser : écrire dans un fichier temporaire, et ne le renommer que si tout est valide.
- **Destinataires interchangés** : une stanza recollée sous un autre destinataire. Parade : lier les clés publiques dans la dérivation, comme le fait le labo 6.1 avec `hkdf(ephPub‖rcptPub, …)`.
- **Retour à une version antérieure du fichier entier** : indétectable par le format seul. On le documente.

### 6.2 Risques propres à chaque piste

**A. Fichier indistinguable de l'aléatoire**
- Sans *magic bytes*, comment savoir qu'un fichier est un fichier Janus, et en quelle version ? Il faut tenter le déchiffrement, ce qui coûte (Argon2 pour chaque fichier essayé) et peut produire de faux positifs.
- ML-KEM ne ressemble pas à de l'aléa. L'encodage Kemeleon corrige ce défaut, mais coûte de la place.
- L'extension `.janus`, une taille trop régulière ou un premier octet biaisé trahissent tout autant que l'en-tête.
- **L'indistinguabilité est une propriété globale : un seul détail suffit à la casser.**

**B. Deux visages (déni plausible)**
- Si seuls *certains* fichiers ont un second visage, sa présence se voit. *Tous* les fichiers Janus doivent donc avoir la même structure, la seconde zone étant remplie d'aléa quand elle ne sert pas.
- La taille du visage leurre doit rester plausible par rapport à la taille totale.
- Le système d'exploitation et les applications laissent des traces (Czeskis, 2008).
- L'adversaire connaît Janus et sait qu'un second visage *peut* exister. La protection consiste à ce qu'il ne puisse pas le **prouver**, pas à ce qu'il ne le soupçonne pas. Il ne faut jamais promettre davantage.
- Il n'y a pas de conflit avec l'engagement de clé si chaque visage est un chiffré distinct, engagé séparément. On n'exploite **pas** l'absence d'engagement : ce serait fragile, et cela casserait J-05.
- *Conception détaillée : [03-deux-visages.md](03-deux-visages.md).*

**D. Seuils et politiques d'accès**
- Shamir ne détecte pas une part fausse : le secret reconstruit est faux, sans aucun signal (labo 10.1). Il faut un contrôle des parts (valeur d'engagement authentifiée) ou un partage vérifiable (VSS).
- Les implémentations de seuil ont un lourd passif (TSSHOCK, 2023, sur l'ECDSA à seuil).
- Ne jamais distribuer la part d'abscisse x = 0 : c'est le secret lui-même.

**E. Expéditeur authentifié**
- Le transfert subreptice : il faut signer l'identité des destinataires.
- Une signature hybride exige de vérifier les **deux** signatures, et non l'une *ou* l'autre.
- La signature doit se trouver *dans* le chiffré, sinon elle révèle l'expéditeur à tout le monde.
- **Conflit avec B** : une signature est une preuve, le contraire d'un déni. L'alternative est l'authentification *déniable* (mode Auth de HPKE, ch. 10), mais sa version post-quantique est moins mûre.

**F. Édition et accès aléatoire**
- Réécrire un bloc avec le même nonce, c'est le labo 2.2 en vrai.
- On peut remettre une ancienne version d'*un seul* bloc. Parade : un arbre de Merkle dont la racine est authentifiée.
- Un observateur qui compare deux versions voit quels blocs ont changé.

**Verrou temporel (tlock/drand)**
- Il dépend d'un réseau tiers.
- Il repose sur BLS12-381, qui **n'est pas post-quantique** : un fichier verrouillé « jusqu'en 2040 » pourrait s'ouvrir avant.
- Les puzzles temporels RSW reposent sur un groupe RSA, que Shor casse aussi.
- Problème de recherche ouvert, donc **hors v0**.

**L'humain**
- Une clé perdue, ce sont des données perdues pour de bon (les seuils de la piste D aident).
- Un mot de passe faible reste faible : Argon2 ralentit l'attaquant, il ne le bloque pas.

---

## 7. Que faire des failles ?

1. **Chaque faille connue devient une exigence et un test.**
   - Une ligne `J-xx` dans la spec.
   - Un fichier piégé dans `tests/malicious/`, que Janus doit refuser.
2. **Chaque faille possible devient une propriété à prouver**, par exemple « aucun fichier ne s'ouvre sous deux clés différentes ». Selon le cas, on la vérifie avec :
   - ProVerif ou Tamarin pour le protocole ;
   - des tests statistiques pour l'indistinguabilité (piste A) ;
   - dudect pour le temps constant.
3. **On attaque Janus avant tout le monde.**
   - Ajouter au cours des labos qui attaquent nos propres prototypes.
   - Fuzzing en continu.
   - Revue externe avant la v1.
4. **On transforme ce savoir en outil : `janus inspect`.**
   - Il fait la radiographie de n'importe quel fichier (age, gpg, zip, Janus) et montre ce qui fuit : outil, nombre de destinataires, taille, algorithmes, entropie.
   - Il est purement défensif : il lit ce qui est déjà visible et ne casse rien.
   - Il est pédagogique, et il démontre par contraste l'intérêt de la piste A.
5. **Cadre éthique.**
   - On étudie les failles des autres sur nos propres fichiers et environnements.
   - Si l'on en découvre une nouvelle, on la signale à l'éditeur avant toute publication (divulgation responsable).

---

## 8. Où innover : évaluation honnête

| Piste | Déjà existant | Ce qui serait neuf | Difficulté | Risque | Verdict |
|---|---|---|---|---|---|
| **C.** Hybride et engagement | X-Wing, CTX, HPKE, age | Rien : c'est le socle | Faible | Faible | **v0, obligatoire** |
| **A.** Indistinguable | PURBs (2019), Elligator, Kemeleon (draft) | Un format de fichier post-quantique hybride, multi-destinataires, réellement indistinguable de l'aléa | Élevée | Moyen | **Cœur de l'identité de Janus** |
| **G.** Preuve formelle | TLS 1.3 et Signal (PQXDH) modélisés ; formats de fichier rarement | Spec, modèle ProVerif/Tamarin et vecteurs publiés avec la v0 | Moyenne à élevée | Faible | **Dès la v0, en parallèle** |
| **H.** `janus inspect` | binwalk, ent (génériques) | Un diagnostic « ce qui fuit » orienté cryptographie | Faible | Faible | v0, en bonus |
| **E.** Expéditeur authentifié | PGP (mal lié), HPKE Auth (non post-quantique), Saltpack | Signature hybride post-quantique bien liée, ou authentification déniable post-quantique | Moyenne | Moyen | Option v0 ou v1 |
| **D.** Politiques d'accès | Shamir (ssss), déverrouillage de Vault | Une politique (« Alice OU 2 parmi Bob, Carol, Dave ») dans l'en-tête, post-quantique, sans tiers de confiance | Moyenne | Moyen | v1 |
| **F.** Édition sûre | Cryptomator, gocryptfs (par blocs, en général sans protection contre le retour d'un bloc) | Arbre de Merkle et engagement, sans réutilisation de nonce | Moyenne | Moyen | v1 |
| **B.** Deux visages | VeraCrypt (volumes, pas fichiers) | Déni au niveau du format, avec une structure constante | Élevée | Élevé | v1, phase de recherche |

### Conflits entre pistes

| Conflit | Nature | Résolution envisagée |
|---|---|---|
| A et détection de version | Pas de *magic*, donc pas de version lisible | La version est implicite (essai de déchiffrement) ou cachée dans la dérivation |
| **B et E** | Déni contre preuve | Choisir par fichier, jamais les deux à la fois |
| A et D | Le nombre de parts se voit | Nombre de stanzas fixe, bourré d'aléa |
| A et F | L'accès aléatoire révèle la structure en blocs | La taille des blocs ne fuit pas grand-chose ; à mesurer |

### Proposition pour la v0

- **C** (le socle) ;
- **A** partiel : pas de *magic*, PADMÉ, Elligator pour X25519, Kemeleon à évaluer ;
- **G** (la preuve) ;
- **H** (`inspect`).

On **prévoit l'architecture** pour B, D, E et F (emplacements de structure fixe) sans les implémenter.

---

## 9. Décisions à prendre

1. **Pour qui est Janus ?** Ce choix oriente tout le reste.
   - *Discrétion* (journalistes, sources, voyageurs) : A, puis B.
   - *Partage* (équipe, entreprise) : D, E, F.
   - *Archive* (long terme) : C et G avant tout.
2. **Par défaut, signature ou déni ?** On ne peut pas avoir les deux dans le même fichier.
3. **Rust** pour l'implémentation de référence : d'accord ?

---

## 10. Décisions (18 novembre 2026)

| # | Question | Décision |
|---|---|---|
| D-1 | Pour qui ? | **Pour usage personnel d'abord.** Publication en open source sous licence **MIT** si Janus est performant, innovant et offre des fonctions que les autres n'ont pas |
| D-2 | Signature ou déni par défaut ? | **Ni l'un ni l'autre n'est imposé** (recommandation adoptée provisoirement, voir ci-dessous) |
| D-3 | Langage | **Rust** pour l'implémentation de référence |
| D-4 | Taille de la réserve des deux visages (QB-1) | **`max(64 Kio, L/16)`** : environ 6 % de plus par fichier ([03-deux-visages.md](03-deux-visages.md), § 5) |

### Conséquences de D-1

- **Le critère de réussite devient mesurable.** Pour mériter la publication, Janus doit battre l'existant sur au moins une fonction absente ailleurs, sans perdre sur la sécurité ni, de façon sensible, sur la vitesse.
- **Fonctions différenciantes visées**, de la plus à la moins originale :
  - B, les deux visages, qui donne d'ailleurs son sens au nom : Janus, dieu à deux visages ;
  - A, l'indistinguabilité post-quantique ;
  - D, les politiques d'accès ;
  - `inspect`.
- **Performance.** Les blocs sont indépendants, donc chiffrables en parallèle sur plusieurs cœurs. On mesure contre age et gpg dès le premier prototype, avec un banc d'essai reproductible dans le dépôt.
- **Licence MIT.** On vérifie que chaque dépendance a une licence compatible (MIT, Apache-2.0 ou BSD) avant de l'ajouter.

### Raisonnement derrière D-2

- **Pour un usage personnel, une signature n'apporte presque rien.** Quand tu chiffres pour toi-même, tu es à la fois expéditeur et destinataire. L'intégrité est déjà garantie par l'AEAD et l'engagement de clé.
- **Mode par défaut : « anonyme », comme age.** Aucune signature, ce qui laisse le déni possible.
- **La signature (piste E) est une option**, à activer quand on partage un fichier et qu'on veut prouver qu'on l'a écrit. Elle est incompatible avec un second visage dans le même fichier.
- **Le mode n'est pas visible de l'extérieur.** La signature éventuelle est placée *à l'intérieur* du chiffré, si bien qu'un observateur ne peut pas distinguer un fichier signé d'un fichier non signé (cohérent avec la piste A).
