# Janus v0 : spécification du format

> **Statut : brouillon 0.2 du 18 novembre 2026 (prototype Rust : janus-rs/).** Le format n'est **pas figé**. Il ne le sera qu'une fois réunies trois conditions :
> - les questions ouvertes du § 12 sont tranchées ;
> - une implémentation de référence en Rust existe ;
> - les vecteurs de test sont publiés.
>
> Les fichiers produits avant ce gel pourront devenir illisibles.
>
> Ce document s'appuie sur [la cartographie](01-cartographie.md), et notamment sur ses exigences J-01 à J-11. Les encadrés **« En clair »** expliquent chaque choix sans jargon.

---

## 1. Objectifs et non-objectifs

### Ce que Janus v0 garantit

| Propriété | Signification |
|---|---|
| **P1. Confidentialité hybride** | Le contenu reste secret tant que **X25519 *ou* ML-KEM-768** tient. Pour un mot de passe, tant que celui-ci n'est pas deviné |
| **P2. Intégrité** | Modifier, ajouter, retirer, tronquer ou réordonner un seul octet fait échouer l'ouverture |
| **P3. Engagement de clé** | Un fichier ne s'ouvre que sous une seule clé de fichier |
| **P4. Cohérence entre destinataires** | Tous les destinataires qui ouvrent un fichier obtiennent exactement le même contenu. *En v1 : tous ceux d'un **même visage** ; des visages différents peuvent montrer des contenus différents ([05-preuve-integrite.md](05-preuve-integrite.md), § 7.1)* |
| **P5. Indistinguabilité** | Pour qui n'a pas de clé, chaque octet du fichier est indistinguable de l'aléatoire, et sa taille ne dépend que de la longueur du contenu, arrondie (§ 7) |
| **P6. Destinataires cachés** | Le nombre et l'identité des destinataires ne se voient pas, ni dans les octets, ni dans la taille |

### Ce qu'il ne garantit pas (et qu'on ne prétend pas garantir)

- **L'authentification de l'expéditeur.** Un destinataire peut fabriquer un autre fichier que les autres destinataires ouvriront. C'est la piste E, prévue en v1.
- **La confidentialité persistante.** Si ta clé privée fuit, tous les fichiers qui t'étaient destinés sont lisibles. C'est inhérent à un fichier statique.
- **La détection d'un retour en arrière complet**, c'est-à-dire le remplacement du fichier entier par une ancienne version valide.
- **Le masquage de la longueur approximative du contenu** : environ 12 % de flou (§ 7).
- **L'IND-CCA au sens strict** : en v1, une copie modifiée hors du visage ouvert donne le même clair. La garantie prouvée est IND-RCCA ([06-preuve-confidentialite-active.md](06-preuve-confidentialite-active.md)).
- **Le déni plausible** : c'est la piste B, prévue en v1. Sa conception est dans [03-deux-visages.md](03-deux-visages.md). Elle modifie la structure (deux étiquettes, sel commun, réserve) et propose que v1 remplace v0.

---

## 2. Notations et constantes

| Notation | Sens |
|---|---|
| `a ‖ b` | Concaténation d'octets |
| `BE88(j)` | Entier `j` sur 11 octets, gros-boutiste |
| `aléa(n)` | `n` octets tirés du générateur du système, et seulement de lui |
| `HKDF(ikm, info)` | HKDF-SHA-256 (RFC 5869) avec un sel **vide** et une sortie de 32 octets |
| `HMAC(k, m)` | HMAC-SHA-256 |
| `AEAD(k, nonce, clair)` | ChaCha20-Poly1305 (RFC 8439) sans données associées. Renvoie le chiffré suivi du tag de 16 octets |

| Constante | Valeur | Rôle |
|---|---|---|
| `N_EMPL` | 16 | Nombre d'emplacements de destinataire, toujours présents |
| `S` | 1616 | Taille d'un emplacement, en octets |
| `H` | 32 + 16 × 1616 = **25 888** | Taille de l'en-tête |
| `TB` | 65 536 | Taille d'un bloc de clair (64 Kio) |
| `TC` | 65 552 | Taille d'un bloc chiffré (`TB` + 16) |

Les étiquettes de dérivation sont en ASCII, sans accents :

| Étiquette | Usage |
|---|---|
| `janus/v0/entete` | Clé du MAC d'en-tête |
| `janus/v0/corps` | Clé de chiffrement du contenu |
| `janus/v0/emballage/xwing` ‖ `i` | Clé d'emballage de l'emplacement `i` (un octet), pour un destinataire à clé publique |
| `janus/v0/emballage/mdp` | Clé d'emballage pour un mot de passe |

> **En clair.** Le `v0` présent dans chaque étiquette **est** le numéro de version : il n'existe aucun champ « version » lisible (J-09, piste A). Un futur Janus v1 utilisera `janus/v1/…`. Un lecteur v0 qui reçoit un fichier v1 échouera simplement, comme pour un fichier qui ne lui est pas destiné.

---

## 3. Clés

### 3.1 Destinataire à clé publique

- **Algorithme** : X-Wing (`draft-connolly-cfrg-xwing-kem-11`), c'est-à-dire ML-KEM-768 combiné à X25519.
- **Identité (clé secrète)** : une graine de 32 octets, `aléa(32)`. Toute la paire de clés en est déduite, comme le prévoit X-Wing.
- **Clé publique** : 1216 octets, soit `pk_M` (1184) suivi de `pk_X` (32).
- **Encodage texte** : provisoire, voir Q7.

### 3.2 Mot de passe

| Paramètre | Valeur |
|---|---|
| Algorithme | Argon2id, version `0x13` |
| Mémoire `m` | 65 536 Kio (64 Mio) |
| Passes `t` | 3 |
| Parallélisme `p` | 4 |
| Sortie | 32 octets |
| Sel | Le `sel` de 32 octets stocké dans l'emplacement |

C'est la seconde configuration recommandée par la RFC 9106 (§ 4). Ces paramètres sont **fixes**, ils ne figurent pas dans le fichier. Il n'y a donc ni agilité ni possibilité d'imposer des paramètres extravagants (J-08, J-09). Une évolution passera par une nouvelle version.

---

## 4. Structure du fichier

```
 décalage   taille            contenu
 ────────   ───────────────   ──────────────────────────────────────────────
 0          32                T       étiquette d'en-tête (HMAC-SHA-256)
 32         16 × 1616         E_0 … E_15   emplacements de destinataire
 25 888     F − 25 888        corps   blocs chiffrés
```

Le fichier ne contient **aucun champ en clair** : pas de nombre magique, pas de version, pas de longueur, pas de liste d'algorithmes.

### 4.1 Emplacement pour clé publique (1616 octets)

```
 0      32     r    représentant Elligator 2 de l'éphémère X25519 (ct_X)
 32     1536   κ    Kemeleon(ct_M), chiffré ML-KEM-768 encodé
 1568   48     w    AEAD(clé_emb_i, 0¹², K)
```

### 4.2 Emplacement pour mot de passe (1616 octets, toujours `E_0`)

```
 0      32     sel  aléa(32)
 32     1536   ——   aléa(1536)
 1568   48     w    AEAD(clé_emb_mdp, 0¹², K)
```

### 4.3 Emplacement inutilisé

`aléa(1616)`.

> **En clair.** Il y a **toujours 16 emplacements**, qu'il y ait 1 ou 16 destinataires. Ceux qui ne servent pas sont remplis d'aléa. Un observateur ne peut donc pas les compter. L'en-tête mesure toujours 25 888 octets : c'est le prix de la discrétion et du post-quantique (§ 10).

### 4.4 Règles de remplissage

- **R1.** Si un mot de passe est utilisé, il occupe `E_0` et c'est le **seul** destinataire. Les autres emplacements sont aléatoires.
  - *Pourquoi :* avec un mot de passe seul, réussir l'ouverture prouve que l'auteur connaissait le mot de passe. Si l'on mélangeait mot de passe et clés publiques, un destinataire à clé publique, qui connaît `K`, pourrait recopier `E_0` dans un faux fichier. age applique la même règle.
- **R2.** Les destinataires à clé publique occupent des emplacements tirés **au hasard** parmi les 16, sans doublon. Les autres emplacements sont aléatoires.
- **R3.** Pas plus de 16 destinataires.

---

## 5. Dérivations

```
K           = aléa(32)                    clé de fichier, neuve pour chaque fichier
K_entete    = HKDF(K, "janus/v0/entete")
K_corps     = HKDF(K, "janus/v0/corps")

clé_emb_i   = HKDF(ss_i,  "janus/v0/emballage/xwing" ‖ octet(i))
clé_emb_mdp = HKDF(Argon2id(mdp, sel), "janus/v0/emballage/mdp")
```

Le secret partagé `ss_i` est celui produit par X-Wing pour l'emplacement `i` (§ 6).

> **En clair.** On a une seule clé secrète `K` par fichier. Chaque usage reçoit sa propre sous-clé, avec une étiquette différente (labo 4.2). La clé d'emballage est neuve pour chaque emplacement, puisque `ss_i` et `sel` sont neufs à chaque fois. Le nonce nul ne pose donc aucun problème de réutilisation.

---

## 6. Encapsulation X-Wing rendue indistinguable

X-Wing produit un chiffré `ct = ct_M ‖ ct_X`. Aucune des deux parties ne ressemble à de l'aléa : `ct_M` a une structure due à la compression des coefficients, et `ct_X` est un point de courbe. On les **encode** donc, sans rien changer à la cryptographie d'X-Wing.

### 6.1 Côté chiffrement, pour un destinataire `pk = pk_M ‖ pk_X` placé dans l'emplacement `i`

1. **ML-KEM.** Calculer `(ss_M, ct_M) = ML-KEM-768.Encaps(pk_M)`.
2. **Éphémère X25519 « caché ».** Répéter :
   - tirer le scalaire `e` **uniformément modulo ℓ** (64 octets d'aléa réduits modulo ℓ). Il ne faut **pas** le clamper : un scalaire clampé ne couvre que la moitié du sous-groupe premier, ce qu'un ordinateur quantique sait tester ([04-preuve-deux-visages.md](04-preuve-deux-visages.md), § 7.1) ;
   - calculer `P = e·B + L`, où `L` est un point d'ordre faible tiré au hasard. On obtient ainsi un point dit « sale », **uniforme sur toute la courbe** ;
   - recommencer tant que `P` n'a pas de représentant Elligator 2 (cela arrive environ une fois sur deux).

   Ensuite :
   - `r` = un représentant de `P` choisi au hasard, dont les 2 bits de poids fort sont aléatoires ;
   - `ct_X` = la coordonnée `u` de `P` ;
   - `ss_X = e·pk_X`. Le destinataire, lui, calcule le X25519 standard `X25519(sk_X, ct_X)` et obtient la même valeur, car son scalaire clampé est multiple de 8 et annule `L`.
3. **Combineur X-Wing.** `ss_i = SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ XWingLabel)`, exactement selon draft-11 (étiquette en dernier, confirmé par le vecteur de test officiel).
4. **Encodage Kemeleon.** `κ = Kemeleon.EncodeCtxt(ct_M)` (`draft-irtf-cfrg-kemeleon-02`, variante par défaut : 1536 octets, sans échec). Chaque vecteur de 3072 bits est écrit en octets gros-boutistes (Q10). L’aléa de l’encodage doit rester secret.
5. **Masquage (v1).** `κ' = κ ⊕ SHAKE256("janus/v1/masque" ‖ ss_X ‖ ct_X, 1536 octets)`. Ainsi `κ'` est indistinguable de l'aléa si MLWE tient **ou** si X25519 tient : la discrétion devient hybride, comme la confidentialité ([04-preuve-deux-visages.md](04-preuve-deux-visages.md), § 7.2).
6. **Assemblage.** `E_i = r ‖ κ' ‖ AEAD(clé_emb_i, 0¹², …)`.

### 6.2 Côté déchiffrement

1. `ct_X = Elligator2.carte(r)`, en ignorant les 2 bits de poids fort (RFC 9380, § 6.7.1, Z = 2).
2. `ss_X = X25519(sk_X, ct_X)`, puis `κ = κ' ⊕ SHAKE256("janus/v1/masque" ‖ ss_X ‖ ct_X, 1536)` (v1).
3. `ct_M = Kemeleon.DecodeCtxt(κ)`. Ce décodage ne peut pas échouer : toute chaîne de 1536 octets se décode.
4. `ss_i = X-Wing.Decaps(sk, ct_M ‖ ct_X)`, avec la fonction **standard** (en réutilisant `ss_X`).

> **Pourquoi c'est sûr (à prouver formellement, voir Q2).**
> - Côté destinataire, X25519 multiplie le point par un scalaire multiple de 8. La composante d'ordre faible `L` disparaît : `ss_X` est inchangé.
> - Le combineur hache `ct_X` *tel que transmis* des deux côtés, donc les deux parties obtiennent le même `ss_i`.
> - Un attaquant peut calculer lui-même `L` à partir de `ct_X`, donc l'ajouter ne lui apprend rien.
> - Janus réimplémente uniquement la ligne du combineur, côté chiffrement. On la vérifie contre les vecteurs de test officiels du draft (cas sans `L`).

---

## 7. Taille du fichier et bourrage

Le contenu bourré est `C = M ‖ 0x80 ‖ 0x00^z`. Sa longueur `P` est choisie ainsi :

```
Lmin  = |M| + 1
Bmin  = Lmin + 16 × ⌈Lmin / TB⌉            corps minimal
Ref   = H + Bmin                           taille de référence
Fmax  = PADMÉ(Ref)                         labo 9.2

répéter
    F     = entier uniforme dans [Ref, Fmax]
    B     = F − H
    c     = ⌈B / TC⌉
    reste = B − (c − 1) × TC
jusqu'à reste ≥ 17                         le dernier bloc contient au moins 1 octet de clair

P = B − 16 × c                              P ≥ Lmin, garanti
```

La boucle se termine toujours, car `F = Ref` est toujours valide.

> **En clair.** On ne prend pas `F = PADMÉ(Ref)` tel quel, parce que les tailles PADMÉ se terminent par beaucoup de bits à zéro. Un fichier d'environ 1 Mo dont les 15 bits de poids faible sont nuls, cela n'arrive qu'une fois sur 32 768 par hasard : ce serait une **signature**. Tirer la taille au hasard dans l'intervalle de PADMÉ supprime ce motif, avec une fuite du même ordre que PADMÉ (voir Q4). Cette variante est **propre à Janus** et doit être analysée.

**Ce que la taille révèle à un tiers.** Toute la fuite tient en une plage : les longueurs de clair `L` compatibles avec une taille `F` sont celles qui vérifient `Ref(L) ≤ F ≤ PADMÉ(Ref(L))`. `janus inspect` calcule cette plage (deux recherches dichotomiques, car `Ref` et `PADMÉ∘Ref` sont croissantes). Pour un fichier de 512 Mio, elle s'étend sur environ 0,8 %.

Il existe une seconde fuite, minime : les tailles dont le reste vaut entre 1 et 16 ne sont jamais produites. Elles représentent 16 tailles sur 65 552, soit 0,024 %. Une telle taille prouve seulement que le fichier **n'est pas** un fichier Janus. À l'inverse, une taille valide ne prouve rien, puisque 99,98 % des tailles le sont.

---

## 8. Corps

```
C = C_0 ‖ C_1 ‖ … ‖ C_{c-1}     blocs de TB octets, le dernier faisant entre 1 et TB octets
corps_j = AEAD(K_corps, BE88(j) ‖ d_j, C_j)
d_j     = 0x01 si j = c − 1, sinon 0x00
```

Cette construction est STREAM (labo 8.1). Le nonce est un simple compteur, ce qui est sûr parce que `K` est neuve pour chaque fichier. Les blocs sont indépendants et peuvent donc être chiffrés et déchiffrés **en parallèle**.

---

## 9. Algorithmes

### 9.1 Chiffrer `M` pour une liste de destinataires (ou un mot de passe)

1. `K = aléa(32)`, puis dériver `K_entete` et `K_corps`.
2. Construire les 16 emplacements selon les règles R1 à R3 (§ 4.4) et le § 6.
3. Calculer `T = HMAC(K_entete, E_0 ‖ … ‖ E_15)`.
4. Calculer `F` et `P` (§ 7), puis former `C = M ‖ 0x80 ‖ 0x00^(P − |M| − 1)`.
5. Écrire `T ‖ E_0 ‖ … ‖ E_15 ‖ corps`.
6. Effacer de la mémoire `K`, les sous-clés, les secrets partagés et le mot de passe.

### 9.2 Ouvrir un fichier de taille `F`

**Toute** erreur, à n'importe quelle étape, produit le même message, « impossible de déchiffrer » (J-07), et efface le fichier temporaire.

1. Si `F < H + 17`, échec.
2. **Retrouver la clé de fichier `K`.**
   - *Avec un mot de passe* : un seul calcul Argon2id, sur `E_0` uniquement.
   - *Avec une ou plusieurs identités* : pour chaque emplacement `i` de 0 à 15 et chaque identité, essayer le § 6.2 puis ouvrir `w`. On s'arrête au premier succès.
3. Si aucune tentative n'a réussi, échec.
4. **Vérifier l'en-tête.** Calculer `T' = HMAC(K_entete, octets[32 … H))`. Si `T' ≠ T` (comparaison en temps constant), échec.
5. **Déchiffrer le corps.**
   - Calculer `B = F − H`, `c` et `reste` comme au § 7. Si `reste < 17`, échec.
   - Déchiffrer chaque bloc avec son nonce. Le bloc `c − 1`, et lui seul, porte le drapeau « dernier ».
   - Écrire le résultat dans un **fichier temporaire**.
6. **Retirer le bourrage.** Le clair doit se terminer par `0x80` suivi uniquement de `0x00`. Sinon, échec. Tronquer le fichier temporaire juste avant ce `0x80`.
7. Renommer le fichier temporaire vers sa destination (J-06), puis effacer les secrets (J-10).

> **En clair, l'étape 4 est la clé de voûte.**
> - `T` est placé à une **position fixe** (octet 0) et couvre **tout** l'en-tête.
> - Si deux destinataires obtenaient deux clés différentes `K₁` et `K₂`, il faudrait que `HMAC(K₁,…) = HMAC(K₂,…)`, c'est-à-dire trouver une collision SHA-256.
> - Cela donne à la fois l'**engagement de clé** (P3) et la **cohérence entre destinataires** (P4).
> - Comme `K_corps` découle de `K`, le contenu est lui aussi entièrement déterminé.

---

## 10. Coût

| Élément | Surcoût |
|---|---|
| En-tête | 25 888 octets, fixe |
| Tags | 16 octets par bloc de 64 Kio (0,02 %) |
| Bourrage | Au plus environ 12 % pour les petits contenus, moins de 4 % au-delà de 4 Mio (mesuré sur 20 000 tailles) |

| Exemple | Fichier Janus |
|---|---|
| Note de 1 Kio | 26 929 à 27 648 octets (environ 27 Kio) |
| Photo de 5 Mio | 5 270 065 à 5 373 952 octets (environ 5,03 à 5,13 Mio) |

| Opération | Coût |
|---|---|
| Ouverture par mot de passe | Un calcul Argon2id (environ 0,1 à 0,3 s selon la machine), quel que soit le fichier |
| Ouverture par clé | Au plus 16 décodages Kemeleon et 16 décapsulations, soit quelques millisecondes |

> L'en-tête de 26 Kio est le prix de P5 et P6. C'est assumé pour un usage personnel. Voir Q5 si l'on veut le réduire.

---

## 11. Correspondance avec les exigences de la cartographie

| Exigence | Comment v0 la satisfait |
|---|---|
| J-01 Format canonique | Positions et tailles fixes. Les encodages non uniques (Kemeleon, bits hauts d'Elligator, octets aléatoires) sont tous couverts par `T` : en modifier un seul fait échouer l'ouverture. Le bourrage est vérifié octet par octet |
| J-02 En-tête authentifié | `T` couvre les 16 emplacements |
| J-03 Séparation des domaines | Étiquettes du § 2, une par usage, avec l'indice d'emplacement |
| J-04 Nonces | `K` neuve pour chaque fichier, nonce compteur et drapeau « dernier » ; clés d'emballage à usage unique |
| J-05 Engagement | `T` (§ 9.2, étape 4) |
| J-06 Pas de clair non vérifié | Fichier temporaire, renommé seulement si tout est valide |
| J-07 Une seule erreur | § 9.2 |
| J-08 Paramètres bornés | Argon2id fixe ; 16 emplacements ; blocs de 64 Kio |
| J-09 Aucune agilité | Aucun champ d'algorithme ; la version est dans les étiquettes |
| J-10 Hygiène mémoire | § 9.1, étape 6, et § 9.2, étape 7 |
| J-11 Vecteurs de test | 6 vecteurs publiés dans `janus-rs/vecteurs/` (fichiers `.janus` et `manifeste.json`) |

---

## 12. Questions ouvertes (à trancher avant le gel)

| # | Question | Piste |
|---|---|---|
| Q1 | ~~Position de l’étiquette dans le combineur X-Wing~~ | **Résolue** : à la fin (draft-11). Le prototype reproduit le vecteur de test n° 1 du draft |
| Q2 | Le point « sale » d'Elligator conserve-t-il la sécurité d'X-Wing ? | **En partie résolue** : oui pour IND-CPA dans le modèle de l'oracle aléatoire ([04-preuve-deux-visages.md](04-preuve-deux-visages.md), étape G₂). IND-CCA reste à prouver. La preuve a aussi montré que l'éphémère doit être tiré **uniformément modulo ℓ**, et non clampé (§ 7.1 du même document). *Corrigé dans le code le 18 novembre 2026.* |
| Q3 | Kemeleon n'est qu'un draft (version 02) : tailles et algorithme peuvent changer | Figer la version citée, prévoir v0 → v0.1 |
| Q4 | Quelle est la fuite exacte du bourrage « PADMÉ aléatoire » ? | Calculer l'information mutuelle par rapport à PADMÉ pur |
| Q5 | 16 emplacements (26 Kio) ou 8 (13 Kio) ? | 16 laisse de la place aux politiques d'accès de la v1 |
| Q6 | Calibrer Argon2id (64 Mio, t = 3) ou passer à la première configuration de la RFC 9106 (2 Gio) ? | Mesurer sur tes machines |
| Q7 | Encodage texte des clés (Bech32m sans limite comme age, ou base64 avec somme de contrôle) ? | Bech32m, pour détecter les fautes de frappe |
| Q8 | Bibliothèques Rust | **En partie résolue** : `ml-kem` 0.3 (RustCrypto, zeroize), `curve25519-elligator2` (variante `Randomized` = point sale), Kemeleon écrit par nous **en temps constant** (dudect : aucune fuite détectée, témoin num-bigint détecté). Reste à évaluer libcrux (vérifié formellement) |
| Q9 | Le temps d'ouverture révèle-t-il l'emplacement trouvé ? | Essayer les 16 emplacements dans tous les cas |
| Q10 | Le draft Kemeleon ne fixe pas l’ordre des octets de VectorEncode | Gros-boutiste dans le prototype (comme la variante à rejet du draft) ; à confirmer avec les auteurs |

---

## 13. Tests exigés

### 13.1 Vecteurs positifs

Pour chacun, l'implémentation de référence publiera les entrées, l'aléa fixé et le fichier attendu, octet par octet :
- un mot de passe ;
- 1 destinataire ;
- 16 destinataires ;
- un contenu vide ;
- un contenu de exactement 64 Kio ;
- un contenu à cheval sur deux blocs.

### 13.2 Corpus de fichiers piégés (`tests/malicious/`)

Chacun doit produire « impossible de déchiffrer ».

| Fichier piégé | Exigence vérifiée |
|---|---|
| Un bit inversé dans `T`, dans chaque emplacement et dans chaque bloc | P2, J-02 |
| Fichier tronqué d'un octet, d'un bloc, ou réduit à l'en-tête seul | P2, J-06 |
| Octets ajoutés à la fin | P2 |
| Deux blocs échangés, un bloc dupliqué | P2 |
| Bourrage invalide (pas de `0x80`, un octet non nul après) | J-01 |
| Deux emplacements emballant deux `K` différentes, avec un `T` valide pour l'une | P3, P4 |
| Emplacement d'un fichier A greffé dans un fichier B | J-02 |
| Fichier aléatoire de taille valide | J-07 |

### 13.3 Tests de propriétés

- **P5** : batterie statistique (NIST STS ou équivalent) sur 10 000 fichiers Janus, comparés à de l’aléa. *Fait partiellement : test du χ² (`tests/format.rs`) ; NIST STS reste à passer.*
- **Temps constant** : dudect sur l’ouverture. *Fait : `examples/dudect.rs`, avec témoin positif.*
- **Fuzzing** : en continu sur le décodeur. *Fait par mutations en Rust stable (`tests/fuzz.rs`, 30 000 mutations) ; cargo-fuzz avec couverture reste à mettre en place.*
- **Vu de l'extérieur** : `janus inspect` ne doit reconnaître aucun format dans un fichier Janus, et la plage de clair qu'il annonce doit contenir la vraie taille. *Fait : `tests/inspect.rs`, sur 6 tailles et jusqu'à 16 destinataires, ainsi que sur des milliers de tailles tirées par `tirer_taille`.*

---

## 14. Ce qui est neuf ici

Pris séparément, chaque élément existe :
- X-Wing ;
- Kemeleon ;
- Elligator ;
- STREAM ;
- PADMÉ ;
- le MAC d'en-tête d'age.

À notre connaissance, aucun format de fichier ne les **assemble** pour obtenir à la fois :
- un chiffrement **post-quantique hybride** et **multi-destinataires** ;
- **sans aucun octet distinguable** de l'aléa ;
- un nombre de destinataires **caché**, y compris dans la taille ;
- l'**engagement de clé** et la **cohérence entre destinataires** garantis par une seule valeur.

PURBs (2019) visait une partie de ces objectifs, avec une cryptographie classique.

Les apports propres à Janus, qui sont donc les plus à risque, sont :
- le **point sale combiné à X-Wing** (Q2) ;
- le **PADMÉ aléatoire** (Q4).
