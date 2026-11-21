# Janus : preuves renforcées

*21 novembre 2026.*

Les documents 04 à 06 prouvent le déni, l'intégrité et la confidentialité active, sur papier et dans le modèle de l'oracle aléatoire classique. Ce document les renforce sur quatre points :

| § | Question | Résultat |
|---|---|---|
| 1 | Q4 : que révèle exactement la taille du fichier ? | **Calculé exactement.** L'ancienne règle de tirage fuyait plus que PADMÉ ; la nouvelle (le « seau ») fuit **exactement** ce que fuit PADMÉ. Changement adopté (seul le chiffrement change) |
| 2 | Q2 : le KEM caché, point sale compris, est-il IND-CCA ? | **Oui**, par deux chemins dont un seul suffit, **vérifiés par machine** (CryptoVerif). La vérification a fait apparaître une hypothèse oubliée, C2PRI d'ML-KEM |
| 3 | Face à un ordinateur quantique (modèle QROM) ? | Pour les visages à **clé**, aucune étape n'a plus besoin de l'oracle aléatoire : les preuves valent dans le modèle standard, donc face à un adversaire quantique. Pour les **mots de passe**, Argon2id perd la moitié de l'entropie face à un adversaire quantique |
| 4 | Vérification par machine | Le cœur nouveau de Janus, le KEM caché, est vérifié par CryptoVerif dans ses deux chemins (`preuves/cryptoverif/`) |

Comme les précédentes, ces preuves n'ont été relues par personne.

---

## 1. Q4 : la fuite exacte de la taille

### 1.1 La question

Un observateur voit la taille `F` du fichier. Elle dépend de la longueur `L` du leurre, et de rien d'autre (spec, § 6.2). Que lui apprend-elle sur `L` ? On mesure deux quantités, pour `L` uniforme sur un intervalle :
- **l'information mutuelle** `I(L ; F)`, en bits : ce que `F` apprend **en moyenne** ;
- **la fuite maximale** (Issa, Wagner, Kamath, 2016) : `log2 Σ_F max_L P(F | L)`, en bits. Elle borne ce que gagne un adversaire qui cherche à deviner **n'importe quelle** fonction de `L`, et elle ne dépend pas de la loi de `L`. C'est la mesure prudente.

Le calcul est **exact**, sans échantillonnage (`janus-rs/examples/fuite_bourrage.rs`). Les bornes du tirage croissent avec `L`, donc les `L` compatibles avec un `F` donné forment un intervalle qui avance avec `F`. Un seul balayage suffit, même pour 2³⁰ valeurs de `L`.

### 1.2 Résultat : l'ancienne règle fuyait plus que PADMÉ

Jusqu'ici, Janus tirait `F` uniformément dans `[Ref, PADMÉ(Ref)]`, où `Ref = H + c(L) + Réserve(L)`. L'idée était d'effacer la signature de PADMÉ, dont les tailles finissent par beaucoup de bits nuls. Mais cela ajoute une fuite : `F ≥ Ref(L)` borne `L` par le haut, ce que PADMÉ seul ne fait pas.

| `L` uniforme dans | `log2 N` | ancienne règle (I / max) | PADMÉ seul (I / max) | **seau** (I / max) | surcoût ancienne (pire) | surcoût seau (pire) |
|---|---|---|---|---|---|---|
| [0, 1 Kio) | 10,0 | 1,28 / 2,96 | 0,91 / 1,00 | **0,91 / 1,00** | 0,65 % (2,22) | 2,40 % (4,44) |
| [0, 64 Kio) | 16,0 | 5,46 / 7,76 | 4,65 / 4,75 | **4,65 / 4,75** | 0,57 % (3,12) | 2,30 % (6,25) |
| [64 Kio, 1 Mio) | 19,9 | 7,13 / 9,80 | 6,30 / 6,54 | **6,30 / 6,54** | 0,56 % (3,12) | 2,26 % (6,25) |
| [1 Mio, 16 Mio) | 23,9 | 7,44 / 10,58 | 6,61 / 7,01 | **6,61 / 7,01** | 0,56 % (3,12) | 2,25 % (6,25) |
| [16 Mio, 64 Mio) | 25,6 | 6,72 / 9,82 | 5,89 / 6,02 | **5,89 / 6,02** | 0,56 % (3,12) | 2,24 % (6,25) |
| [512 Mio, 1 Gio) | 29,0 | 5,81 / 9,11 | 4,97 / 5,04 | **4,97 / 5,04** | 0,56 % (3,12) | 2,24 % (6,25) |
| [0, 1 Gio) | 30,0 | 7,80 / 12,45 | 6,97 / 8,78 | **6,97 / 8,78** | 0,56 % (3,12) | 2,24 % (6,25) |

(Sans bourrage, la fuite serait totale : `log2 N` bits. Le surcoût est mesuré par rapport à `Ref`, réserve non comprise.)

L'ancienne règle fuyait environ **0,8 bit de plus en moyenne**, et **3 à 4 bits de plus au pire** que PADMÉ seul.

### 1.3 La correction : le seau

PADMÉ arrondit `Ref` à une valeur alignée `X = PADMÉ(Ref)`. Les intervalles `[X, X + masque(X)]`, où `masque(X) = 2^(E−S) − 1` est le masque de PADMÉ calculé sur `X`, pavent les entiers : ce sont les **seaux**. Janus tire désormais `F` uniformément dans le seau de `PADMÉ(Ref)`.

**Proposition.** Avec le seau, `I(L ; F) = I(L ; PADMÉ(Ref(L)))`, et la fuite maximale est la même que celle de PADMÉ seul.

*Preuve.* Comme les seaux pavent les entiers, `F` détermine son seau, donc `X = PADMÉ(Ref(L))`. Inversement, sachant `X`, `F` est uniforme sur le seau de `X`, indépendamment de `L`. On a donc une chaîne de Markov `L → X → F`, où `X` est une fonction de `F` : `I(L ; F) = I(L ; X)`. Pour la fuite maximale, `P(F | L) = 1 / |seau(X)|` sur le seau, d'où `Σ_F max_L P(F | L) = Σ_X 1 = |{X atteints}|`, exactement la fuite maximale de PADMÉ. ∎

**Et la signature ?** `F = X + U`, où `U` est uniforme sur toute la largeur du seau, une puissance de deux. Les bits de poids faible de `F` sont donc uniformes : la taille ne porte plus le motif de bits nuls de PADMÉ.

**Coût.** Environ 2,2 % de taille en moyenne au lieu de 0,6 %, et 6,25 % au pire au lieu de 3,12 %. Le surcoût total d'un fichier, réserve comprise, passe d'environ 7 % à 8,5 %. **Décision du 21 novembre 2026 : seau adopté.** Seul le chiffrement change : l'ouverture ne vérifie pas la loi de `F`, donc les fichiers déjà écrits et les autres clients restent compatibles. Les vecteurs de test ont été régénérés.

---

## 2. Q2 : le KEM caché est IND-CCA

### 2.1 L'énoncé

Le « KEM caché » est la partie d'un emplacement à clé qui produit le secret partagé `ss` (spec, § 5.2 et 5.3) : X-Wing avec un éphémère X25519 « sale » (une composante d'ordre faible), le chiffré ML-KEM encodé par Kemeleon et masqué par un flux qui dépend de `ss_X`, et le point transmis par son représentant Elligator.

On sépare deux choses :
- **le KEM lui-même**, dont le chiffré est le couple `(ct_X, κ')` une fois décodés le représentant et l'encodage ;
- **les encodages** Elligator et Kemeleon, qui sont plusieurs-pour-un : plusieurs représentants `r` donnent le même `ct_X` (deux racines, deux bits hauts), et plusieurs `κ` le même `ct_M`. Modifier l'encodage sans changer le chiffré décodé redonne la même clé. C'est une **malléabilité bénigne** : elle interdit l'IND-CCA strict au niveau des octets, et c'est pourquoi le document 06 prouve IND-RCCA, qui la tolère.

**Théorème (Q2).** Le KEM caché, à chiffrés décodés, est IND-CCA. Pour tout adversaire faisant `N_d` requêtes de décapsulation :

```
Adv^IND-CCA ≤ min( 2·Adv^PRF_SHA3 + 6·N_d·P_ctxtcoll + 2·Adv^IND-CCA2_ML-KEM ,                  (chemin ML-KEM)
                   2·Adv^gapDH(q_H) + 4·2⁻¹²⁶ + O((q_H + N_d)·2⁻²⁵²) + 2·q_H·N_d·2⁻¹²²⁸⁸ )   (chemin X25519, avec C2PRI)
```

Ces bornes sont celles que donne CryptoVerif (§ 4), où `P_ctxtcoll`, la probabilité qu'un chiffré ML-KEM honnête tombe sur une valeur donnée, est négligeable.

- **Chemin ML-KEM.** Hypothèses : ML-KEM-768 est IND-CCA2, et SHA3-256 est une fonction pseudo-aléatoire de clé `ss_M`, comme dans l'analyse d'X-Wing (Barbosa et al., 2024). Il tient **même si X25519 est entièrement cassé** : l'adversaire du modèle reçoit la clé secrète X25519.
- **Chemin X25519.** Hypothèses : gap-DH sur Curve25519, SHA3 et SHAKE comme oracles aléatoires, et **C2PRI** pour ML-KEM. Il tient même si le secret d'ML-KEM est compromis.

### 2.2 Ce que la vérification par machine a révélé : C2PRI

La première version du modèle X25519 supposait ML-KEM *entièrement* cassé, et CryptoVerif a refusé de conclure. La raison est réelle. Le combineur d'X-Wing ne hache pas `ct_M` (c'est voulu, pour la performance). Un adversaire qui saurait trouver un second chiffré `ct'_M ≠ ct_M` donnant le même secret `ss_M` pourrait alors :
- garder `ct_X` ;
- changer `κ'` pour qu'il décode en `ct'_M` ;
- obtenir la même clé avec un chiffré différent.

Cela casse l'IND-CCA strict. Il faut donc que deux chiffrés différents ne donnent jamais le même secret, ce qu'on appelle **C2PRI** (*ciphertext second-preimage resistance*). L'analyse d'X-Wing utilise la même propriété.

**C2PRI tient pour ML-KEM, et elle ne dépend pas de MLWE.** Avec la transformée de Fujisaki-Okamoto à rejet implicite, un chiffré valide détermine `m`, donc la clé, par réencryption. Un chiffré invalide donne `J(z ‖ c)`, qui dépend de `c`. Une collision demande donc une collision de SHA3 ou de SHAKE. C2PRI reste vraie face à un ordinateur quantique, à la sécurité générique des collisions près.

**Conséquences pour Janus :**
- **IND-RCCA (document 06) n'est pas touché.** Une collision `ss'_M = ss*_M` redonnerait la même clé, donc le même clair, et l'oracle RCCA répond alors « test », ce qui est permis.
- **L'énoncé « Janus résiste si l'un des deux KEM tient » est précisé.** Pour le chemin X25519, il faut en plus C2PRI d'ML-KEM, qui ne repose que sur SHA3. La confidentialité **passive** (document 04) n'en a pas besoin : sans oracle de décapsulation, la question ne se pose pas.

### 2.3 Le lemme du cofacteur

CryptoVerif raisonne dans un groupe d'ordre premier. Curve25519 a un cofacteur 8 : le groupe des points est `⟨B⟩ × T₈`, où `T₈` est formé des 8 points d'ordre faible. Le point de Janus est « sale » : `P = e·B + L`, avec `L ∈ T₈`. Le lemme suivant justifie l'abstraction.

**Lemme.** Soit `π(P) = (8⁻¹ mod ℓ)·(8·P)` la projection sur `⟨B⟩`, calculable par tous. Pour toute clé X25519 `sk`, de scalaire clampé `s = clamp(sk)`, et tout point `P` de la courbe : `X25519(sk, u(P)) = u(s · π(P))`.

*Preuve.* `s` est multiple de 8, donc `s·L = 0` pour tout `L ∈ T₈`, et `s·P = s·π(P)`. X25519 ne dépend que de la coordonnée `u`, qui est la même pour `P` et `−P`, et l'échelle de Montgomery calcule `u(s·P)`. ∎

**Conséquences :**
- Le défi `P* = e·B + L` donne `ss*_X = s·e·B = e·pk_X`, un Diffie-Hellman ordinaire dans `⟨B⟩`. Le défi gap-DH `(pk_X, e·B)` se plonge en ajoutant un `L` aléatoire, comme au document 04.
- Toute requête de décapsulation porte sur `π(P')`, dans `⟨B⟩`. La simulation interroge l'oracle de décision DH sur `(pk_X, π(P'), Z)`, ce qui est exactement l'oracle du modèle.
- **Elligator ne produit que des points de la courbe, jamais de sa tordue.** Un adversaire ne peut donc pas faire calculer `s·P'` sur un groupe de petit ordre de la tordue, l'attaque classique contre X25519 sur entrée invalide.
- Les clés « clampées » de X25519 ne couvrent pas uniformément `ℤ_ℓ`. L'écart est le terme `pDistRerandom` de CryptoVerif, que sa bibliothèque évalue à `2⁻¹²⁶` pour Curve25519.

---

## 3. Face à un ordinateur quantique

### 3.1 Le problème

Les preuves des documents 04 à 06 utilisent l'**oracle aléatoire** (H1) : on y remplace une fonction de hachage par une fonction aléatoire, et on observe ou on reprogramme les requêtes de l'adversaire. Un adversaire quantique peut interroger le hachage **en superposition** (modèle QROM). Observer ses requêtes n'a alors plus de sens, et les preuves ne se transposent pas telles quelles. Les outils du QROM, comme le lemme « one-way to hiding » (O2H), perdent en général une racine carrée dans les bornes.

### 3.2 Pour les visages à clé : plus besoin d'oracle aléatoire

Contre un adversaire quantique, le chemin X25519 ne sert à rien : il casse gap-DH. Il reste le **chemin ML-KEM**. On reprend chacune de ses utilisations de l'oracle aléatoire, et on la remplace par une hypothèse du **modèle standard** :

| Où (documents 04 à 06) | Usage de l'oracle aléatoire | Remplacé par |
|---|---|---|
| Combineur `SHA3-256(ss_M ‖ …)` | `ss` uniforme si `ss_M` l'est | **SHA3-256 est une PRF de clé `ss_M`**, l'hypothèse de l'analyse d'X-Wing |
| Masque `SHAKE256(ss_X ‖ ct_X)` | aucun dans le chemin ML-KEM : la réduction connaît `ss_X` et calcule le masque | rien, aucune hypothèse (voir le modèle CryptoVerif) |
| `HKDF(ss, …)`, `HKDF(K, …)` | clés d'emballage, d'en-tête et de corps uniformes | **HMAC-SHA-256 est une PRF**, et une **PRF duale** (pseudo-aléatoire même quand la clé passe par l'entrée message). HKDF-Extract avec un sel nul est `HMAC(0³², ikm)`, sur un `ikm` uniforme de 32 octets (Backendal, Bellare, Günther, Scarlata, 2023) |
| ML-KEM lui-même | la transformée FO | **IND-CCA d'ML-KEM**, établie dans le QROM par la littérature sur la transformée FO à rejet implicite (Hofheinz, Hövelmanns, Kiltz 2017 ; Bindel, Hamburg, Hövelmanns, Hülsing, Persichetti 2019) |
| Kemeleon | uniformité de `κ` | MLWE (H5), déjà dans le modèle standard |
| Elligator | uniformité de `r` | statistique (H6), vraie face à tout adversaire |

**Théorème (post-quantique, visages à clé).** Les théorèmes des documents 04 (déni), 05 (intégrité) et 06 (IND-RCCA), restreints au chemin ML-KEM, valent **dans le modèle standard** sous :
- IND-CCA d'ML-KEM-768 ;
- MLWE ;
- SHA3-256 PRF de clé `ss_M` ;
- HMAC-SHA-256 PRF et PRF duale ;
- ChaCha20 PRF ;
- la résistance aux collisions de SHA-256 (document 05).

Les bornes sont celles des documents 04 à 06, sans les termes en `q_H / 2²⁵⁶`. Les réductions sont des simulations directes, sans rembobinage : elles valent face à un adversaire quantique, tant que les hypothèses elles-mêmes résistent au quantique.

*Vérification.* Pour Q2, c'est ce que montre le modèle CryptoVerif du chemin ML-KEM (§ 4) : il ne contient **aucun** oracle aléatoire.

**Niveaux de sécurité face au quantique :**
- La confidentialité et le déni reposent sur ML-KEM-768 (catégorie NIST 3), et sur des PRF de 256 bits, que l'algorithme de Grover ramène à 128 bits.
- L'engagement de clé (document 05) repose sur les collisions de SHA-256, que l'algorithme générique de Brassard, Høyer et Tapp trouve en environ 2⁸⁵ requêtes. Il demande cependant autant de mémoire quantique, et les meilleures estimations réalistes restent bien au-delà.

### 3.3 Pour les mots de passe : Argon2id dans le QROM

Argon2id est le seul endroit où l'oracle aléatoire est **indispensable** : rien dans le modèle standard ne dit qu'une fonction lente et gourmande en mémoire cache bien un mot de passe. Dans le QROM, l'étape G₁ du document 04 se refait avec le lemme O2H :

```
classique :   q_A / 2^h
quantique :   2·(q_A + 1) · 2^(−h/2)
```

**Lecture.** Face à un adversaire quantique, un mot de passe de `h` bits d'entropie n'en vaut plus que `h/2` environ. C'est l'effet de la recherche de Grover, qui atteint cet ordre de grandeur : avec `q` évaluations, elle trouve le mot de passe avec une probabilité d'environ `q² / 2^h`, donc en environ `2^(h/2)` évaluations. Un mot de passe de 60 bits en vaut donc environ 30.

Deux nuances :
- Chaque requête quantique demande d'évaluer Argon2id, avec ses 64 Mio de mémoire, **en superposition**, ce qui dépasse de très loin tout matériel envisageable.
- Grover se parallélise mal : `k` machines ne gagnent qu'un facteur `√k`.

En pratique, le conseil reste le même qu'en classique : **pour un secret important, une clé plutôt qu'un mot de passe**, ou un mot de passe long, d'au moins 100 bits d'entropie, soit une phrase de passe de 8 mots tirés au hasard.

---

## 4. Vérification par machine (CryptoVerif)

### 4.1 Ce qui est vérifié

L'outil est **CryptoVerif 2.13** (Blanchet et al.). Il raisonne directement par séquences de jeux dans le modèle calculatoire, comme nos preuves papier, et calcule lui-même la borne finale. Les modèles sont dans `preuves/cryptoverif/`.

| Modèle | Hypothèses | Ce que l'adversaire reçoit en plus | Résultat |
|---|---|---|---|
| `kem_cache_mlkem.ocv` | ML-KEM IND-CCA2, SHA3 PRF de clé `ss_M` ; **aucun oracle aléatoire** | la clé secrète X25519 | **Prouvé** automatiquement : `Adv ≤ 2·Pprf + 6·N_d·P_ctxtcoll + 2·P_ind-cca2` |
| `kem_cache_gdh.ocv` | gap-DH, SHA3 et SHAKE oracles aléatoires, C2PRI d'ML-KEM | un ML-KEM dont il sait décapsuler | **Prouvé** automatiquement : `Adv ≤ 2·pGDH + 4·pDistRerandom + O((q_H + N_d)·P_coll) + 2·q_H·N_d / |κ|` |

Dans les deux modèles :
- la requête est le **secret** de la clé partagée du défi (`query secret k`), face à un oracle de décapsulation qui accepte tout chiffré sauf le défi lui-même ;
- le masquage de `κ` est modélisé tel qu'il est, un XOR avec un flux qui dépend de `ss_X` et de `ct_X` ;
- le combineur d'X-Wing est modélisé tel qu'il est : `ss_M`, `ss_X`, `ct_X` et `pk_X`, mais pas `ct_M`.

### 4.2 Ce qui est abstrait, et où c'est traité

| Abstraction | Justification |
|---|---|
| Groupe d'ordre premier au lieu de Curve25519 | lemme du cofacteur (§ 2.3) |
| Elligator et Kemeleon remplacés par l'identité | ce sont des encodages ; leur malléabilité bénigne relève d'IND-RCCA (document 06) ; leur uniformité relève du déni (document 04, H5 et H6) |
| C2PRI modélisée par l'injectivité de la décapsulation | vraie pour ML-KEM à une collision de SHA3/SHAKE près (§ 2.2) |

### 4.3 Reproduire

Dans un Linux (ou WSL), avec opam :

```bash
opam switch create janus ocaml-base-compiler.4.14.2
opam install cryptoverif
cd preuves/cryptoverif
cryptoverif kem_cache_mlkem.ocv     # « All queries proved. »
cryptoverif kem_cache_gdh.ocv       # « All queries proved. »
```

Chaque modèle se vérifie en quelques secondes.

### 4.4 Ce qui n'est pas encore vérifié par machine

- **Le déni** (document 04) et la **confidentialité active** du fichier entier (document 06) : il faudrait modéliser l'en-tête complet, les 4 étiquettes, la réserve et STREAM. Ce sont de gros modèles ; le cœur cryptographique nouveau, le KEM caché, est désormais vérifié.
- **L'intégrité** (document 05), qui repose surtout sur des collisions de hachage.
- **Le QROM**, que CryptoVerif ne traite pas. Le § 3 contourne la question pour les visages à clé, en se passant de l'oracle aléatoire.

---

## 5. Bilan des preuves

| Propriété | Notion | Hypothèses (classique) | Face au quantique | Vérifié par machine |
|---|---|---|---|---|
| Confidentialité passive, discrétion, déni | IND$, DENI (04) | MLWE **ou** gap-DH ; Elligator statistique | modèle standard (chemin ML-KEM) ; mot de passe : `h/2` bits | non |
| KEM caché | IND-CCA (09, § 2) | (IND-CCA ML-KEM + PRF SHA3) **ou** (gap-DH + C2PRI) | modèle standard | **oui, les deux chemins** |
| Engagement, intégrité par visage | collisions, INT-CTXT (05) | SHA-256, HMAC, ChaCha20-Poly1305 | modèle standard ; collisions en 2⁸⁵ génériques | non |
| Confidentialité face aux fichiers piégés | IND-RCCA (06) | celles ci-dessus | modèle standard (chemin ML-KEM) | non (sauf le KEM, § 2) |
| Taille du fichier | fuite = celle de PADMÉ (09, § 1) | aucune (information-théorique) | idem | calcul exact |

**Ce qui manque encore :** la relecture par un cryptographe, qui reste indispensable, et les modèles CryptoVerif du fichier entier.
