# Janus : preuve d'intégrité (P2, P3, P4)

*Brouillon 0.1, 18 novembre 2026. Preuve « papier », non vérifiée par machine et non relue par un tiers. Elle porte sur le format v1 à deux visages, avec l'éphémère uniforme et le masquage de κ ([04-preuve-deux-visages.md](04-preuve-deux-visages.md)).*

## 0. En bref

La preuve de déni (document 04) traite un adversaire **passif** : il regarde un fichier honnête. Celle-ci traite un adversaire **actif** : il fabrique ou modifie des fichiers, puis observe ce qui se passe quand tu les ouvres.

| Propriété | Énoncé prouvé | Hypothèse principale |
|---|---|---|
| **P3. Engagement** (§ 3) | Quel que soit son auteur, un fichier s'ouvre sur **au plus deux** clés de fichier, une par étiquette | Résistance aux collisions de SHA-256 |
| **P4. Cohérence** (§ 4) | Deux destinataires qui valident la **même étiquette** lisent exactement le même contenu | P3 |
| **P2. Intégrité par visage** (§ 5) | Sans l'identifiant d'un visage, on ne peut modifier aucun octet de ce visage sans que l'ouverture échoue. Avec un mot de passe, on ne peut même pas fabriquer un nouveau fichier qui s'ouvre avec lui | HMAC (PRF), ChaCha20-Poly1305 (INT-CTXT), entropie du mot de passe |
| **Oracle de partition** (§ 6) | Ouvrir un fichier piégé teste au plus 2 mots de passe par tentative | P3 |

**Ce que la preuve a révélé**, détaillé au § 7 :
1. **La cohérence n'est plus globale, et c'est le prix du déni.** Un auteur malveillant peut fabriquer *un même fichier* que Alice ouvre sur un contenu et Bob sur un autre. C'est impossible en v0, inévitable en v1, et à documenter pour l'utilisateur.
2. **Un tiers peut effacer un visage caché sans que le leurre s'en aperçoive.** C'est inhérent au déni. Conséquence pratique : garder une sauvegarde.
3. **Deux petits défauts d'implémentation**, sans gravité, **corrigés depuis** (§ 7.3) :
   - le dédoublonnage se fait sur `K` seul, au lieu du triplet `(K, début, longueur)` ;
   - le temps d'ouverture dépend du nombre d'emplacements déballés, ce qui fait un petit canal temporel.

---

## 1. Rappel de l'ouverture

```
Ouvrir(f, identifiant) :
  F = |f| ;  lire T_0, T_1, sel, E_0 … E_15
  candidats = { (K, d, l) déballés de w_i, pour i = 0 … 15 } :
     mot de passe : clé_i = HKDF(Argon2id(m, sel), « mdp » ‖ i)
     identité     : clé_i = HKDF(Décaps(sk, r_i, κ_i), « xwing » ‖ i)
  valides = { c ∈ candidats : HMAC(HKDF(K, « entete »), F ‖ d ‖ l ‖ sel ‖ E) ∈ {T_0, T_1} }
  0 valide → ⊥ ;  plus d'un → « plusieurs visages » ;  un seul (K, d, l) :
  vérifier d + c(l) ≤ F − H, puis déchiffrer les n = ⌈l / 64 Kio⌉ blocs STREAM
  (nonce = j, drapeau « dernier » sur le bloc n − 1) à partir de H + d
  tout échec → ⊥
```

Deux faits structurent toute la preuve :
- **Tout l'en-tête est sous l'étiquette**, sauf les deux emplacements d'étiquette eux-mêmes. Cela couvre `sel`, les 16 emplacements, ainsi que `F`, `d` et `l`.
- **Une étiquette ne couvre pas l'autre étiquette, ni le corps hors de son visage.** C'est voulu : c'est là que vit l'autre visage.

---

## 2. Hypothèses

| N° | Hypothèse | Usage |
|---|---|---|
| I1 | **SHA-256 résiste aux collisions** (avantage `Adv^CR`) | Engagement (§ 3) |
| I2 | **HMAC-SHA-256 est une PRF**, donc un MAC infalsifiable sous une clé uniforme | Intégrité de l'en-tête (§ 5) |
| I3 | **ChaCha20-Poly1305 est INT-CTXT** : sans la clé, on ne fabrique pas de chiffré valide (avantage `≤ q·2⁻¹⁰³` environ pour Poly1305) | Emballages `w` et blocs du corps (§ 5) |
| I4 | **HKDF et Argon2id sont des oracles aléatoires** | Indépendance des sous-clés (§ 5) |
| I5 | **Le mot de passe a une entropie minimale `h`** | Mode mot de passe (§ 5.2) |
| I6 | **ML-KEM rejette implicitement** : un chiffré modifié donne un secret pseudo-aléatoire, sans message d'erreur | Emplacements à clé (§ 5.1) |

**Ce qu'on ne suppose pas :** que ChaCha20-Poly1305 soit *engageant*. Il ne l'est pas, et on verra que l'étiquette `T` compense.

---

## 3. Théorème 1 : engagement par étiquette (P3)

**Énoncé.** Pour tout fichier `f`, même fabriqué par un adversaire qui connaît toutes les clés, et pour chaque position d'étiquette `x ∈ {0, 1}`, il existe au plus un triplet `(K, d, l)` accepté via `T_x`, sauf si l'adversaire trouve une collision de SHA-256 :

```
Pr[ deux triplets distincts acceptés via la même étiquette ] ≤ Adv^CR_SHA-256
```

Par conséquent, un fichier s'ouvre sur **au plus deux** triplets, et donc au plus deux contenus.

**Preuve.** Soient `(K, d, l) ≠ (K', d', l')` acceptés via `T_x`. Alors `HMAC(k, m) = HMAC(k', m') = T_x`, avec `k = HKDF(K, « entete »)` et `m = F ‖ d ‖ l ‖ sel ‖ E`, et de même pour `k'` et `m'`. Il y a trois cas.

- **`k = k'` et `m = m'`.** Alors `d = d'` et `l = l'`, et `K ≠ K'` alors que `HKDF(K) = HKDF(K')`. HKDF est construit sur HMAC-SHA-256, donc on a trouvé une collision de HMAC, qui se ramène à une collision de SHA-256.
- **`k ≠ k'`.** La clé HMAC fait 32 octets, complétée à 64. Les blocs `k ⊕ opad` et `k' ⊕ opad` diffèrent, donc les deux entrées du hachage externe diffèrent et ont la même sortie : c'est une collision de SHA-256.
- **`k = k'` et `m ≠ m'`.** Soit les hachages internes sont égaux, ce qui fait une collision sur des entrées différentes, soit ils diffèrent et le hachage externe entre en collision. ∎

> **En clair.** L'étiquette fixe la clé **et** la position du visage. Un auteur malveillant ne peut pas faire valider deux visages par la même étiquette. Il en a deux à sa disposition : il peut donc faire deux visages, pas trois. C'est exactement la fonction voulue, et rien de plus.

---

## 4. Théorème 2 : cohérence par visage (P4)

**Énoncé.** Si deux destinataires, avec deux identifiants différents, ouvrent le même fichier `f` en validant **la même étiquette**, ils obtiennent le même clair.

**Preuve.** Par le théorème 1, ils obtiennent le même `(K, d, l)`. Le déchiffrement est ensuite une fonction déterministe de `(f, K, d, l)`. ∎

**La limite, qui est le prix du déni.** Deux destinataires qui valident deux étiquettes **différentes** peuvent lire deux contenus différents, à partir d'un fichier identique octet pour octet. Personne ne peut le détecter, car le détecter reviendrait à prouver l'existence de l'autre visage. Voir § 7.1.

---

## 5. Théorème 3 : intégrité par visage (P2)

### 5.1 Le jeu INT

Le défi tient les identifiants honnêtes d'un visage : des identités X-Wing dont `𝒜` ne connaît que les clés publiques, ou un mot de passe tiré selon une loi d'entropie `h`. `𝒜` connaît tout le reste, y compris les identifiants de l'autre visage, s'il y en a un.

- **Oracle de chiffrement.** `𝒜` choisit `(M₁, R₁, M₂, R₂)`, où l'un des visages utilise les identifiants honnêtes. Il reçoit le fichier `f_i`. Le défi note `(K_i, d_i, l_i, M_i)` pour le visage honnête.
- **Oracle d'ouverture.** `𝒜` soumet n'importe quel fichier. Il reçoit le clair, ou `⊥`, obtenu avec les identifiants honnêtes. C'est toi qui ouvres les fichiers qu'on t'envoie.
- **𝒜 gagne** s'il fait accepter, par l'oracle d'ouverture, un fichier `f*` qui donne `(K*, d*, l*, M*)` avec l'une des deux situations suivantes :
  - **(a) modification :** `K* = K_i` pour un fichier honnête `i`, mais `M* ≠ M_i` ;
  - **(b) contrefaçon par mot de passe :** le visage honnête est protégé par mot de passe, et `K*` n'est la clé d'aucun fichier honnête.

Une contrefaçon d'un visage à **clé publique** n'est pas une victoire : n'importe qui peut chiffrer pour ta clé publique. Janus n'authentifie pas l'expéditeur (c'est la piste E). Seule la **modification** d'un fichier existant compte.

### 5.2 Énoncé

```
Pr[𝒜 gagne] ≤ q_A / 2^h                                  (deviner le mot de passe, cas b)
            + 16 · q_O · Adv^INT-CTXT_AEAD                 (forger un emballage w)
            + q_O · Adv^MAC_HMAC                           (forger une étiquette sous K_i)
            + q_O · Adv^INT-CTXT_STREAM                    (forger ou déplacer un bloc)
            + Adv^CR_SHA-256 + q_H / 2²⁵⁶
```

Dans cette borne :
- `q_O` est le nombre d'appels à l'oracle d'ouverture ;
- `q_A` et `q_H` sont les requêtes aux oracles Argon2id et HKDF ;
- `Adv^INT-CTXT_STREAM` vaut au plus `Adv^INT-CTXT_AEAD`, d'après Hoang, Reyhanitabar, Rogaway et Vizár (2015), car les nonces sont distincts et le dernier bloc est marqué.

### 5.3 Preuve, cas (a) : modifier un fichier honnête

`f*` est accepté avec `K* = K_i`, que `𝒜` ne connaît pas.
1. **L'étiquette.** `f*` porte `T* = HMAC(k_i, F* ‖ d* ‖ l* ‖ sel* ‖ E*)` à l'une des deux positions, avec `k_i = HKDF(K_i, « entete »)` uniforme et inconnue (I4).
   - Si le message `(F*, d*, l*, sel*, E*)` diffère de celui du fichier honnête `i`, alors `𝒜` a forgé un MAC sous `k_i`. Coût : `Adv^MAC_HMAC` par requête.
   - Sinon, l'en-tête et la taille sont **identiques** à ceux de `f_i`, et `(d*, l*) = (d_i, l_i)`.
2. **Le corps.** Le visage occupe les mêmes octets `[H + d_i, H + d_i + c(l_i))`. Le nombre de blocs est fixé par `l_i`. Chaque bloc est vérifié sous `HKDF(K_i, « corps »)` avec son numéro, et le dernier porte son drapeau.
   - Modifier, échanger, dupliquer, tronquer ou prolonger un bloc revient à forger un chiffré STREAM (I3).
   - Sinon, les octets du visage sont ceux de `f_i`, et `M* = M_i`.
3. **Ce qui reste libre** : l'autre étiquette et le corps hors du visage. Les modifier ne change pas `M*`. Ce n'est pas une victoire, c'est la propriété voulue.

### 5.4 Preuve, cas (b) : contrefaçon sous un mot de passe inconnu

`f*` est accepté sous le mot de passe honnête `m`, avec une clé `K*` neuve.
1. **Un emballage a été déballé.** Un emplacement `w*_j` s'est déballé sous `HKDF(A*, « mdp » ‖ j)`, avec `A* = Argon2id(m, sel*)`. Il y a trois cas.
   - `𝒜` a interrogé Argon2id sur `(m, sel*)` : il a deviné le mot de passe. Coût : `q_A / 2^h`.
   - Sinon, `A*` est uniforme et inconnu. Si `sel*` est neuf, la clé d'emballage n'a jamais servi, et `w*_j` est une contrefaçon AEAD.
   - Si `sel*` est celui d'un fichier honnête `i`, la clé `HKDF(A_i, j)` est celle de l'emplacement `j` de `f_i`. `𝒜` peut alors recopier `w_j`. Mais `w_j` contient `K_i`, donc on retombe dans le cas (a). Autrement, il doit forger un chiffré nouveau sous cette clé, soit une contrefaçon AEAD. Le numéro `j` entre dans la dérivation, donc **déplacer** un emballage d'un emplacement à un autre ne marche pas.
   - Coût total : `16 · q_O · Adv^INT-CTXT_AEAD`.
2. Une fois `K*` connu de `𝒜` (il l'a choisi), le reste du fichier est sous son contrôle, mais il a déjà fallu réussir l'étape 1. ∎

### 5.5 Et pour un visage à clé publique ?

Le cas (a) s'applique tel quel, ce qui couvre l'intégrité : personne ne modifie ton fichier. La contrefaçon n'a pas de sens sans authentification de l'expéditeur.

**Une remarque utile.** Les emplacements à clé sont **malléables** en eux-mêmes :
- les 2 bits hauts de `r` sont ignorés ;
- Kemeleon décode de nombreux `κ` en un même chiffré ;
- le masque de `κ` est un simple XOR.

Le KEM caché seul n'est donc **pas** IND-CCA. Ce n'est pas grave, car l'étiquette couvre chaque octet de chaque emplacement : toute modification de ce genre fait échouer `T` (étape 1 du cas a). C'est l'étiquette, et non le KEM, qui apporte la non-malléabilité du fichier. Il faudra le rappeler si l'on réutilise un jour le KEM caché hors de Janus.

---

## 6. Théorème 4 : pas d'oracle de partition

**La menace** (Len, Grubbs et Ristenpart, 2021). ChaCha20-Poly1305 n'est pas engageant. Un attaquant peut fabriquer un chiffré qui se déchiffre correctement sous **plusieurs** clés à la fois. S'il te fait ouvrir un fichier piégé et observe le succès ou l'échec, il teste alors plusieurs mots de passe d'un coup. Avec un format mal conçu, cela réduit une recherche exhaustive à une recherche dichotomique.

**Énoncé.** Le **résultat** d'une ouverture (succès ou `⊥`) teste au plus **2** mots de passe par fichier piégé, sauf collision de SHA-256.

**Preuve.** Un succès exige un triplet validé par `T_0` ou `T_1`. Pour un mot de passe candidat donné, le triplet déballé est fixé, et la validation dépend de lui. Par le théorème 1, chaque étiquette ne valide qu'un triplet. Au plus deux candidats peuvent donc conduire à un succès. ∎

**Le canal temporel.** Le **temps** d'ouverture, lui, dépend du code : l'étiquette n'est calculée que pour les emplacements qui se déballent (§ 7.3, défaut 2).
- Un emballage piégé, valide sous plusieurs clés, ajoute environ 15 µs de calcul quand ton mot de passe est parmi les candidats.
- Un `w` ne compte que 3 blocs Poly1305 libres. Le système d'équations ne permet donc qu'**environ 4 clés** à la fois.
- Ces 15 µs sont noyées dans les variations d'Argon2id, de l'ordre de la milliseconde.

L'effet est négligeable, mais il est simple à supprimer.

---

## 7. Ce que la preuve a révélé

### 7.1 La cohérence entre destinataires n'est plus globale (conséquence du déni)

**Le constat.** En v0, un même fichier donnait le même contenu à tous ceux qui l'ouvraient. En v1, un auteur malveillant peut :
1. mettre Alice dans le visage 1 et Bob dans le visage 2 ;
2. y écrire deux contenus différents, par exemple deux versions d'un contrat ;
3. envoyer **le même fichier** aux deux.

Si Alice et Bob comparent l'empreinte SHA-256 du fichier, ils la trouvent identique, et pourtant ils n'ont pas lu la même chose.

**Pourquoi on ne peut pas l'empêcher.** Si Bob pouvait vérifier qu'Alice lit la même chose que lui, il pourrait vérifier qu'il n'existe pas d'autre visage, et le déni disparaîtrait. Les deux propriétés sont incompatibles. On retrouve le conflit entre déni et preuve noté dans la cartographie (D-2), sous une forme nouvelle.

**Ce qu'il faut faire.**
- **Le documenter**, dans la spec (P4 devient « cohérence par visage ») et dans le README.
- **Le conseil pratique :** pour s'assurer d'avoir lu la même chose, comparer l'empreinte **du clair**, pas celle du fichier chiffré.
- **Une option possible (piste E) :** si l'expéditeur signe le clair, la signature lie le contenu à son auteur. Elle est alors incompatible avec le second visage, comme prévu.

C'est la version « deux visages » des *invisible salamanders* (Dodis, Grubbs, Ristenpart, Woodage, 2018), mais **bornée à deux contenus** par le théorème 1.

### 7.2 Un tiers peut effacer le visage caché sans que le leurre s'en aperçoive

**Le constat.** Le corps hors du leurre et l'étiquette du visage caché ne sont pas couverts par le leurre. N'importe qui peut les écraser : le leurre s'ouvre toujours, et le secret est perdu. C'est le même phénomène que l'écrasement d'un volume caché VeraCrypt.

**On ne peut pas l'empêcher** sans que le leurre « voie » le secret, ce qui le trahirait.

**Ce qu'il faut faire** : le documenter dans les pièges de la conception (03, § 10), avec un conseil. Toujours garder une copie du fichier, et vérifier de temps en temps, avec le second identifiant, que le secret s'ouvre encore.

### 7.3 Deux défauts d'implémentation mineurs (corrigés)

**Ce qui a été fait (18 novembre 2026).**
- **Défaut 1 :** `retrouver_visages` dédoublonne maintenant sur le triplet `(K, début, longueur)`, en temps constant. Le test `meme_cle_deux_positions_donne_plusieurs_visages` fabrique l'en-tête piégé décrit ci-dessous. L'ouverture signale bien « plusieurs visages », et un même triplet présent dans deux emplacements compte pour un seul visage.
- **Défaut 2 :** l'étiquette est calculée pour **chaque** essai, avec une charge nulle quand l'emplacement ne se déballe pas.
  - Mesure dudect avant le correctif : |t| = 2,85 sur 2 000 mesures. L'écart était réel, mais sous le seuil.
  - Après le correctif : |t| = 0,89 et 1,50 sur deux passages.
  - Coût mesuré : l'ouverture par clé passe de 8,5 à 8,8 ms.
- **Ce qui reste :** la vérification du tag Poly1305 de `w`, puis le déchiffrement de 48 octets en cas de succès, diffèrent encore de quelques dizaines de nanosecondes. C'est négligeable devant les variations d'Argon2id et de la décapsulation.

**Description des défauts d'origine :**

**Défaut 1 : dédoublonnage sur `K` seul.**
- `retrouver_visages` regroupe les candidats par `K`. Un auteur malveillant peut faire déballer, par un même identifiant, `(K, d₁, l₁)` validé par `T_0` et `(K, d₂, l₂)` validé par `T_1`. Le code garde alors le premier en silence, au lieu de signaler « plusieurs visages ».
- Ce n'est pas une faille : le résultat est déterministe, et le théorème 1 borne tout à deux contenus. Mais le comportement est incohérent.
- *Correctif :* dédoublonner sur le triplet `(K, d, l)`.

**Défaut 2 : temps d'ouverture variable** (§ 6).
- L'étiquette n'est calculée que pour les emplacements déballés.
- *Correctif :* calculer **toujours** 16 étiquettes, avec une clé factice pour les emplacements qui ne se déballent pas, puis choisir le résultat en temps constant.
- Coût : environ 16 × 15 µs, soit 0,25 ms par ouverture, contre 8,5 ms par clé et 117 ms par mot de passe.

### 7.4 Ce qui n'est pas couvert

- **L'authentification de l'expéditeur** : c'est la piste E.
- **Le retour en arrière** : remplacer un fichier par une ancienne version valide reste indétectable, comme en v0.
- **La sortie en flux** : `dechiffrer_flux` écrit chaque lot **après** l'avoir vérifié. Une ouverture qui échoue a donc pu écrire un **préfixe authentique** du clair. C'est la garantie de STREAM (nOAE). La ligne de commande jette ce préfixe (fichier temporaire, J-06), mais un autre programme qui utiliserait la bibliothèque devrait faire de même.
- **La confidentialité quand tu ouvres des fichiers piégés** : traitée dans [06-preuve-confidentialite-active.md](06-preuve-confidentialite-active.md). La notion exacte est **IND-RCCA** et non IND-CCA : la malléabilité bénigne (réserve, autre étiquette) est inévitable avec deux visages.

---

## 8. Suite proposée

| Ordre | Travail | Effet |
|---|---|---|
| ~~1~~ | ~~Corriger les deux défauts du § 7.3~~ **Fait** | Comportement cohérent et temps d'ouverture constant |
| ~~2~~ | ~~Documenter § 7.1 et § 7.2~~ **Fait** (03, pièges 10.8 et 10.9 ; spec P4 ; README) | L'utilisateur connaît le prix du déni |
| ~~3~~ | ~~Rédiger le recollement IND-CCA~~ **Fait** : IND-RCCA, document 06 | Confidentialité face aux fichiers piégés |
| 4 | Vérification par machine (CryptoVerif) des documents 04 et 05 | Confiance dans les preuves |
| 5 | Relecture par un cryptographe | Indispensable avant publication |
