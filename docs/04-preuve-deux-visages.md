# Janus : preuve de sécurité des deux visages (QB-5)

*Brouillon 0.1, 18 novembre 2026. Preuve « papier » par séquence de jeux, non vérifiée par machine et non relue par un tiers.*

## 0. En bref

**Le résultat.** On prouve que l'adversaire du § 9.1 de [03-deux-visages.md](03-deux-visages.md) ne gagne qu'avec une probabilité négligeable. Cet adversaire possède le fichier et tous les secrets du leurre, et cherche à savoir s'il existe un visage caché. Le théorème du § 6 donne la borne exacte.

**Deux découvertes faites en écrivant la preuve.**

1. **Une faiblesse post-quantique dans le prototype (§ 7.1).**
   - Le code tire l'éphémère X25519 avec un scalaire *clampé*. Le point obtenu ne couvre donc que la **moitié** du sous-groupe premier.
   - Un ordinateur quantique sait calculer des logarithmes discrets, donc tester cette moitié. Son avantage est d'environ **10 % par fichier** pour un seul destinataire caché, et de **80 % sur 100 fichiers**.
   - Pour un adversaire classique, ce même test coûte environ 2¹²⁶ opérations, donc rien ne change.
   - La spécification est saine. Le défaut était dans l'implémentation. **Il est corrigé** : le scalaire est maintenant tiré uniformément modulo ℓ (§ 7.1, « Le correctif »).
2. **Le déni n'était pas hybride (§ 7.2).** La confidentialité tient si ML-KEM **ou** X25519 tient, mais la discrétion des emplacements à clé reposait sur **MLWE seul**. **C'est corrigé** : `κ` est maintenant masqué par un flux dérivé de X25519, et la discrétion est hybride elle aussi.

**Ce que « preuve » veut dire ici.** C'est une **réduction**. Si quelqu'un savait gagner le jeu, on saurait construire, à partir de lui, une attaque contre l'une des briques : X-Wing, ChaCha20, HMAC, MLWE ou la devinette du mot de passe. Les briques sont supposées sûres (§ 4), et la preuve ne dit rien si l'une d'elles tombe. C'est la méthode standard de la cryptographie moderne (Bellare et Rogaway, Shoup, « sequences of games »).

---

## 1. Notations

| Notation | Sens |
|---|---|
| `x ←$ X` | `x` tiré uniformément dans l'ensemble `X` |
| `U_n` | chaîne uniforme de `n` octets |
| `Adv^P(B)` | avantage de l'algorithme `B` contre la propriété `P` : `|Pr[B gagne] − 1/2|`, multiplié par 2 |
| `q_H`, `q_A` | nombre de requêtes de l'adversaire aux oracles aléatoires HKDF (et SHA3) et Argon2id |
| `n₁`, `n₂` | nombre de destinataires du leurre et du secret (`n₁ + n₂ ≤ 16`) |
| `ℓ` | ordre du sous-groupe premier de Curve25519, `ℓ = 2²⁵² + 27742317777372353535851937790883648493` |

---

## 2. Le schéma, tel que prouvé

On abstrait le format v1 ([03-deux-visages.md](03-deux-visages.md), § 3 à 7). Pour chaque visage `v` ∈ {1, 2}, de clair `M_v`, de destinataires `R_v`, placé en `d_v` :

```
Chiffrer(M₁, R₁, [M₂, R₂]) :
  F   ←  tirage uniforme dans [Ref(|M₁|), PADMÉ(Ref(|M₁|))]          (§ 5)
  sel ←$ U₃₂ ;  E_0 … E_15 ←$ U₁₆₃₂ ;  T_0, T_1 ←$ U₃₂ ;  corps ←$ U_{F−H}
  π   ←$ permutation de {0 … 15} ;  σ ←$ {0, 1}                     (R2, R4)
  d₁ = 0 ;  d₂ ←$ [c(|M₁|), F − H − c(|M₂|)]
  pour chaque visage v présent :
     K_v ←$ U₃₂ ;  charge_v = K_v ‖ d_v ‖ |M_v|
     pour chaque destinataire de R_v, à l'emplacement i = π(prochain) :
        clé publique pk :  (r, κ, ss) ← EncapsCachée(pk)
                           E_i = r ‖ κ ‖ AEAD(HKDF(ss, « xwing » ‖ i), 0, charge_v)
        mot de passe m :   A = Argon2id(m, sel)
                           E_i[1568..] = AEAD(HKDF(A, « mdp » ‖ i), 0, charge_v)
  pour chaque visage v présent :
     T_{(v+σ) mod 2} = HMAC(HKDF(K_v, « entete »), F ‖ d_v ‖ |M_v| ‖ sel ‖ E_0 … E_15)
     corps[d_v .. d_v + c(|M_v|)] = STREAM(HKDF(K_v, « corps »), M_v)
  renvoyer T_0 ‖ T_1 ‖ sel ‖ E_0 … E_15 ‖ corps
```

`EncapsCachée(pk)` est le § 6 de la spec v0 :
- un éphémère « sale » `P = e·B + L`, avec `L` d'ordre faible et `r` un représentant Elligator 2 de `P` ;
- `κ = Kemeleon(ct_M) ⊕ SHAKE256(« masque » ‖ ss_X ‖ ct_X)` (masquage du § 7.2, ajouté après la première version de cette preuve) ;
- `ss` le secret du combineur X-Wing.

**La spécification tire `e` uniformément modulo ℓ** (§ 7.1 pour l'écart avec le code).

> **En clair.** Tout ce qui n'est pas écrit pour un visage est tiré au hasard au départ. Écrire un visage ne fait que **remplacer** de l'aléa par autre chose. Toute la preuve consiste à montrer que cet « autre chose » ressemble à de l'aléa pour qui n'a pas la clé.

---

## 3. Le jeu DENI

```
Jeu DENI_b(𝒜) :                                       b ∈ {0, 1}
  1. Le défi crée n₂ identités X-Wing honnêtes (sk₂ⱼ, pk₂ⱼ) et donne les pk₂ⱼ à 𝒜.
     S'il y a un mot de passe secret, il tire m₂ selon une loi D d'entropie minimale h.
  2. 𝒜 choisit :
       M₁, M₂ avec c(|M₂|) ≤ Réserve(|M₁|) ;
       R₁ : n'importe quelles clés publiques valides (même fabriquées par lui),
            ou n'importe quel mot de passe m₁ ;
       la forme de R₂ : les pk₂ⱼ, ou « le mot de passe secret ».
     Contraintes R5 : aucune pk₂ⱼ dans R₁ ; n₁ + n₂ ≤ 16.
  3. Si b = 1 : f ← Chiffrer(M₁, R₁, M₂, R₂).  Si b = 0 : f ← Chiffrer(M₁, R₁).
  4. 𝒜 reçoit f. Il connaît déjà tous les secrets de R₁, et il a accès aux oracles
     aléatoires (HKDF, SHA3, Argon2id) tout au long du jeu.
  5. 𝒜 renvoie b'.

Adv^DENI(𝒜) = | Pr[DENI₁(𝒜) = 1] − Pr[DENI₀(𝒜) = 1] |
```

Remarques sur ce modèle :
- **L'adversaire choisit le leurre et ses destinataires**, y compris des clés malhonnêtes. Il est donc plus fort que celui qui a « seulement » obtenu ton mot de passe.
- **Il connaît `M₂`.** Le déni ne doit pas dépendre du contenu du secret.
- **Il n'a pas d'oracle de déchiffrement pour le secret.** C'est cohérent : sous la contrainte, tu nies posséder un second identifiant, donc tu ne déchiffres rien avec. Il peut en revanche tout déchiffrer avec les identifiants du leurre, puisqu'il les a.
- **Un seul fichier.** Le cas de plusieurs fichiers s'obtient par un argument hybride, avec une borne multipliée par le nombre de fichiers. Le cas de **plusieurs versions du même fichier** sort du modèle : c'est le piège 10.1 de la conception, qui n'est pas cryptographique.

---

## 4. Hypothèses

| N° | Hypothèse | Ce qu'elle dit | Statut |
|---|---|---|---|
| H1 | Oracle aléatoire | HKDF-SHA-256, SHA3 (dans ML-KEM et le combineur) et Argon2id se comportent comme des fonctions aléatoires | Modèle standard pour ce type de preuve |
| H2 | ChaCha20-Poly1305 est IND$ | Avec une clé uniforme et des nonces distincts, chiffré et tag sont indistinguables de l'aléa : `Adv ≤ Adv^PRF_ChaCha20` plus un terme négligeable | Vrai si ChaCha20 est une PRF (Procter, 2014). Le tag de Poly1305 est masqué par `s`, issu du flux |
| H3 | HMAC-SHA-256 est une PRF | Avec une clé uniforme, la sortie est indistinguable de l'aléa | Bellare (2006) |
| H4 | MLWE **ou** gap-DH | Soit MLWE est difficile (ML-KEM-768 est alors IND-CPA), soit gap-DH est difficile sur Curve25519. La preuve n'utilise **que l'un des deux à la fois** (étape G₂), comme l'analyse d'X-Wing (Barbosa et al., 2024) | L'hypothèse hybride elle-même |
| H5 | Chiffrés ML-KEM pseudo-aléatoires | Sous MLWE, `ct_M` est indistinguable de la compression d'éléments uniformes de Z_q. Kemeleon transforme alors `κ` en `U₁₅₃₆`, à une distance statistique `ε_K` près | Preuve d'IND-CPA de Kyber, et article Kemeleon (Günther, Stebila, Veitch, 2024) |
| H6 | Elligator 2, point sale | Si `e` est uniforme modulo ℓ et `L` uniforme parmi les 8 points d'ordre faible, alors `P` est uniforme sur la courbe et `r` est uniforme sur 256 bits, à `ε_E ≈ 2⁻²⁵⁰` près | **Statistique**, donc vraie même contre un ordinateur quantique. **Exige un `e` uniforme** (§ 7.1, corrigé dans le code) |
| H7 | Mot de passe | Le mot de passe secret a une entropie minimale `h` | Hypothèse sur l'utilisateur |

---

## 5. La séquence de jeux

On part du monde `b = 1` et on arrive, par petites modifications, au monde `b = 0`. On note `Pr[Gₖ]` la probabilité que `𝒜` renvoie 1 dans le jeu `Gₖ`. Chaque étape ne change cette probabilité que d'une quantité qu'on borne.

**G₀.** Le jeu `DENI₁` tel quel.

**G₁ — le mot de passe secret devient une clé aléatoire.** S'il y a un mot de passe secret, remplacer `A₂ = Argon2id(m₂, sel)` par `A₂ ←$ U₃₂`.
- *Pourquoi ce n'est presque pas visible :* dans le modèle de l'oracle aléatoire (H1), `A₂` est déjà uniforme, **sauf** si `𝒜` interroge Argon2id sur `(m₂, sel)`.
- *Coût :* `|Pr[G₁] − Pr[G₀]| ≤ q_A / 2^h`. Ce terme est la **seule** limite qui dépende de toi : c'est la force du mot de passe secret, multipliée par le nombre d'essais que l'adversaire peut payer, à environ 0,1 s d'Argon2id par essai.

**G₂ — le secret et le `κ` masqué du visage caché deviennent aléatoires.** Pour chaque destinataire caché `j`, remplacer **ensemble** `ss_j` par `U₃₂` et `κ'_j` par `U₁₅₃₆`.

*Pourquoi les deux ensemble.* La première version de cette preuve traitait `ss` (par l'IND-CPA d'X-Wing) puis `κ` séparément. Avec le masquage, ce découpage ne marche plus. L'algorithme `B` qui reçoit un défi X-Wing complet ne connaît pas `ss_X`, donc il ne peut pas calculer le masque, ni par conséquent `κ'`. On utilise plutôt **deux chemins, dont un seul suffit**. Dans chacun, `B` fabrique lui-même la moitié du KEM qu'il doit connaître.

- **Chemin MLWE.** `B` reçoit un défi ML-KEM `(pk_M, ct_M, ss_M*)` et fabrique lui-même toute la partie X25519 : il connaît `e`, donc `ss_X` et le masque.
  - Si `ss_M*` est uniforme, `ss = SHA3(ss_M*, ss_X, ct_X, pk_X, label)` l'est aussi (H1). Coût : IND-CPA de ML-KEM, donc MLWE.
  - Ensuite, `Kemeleon(ct_M)` est indistinguable de l'aléa (H5). Le XOR avec un masque connu le laisse uniforme.
  - Coût : `Adv^MLWE + ε_K`, à une constante près.
- **Chemin X25519.** `B` reçoit un défi Diffie-Hellman `(pk_X, e·B)` et fabrique lui-même toute la partie ML-KEM : il connaît `ss_M` et `κ`. Il ajoute un `L` aléatoire au point reçu.
  - `ss` et le masque sont deux sorties d'oracle aléatoire qui contiennent `ss_X`. Tant que `𝒜` n'interroge pas l'oracle sur `ss_X`, les deux sont uniformes et indépendants. `κ' = κ ⊕ masque` est alors uniforme, quel que soit `κ`.
  - `B` reconnaît une telle requête avec un oracle de décision DH, ce qui revient à résoudre gap-DH.
  - Coût : `Adv^gapDH`, plus un terme en `q_H / 2²⁵⁶`.

Coût de l'étape : `n₂ · min(Adv^MLWE + ε_K, Adv^gapDH)`. Avant le masquage, seul le chemin MLWE pouvait rendre `κ` aléatoire : le déni dépendait de MLWE seul (§ 7.2).

*Note sur Q2.* Dans le chemin X25519, `ct_X` porte en plus le point d'ordre faible `L`, et le combineur hache ce `ct_X` tel quel. `B` ajoute lui-même `L` au point du défi, puis reprogramme l'oracle sur l'entrée modifiée, ce qui est légitime sous H1. **Cela règle Q2 pour la confidentialité passive.** Le cas des chiffrés choisis (IND-CCA) reste ouvert, mais il n'est pas requis ici.

**G₃ — `r` devient aléatoire.** Remplacer chaque `r_j` par `U₃₂`.
- *Pourquoi :* depuis G₂, `ss_j` et `κ'_j` sont uniformes et indépendants de `e`. `r` est alors le représentant d'un point uniforme, ce que donne H6.
- *Coût :* `n₂ · ε_E` (statistique).
- **C'est ici que l'ancien code s'écartait de la preuve** (§ 7.1, corrigé).

**G₄.** *(Étape vide, conservée pour garder la numérotation des étapes suivantes.)*

**G₅ — les emballages `w` deviennent aléatoires.** Remplacer chaque `w_i` du visage caché par `U₆₄`.
- *Pourquoi :* les clés d'emballage `HKDF(ss_j, …)` ou `HKDF(A₂, …)` sont uniformes et indépendantes (H1), sauf si `𝒜` interroge l'oracle sur `ss_j` ou `A₂`, qui sont uniformes et qu'il ne voit pas. Chaque clé ne sert qu'une fois, donc H2 s'applique.
- *Coût :* `(n₂ + 1) · q_H / 2²⁵⁶ + n₂ · Adv^IND$_AEAD(1 message)`.
- **Conséquence :** `K₂`, `d₂` et `|M₂|` n'apparaissent plus nulle part dans ce que voit `𝒜`, sauf à travers `T` et le corps.

**G₆ — l'étiquette du secret devient aléatoire.** Remplacer `T_{(2+σ) mod 2}` par `U₃₂`.
- *Pourquoi :* `K₂` est uniforme et inconnu, donc `HKDF(K₂, « entete »)` est une clé uniforme (H1). HMAC calculé sous cette clé, une seule fois, est indistinguable de l'aléa (H3).
- *Coût :* `q_H / 2²⁵⁶ + Adv^PRF_HMAC`.

**G₇ — le flux du secret devient aléatoire.** Remplacer `corps[d₂ .. d₂ + c(|M₂|)]` par de l'aléa.
- *Pourquoi :* la clé `HKDF(K₂, « corps »)` est uniforme, et les nonces des blocs sont distincts (H2).
- *Coût :* `Adv^IND$_AEAD(⌈|M₂| / 64 Kio⌉ messages)`.

**G₇ = DENI₀.** Dans G₇, tout ce que le visage caché avait écrit a été remplacé par de l'aléa uniforme indépendant :
- son étiquette ;
- ses emplacements (`r`, `κ` et `w`, ou `w` seul pour un mot de passe, `r` et `κ` étant alors déjà aléatoires) ;
- son flux.

Restent les éléments communs aux deux mondes, qui suivent la même loi :
- `F` ne dépend que de `|M₁|` ;
- `π` et `σ` sont uniformes, et les emplacements du leurre sont les `n₁` premiers de `π` dans les deux cas ;
- un bloc d'aléa placé à une position `d₂` aléatoire, au milieu d'autre aléa, ne se distingue pas d'aléa.

Le leurre est fabriqué exactement de la même manière dans les deux mondes. G₇ est donc **identique** au monde `b = 0`. ∎

---

## 6. Théorème

Pour tout adversaire `𝒜` contre le jeu DENI, faisant `q_H` requêtes à HKDF et SHA3 et `q_A` requêtes à Argon2id, il existe des algorithmes `B₁ … B₅`, de temps d'exécution comparable, tels que :

```
Adv^DENI(𝒜) ≤ q_A / 2^h                                  (mot de passe secret, s'il y en a un)
            + n₂ · ( min( Adv^MLWE(B₁) + ε_K , Adv^gapDH(B₂) ) + ε_E )
            + n₂ · Adv^IND$_AEAD(B₃)
            + Adv^PRF_HMAC(B₄) + Adv^IND$_AEAD(B₅)
            + (n₂ + 2) · q_H / 2²⁵⁶
```

**Lecture.**
- Avec un secret protégé par des **clés**, tous les termes sont négligeables. Le niveau visé par ML-KEM-768, X25519 et ChaCha20 est d'au moins 2¹²⁸ opérations.
- Avec un **mot de passe** secret, le terme `q_A / 2^h` domine. Un mot de passe de 60 bits d'entropie, attaqué avec 2³⁰ calculs Argon2id (environ 3 ans de calcul sur un cœur), laisse un avantage de 2⁻³⁰. Le déni ne vaut que ce que vaut le mot de passe caché.
- La borne ne dépend **ni** de `M₁`, **ni** de `M₂`, **ni** de `n₁`.

### Corollaire : P5 pour un tiers

Un tiers sans aucun identifiant ne distingue pas un fichier Janus d'une chaîne aléatoire de même taille. Il suffit d'appliquer les étapes G₁ à G₇ **aussi au leurre**, dont les destinataires sont alors honnêtes. La seule information qui reste est `F`, qui révèle `|M₁|` à PADMÉ près (spec v0, § 7).

---

## 7. Ce que la preuve a révélé

### 7.1 Faiblesse : le scalaire éphémère était clampé (implémentation, corrigée)

**Le constat.** Avant le correctif, dans `src/xwing.rs`, `encapsuler_cache` appelait `Randomized::mul_base_clamped(ek_x)` du crate `curve25519-elligator2`. Ce crate **clampe** l'octet tiré (`clamp_integer`) :

```
e = 2²⁵⁴ + 8k,   avec k uniforme dans [0, 2²⁵¹)
```

Modulo ℓ ≈ 2²⁵², ces `e` ne prennent que **2²⁵¹ valeurs, la moitié des valeurs possibles**. Le point premier `e·B` n'est donc uniforme que sur la moitié du sous-groupe, et l'hypothèse H6 est fausse pour le code actuel.

**Qui peut l'exploiter.** Il faut décider si le logarithme discret de `e·B` tombe dans cette moitié.
- **Adversaire classique :** cette moitié est un intervalle dans la coordonnée `k = (e + 4δ)·8⁻¹ mod ℓ`, où δ = ℓ − 2²⁵². Décider l'appartenance coûte environ 2¹²⁶ opérations avec la méthode des kangourous de Pollard. **Aucun risque pratique.**
- **Adversaire quantique :** l'algorithme de Shor calcule le logarithme discret. Le test devient immédiat.

**L'avantage obtenu** (calculé exactement). L'adversaire contraint teste les 15 emplacements hors leurre. Un vrai éphémère réussit toujours le test, un emplacement aléatoire une fois sur deux.

| Destinataires cachés | Avantage sur un fichier |
|---|---|
| 1 | 0,105 |
| 2 | 0,209 |
| 4 | 0,422 |
| 8 | 0,787 |

Sur plusieurs fichiers d'un même utilisateur ayant chacun un secret, les indices s'additionnent : avantage d'environ 0,32 sur 10 fichiers, 0,80 sur 100 et 0,97 sur 300. **Le même test casse P5 pour un tiers quantique** : il reconnaît un fichier Janus à ses emplacements à clé.

**Pourquoi c'est grave pour Janus en particulier.** L'adversaire du déni peut **archiver** tes fichiers aujourd'hui et les analyser dans quinze ans. Le déni post-quantique est une promesse centrale de la piste A, et elle n'est pas tenue par le code actuel.

**Le correctif.**
1. Tirer `e` **uniformément modulo ℓ** (64 octets d'aléa réduits modulo ℓ), puis `L` parmi les 8 points d'ordre faible.
2. Calculer `P = e·B + L`, puis `ss_X = e·pk_X`. Le destinataire, lui, calcule toujours `X25519(sk_X, ct_X)` sans changement. Son scalaire clampé est multiple de 8, ce qui annule `L`, donc `clamp(sk)·P = e·clamp(sk)·B = e·pk_X`.
3. Calculer le représentant Elligator 2 **du point** `P`. Le crate ne le permet pas : toutes ses variantes, y compris `EdwardsPoint::to_representative`, reprennent l'entrée comme une clé privée à clamper. Il faut écrire nous-mêmes l'inverse de la carte Elligator 2 (Bernstein, Hamburg, Krasnova, Lange, 2013 ; la carte directe est au RFC 9380, § 6.7.1), soit environ 60 lignes en temps constant, sur une arithmétique modulo 2²⁵⁵ − 19 elle-même en temps constant.
4. Ajouter un test : sur des milliers d'éphémères, `e mod ℓ` doit couvrir les deux moitiés.

Le format ne change pas, les vecteurs de test si.

**Ce qui a été fait (18 novembre 2026).**
- `src/elligator.rs` contient l'inverse d'Elligator 2 pour un point quelconque. Il repose sur l'arithmétique modulo 2²⁵⁵ − 19 de `fiat-crypto`, générée et prouvée correcte, déjà présente comme dépendance du crate Elligator.
  - Sur 2 000 points que le crate sait traiter, il donne **le même représentant, octet pour octet**.
  - Sur des points quelconques, l'aller-retour avec la carte directe du crate est exact.
  - dudect ne détecte aucune fuite de temps (|t| ≤ 1,13 sur 10 000 mesures, deux passages).
- `ephemere_cache` (dans `src/xwing.rs`) tire `e` uniformément modulo ℓ et `L` parmi les 8 points d'ordre faible. Un test vérifie que les 8 points sont tous atteints.
- **Le test de l'adversaire quantique** (`le_scalaire_ephemere_couvre_tout_le_sous_groupe`) donne au test le vrai logarithme `e`, que seul un ordinateur quantique pourrait calculer :
  - le témoin, c'est-à-dire l'ancien tirage clampé, tombe dans la moitié testée **2 000 fois sur 2 000** ;
  - le nouveau tirage y tombe environ une fois sur deux, comme un point aléatoire.
- Le secret partagé reste correct, car le destinataire calcule toujours le X25519 standard. Les 5 vecteurs à clé ont été régénérés ; les vecteurs à mot de passe n'ont pas changé.
- Coût : l'encapsulation passe d'environ 0,22 ms à 0,32 ms par destinataire.

### 7.2 Limite de conception : le déni reposait sur MLWE seul (corrigée)

**Le constat (avant le masquage).** Cacher `κ` exigeait MLWE (H5), alors que cacher `ss` exigeait seulement MLWE **ou** X25519. Si MLWE tombait un jour, par une avancée mathématique contre les réseaux euclidiens :
- la **confidentialité** tiendrait encore grâce à X25519 : c'est l'intérêt de l'hybride ;
- la **discrétion** et le **déni** tomberaient, car `κ` redeviendrait reconnaissable comme un chiffré ML-KEM.

**La proposition : masquer `κ` avec un flux tiré de X25519.**

```
κ' = κ ⊕ SHAKE256(« janus/v1/masque » ‖ ss_X ‖ ct_X, 1536 octets)
```

- Le destinataire calcule `ss_X` d'abord, à partir de `r`, puis démasque `κ`, puis termine l'ouverture comme avant.
- `κ'` est alors pseudo-aléatoire si MLWE tient (κ l'est déjà) **ou** si X25519 tient (le masque l'est). La discrétion devient **hybride**, comme la confidentialité.
- Coût : un SHAKE256 de 1536 octets par emplacement, quelques microsecondes.

*Attention :* ce masquage ne rend la discrétion vraiment hybride qu'**après** le correctif du § 7.1. Sinon, X25519 lui-même est reconnaissable par un adversaire quantique. Les deux sont faits.

**Ce qui a été fait (18 novembre 2026).**
- Le masquage est dans `src/xwing.rs` (`masquer`, appelé à l'encapsulation et à la décapsulation).
- Le test `kappa_masque_par_x25519` vérifie deux choses :
  - décoder `κ'` sans le démasquer ne redonne pas le secret ;
  - celui qui connaît `ss_X` retrouve exactement l'encodage Kemeleon.
- Le test statistique de `tests/format.rs` mesure désormais aussi les `κ'` réellement écrits : χ² = 261, pour environ 255 attendus. Le même test trouve χ² ≈ 3 040 sur les chiffrés ML-KEM bruts.
- Coût : non mesurable sur le banc (0,31 ms par encapsulation, 8,5 ms par ouverture). dudect ne détecte aucune fuite.
- Les vecteurs à clé ont été régénérés. Le format v1 change, mais pas sa taille.

**Conséquence pour la sécurité.** La discrétion et le déni tiennent maintenant si **MLWE ou X25519** tient : les deux familles devraient tomber pour qu'on reconnaisse un emplacement à clé. C'est la même garantie que pour la confidentialité.

### 7.3 Points vérifiés et trouvés sains

- **Les positions** (R2) et le **choix de l'étiquette** (R4) suivent la même loi dans les deux mondes.
- **Le sel commun** : sous H1, `Argon2id(m₁, sel)` et `Argon2id(m₂, sel)` sont indépendants dès que `m₁ ≠ m₂`. R5 l'impose. Si le mot de passe secret est tiré au hasard, une collision avec `m₁` a une probabilité au plus 2⁻ʰ, déjà comptée.
- **La taille** ne dépend que de `|M₁|`, et la contrainte de capacité est publique.
- **Le message « plusieurs visages »** n'est déclenchable que par qui possède déjà les deux identifiants, donc il est hors du jeu.
- **Les clés malhonnêtes du leurre** n'aident pas `𝒜` : les éléments du visage caché ne dépendent jamais d'elles.

### 7.4 Ce qui n'est pas couvert

- **Plusieurs versions d'un même fichier** (piège 10.1) et **traces du système** (piège 10.6) : hors du modèle.
- **Les canaux auxiliaires** autres que le temps d'ouverture du leurre. Ce dernier est mesuré par dudect, pas prouvé.
- **IND-CCA du KEM caché** : non requis par ce jeu, mais nécessaire pour prouver l'intégrité (P2, P3) face à des fichiers fabriqués. C'est un autre théorème, à écrire.
- **La sécurité en présence d'un adversaire quantique** qui interroge les oracles aléatoires en superposition (modèle QROM). Les étapes G₁, G₅ et G₆ devraient s'y transposer, avec des bornes typiquement en `q²` au lieu de `q`. Ce n'est ni rédigé ni vérifié.
- **La vérification par machine.** CryptoVerif, qui raisonne directement par séquences de jeux dans le modèle calculatoire, est l'outil adapté. EasyCrypt serait une alternative plus lourde.

---

## 8. Suite proposée

| Ordre | Travail | Effet |
|---|---|---|
| ~~1~~ | ~~Corriger le scalaire (§ 7.1)~~ **Fait** | H6 rétablie, donc le déni post-quantique |
| ~~2~~ | ~~Masquer `κ` (§ 7.2)~~ **Fait** | Discrétion hybride |
| 3 | Écrire le théorème d'intégrité (IND-CCA du KEM caché, P2 à P4 par visage) | Complète la preuve |
| 4 | Modéliser les étapes G₁ à G₇ dans CryptoVerif | Fait vérifier la preuve par une machine |
| 5 | Faire relire par un cryptographe | Indispensable avant toute publication |
