# Janus : les deux visages (piste B)

*Conception, brouillon 0.2, 18 novembre 2026. Prototype implémenté dans `janus-rs` (format v1) ; résultats dans [janus-rs/README.md](../janus-rs/README.md).*

> **L'idée en une phrase.** Un même fichier Janus s'ouvre sur un **leurre** avec un premier mot de passe (ou une première clé), et sur le **vrai contenu** avec un second. Celui qui ne connaît que le premier ne peut pas **prouver** qu'il existe un second visage, car **tous** les fichiers Janus ont exactement la même forme, qu'ils en contiennent un ou non.

Ce document répond à la menace A6 de la cartographie : la **coercition**, quand quelqu'un te force à donner ton mot de passe.

---

## 1. La promesse, et ses limites

### Ce que l'on promet

Quelqu'un qui :
- connaît Janus et lit cette spécification ;
- possède le fichier ;
- obtient le mot de passe ou la clé du leurre, et l'ouvre ;

ne peut pas distinguer un fichier **avec** visage caché d'un fichier **sans** visage caché, avec une probabilité meilleure que le hasard (§ 9).

### Ce que l'on ne promet pas

- **Qu'il ne soupçonne rien.** Il sait que Janus permet un second visage. Il peut donc toujours supposer qu'il y en a un. La protection est qu'il ne peut pas le **démontrer**, rien de plus (cartographie, piste B).
- **Que le déni te protège.** Face à un adversaire qui ne se contentera jamais d'une réponse, pouvoir cacher quelque chose peut aggraver la situation : il ne sera jamais sûr d'avoir tout obtenu. Choisir d'utiliser un second visage relève de ta situation personnelle, pas de la cryptographie.
- **L'effacement des traces laissées par ton système** : fichiers temporaires, documents récents, miniatures, fichier d'échange (Czeskis et al., 2008). Janus protège le fichier, pas l'ordinateur sur lequel tu l'ouvres.

---

## 2. Trois règles de conception

1. **Une seule structure.** Le second visage n'est pas une option ajoutée au format : c'est **le** format. Chaque fichier contient deux étiquettes d'en-tête et une **réserve** d'octets aléatoires. Dans un fichier à un visage, l'étiquette et la réserve inutilisées sont de l'aléa. Dans un fichier à deux visages, elles portent le visage caché.
2. **Chaque visage est un chiffré complet et engagé.** Chaque visage a sa propre clé de fichier `K`, sa propre étiquette d'en-tête et son propre flux STREAM. On n'exploite **pas** l'absence d'engagement de clé (J-05) : ouvrir un visage n'apprend rien sur l'autre, et chacun reste intègre.
3. **La taille ne dépend que du leurre.** La taille de la réserve est une **fonction fixe** de la longueur du leurre, connue de tous (§ 5). L'adversaire qui a ouvert le leurre peut la recalculer, et il trouve exactement ce que la spécification annonce.

> **En clair.** Si seuls certains fichiers avaient une réserve, la réserve trahirait le secret. Si la réserve grandissait avec le secret, sa taille le trahirait. On paie donc une réserve de taille fixe sur **tous** les fichiers : c'est le prix du déni.

---

## 3. Structure du fichier (Janus v1)

Le format v0 n'est ni figé ni diffusé. On propose donc que cette structure **remplace** v0 sous le nom de v1, avec les étiquettes `janus/v1/…` (question QB-4).

```
 décalage   taille           contenu
 ────────   ──────────────   ─────────────────────────────────────────────
 0          32               T_0      étiquette d'en-tête n° 0
 32         32               T_1      étiquette d'en-tête n° 1
 64         32               sel      sel Argon2id, commun aux deux visages
 96         16 × 1632        E_0 … E_15   emplacements de destinataire
 26 208     F − 26 208       corps    visage principal, réserve, visage caché
```

`H` = 96 + 16 × 1632 = **26 208** octets (contre 25 888 en v0).

### 3.1 Emplacement (1632 octets)

```
 0      32     r    représentant Elligator 2       (aléa pour un mot de passe)
 32     1536   κ    Kemeleon(ct_M)                 (aléa pour un mot de passe)
 1568   64     w    AEAD(clé_emb, 0¹², K ‖ BE64(début) ‖ BE64(longueur))
```

Par rapport à v0, `w` transporte aussi **où commence** le visage dans le corps (`début`) et la **longueur exacte** de son clair (`longueur`). Les deux sont nécessaires : un visage ne s'arrête plus à la fin du fichier.

### 3.2 Corps

```
 corps = [ visage principal ][ réserve : aléa ou visage caché, à une position aléatoire ][ aléa ]
          début = 0           Réserve(L₁) octets garantis                               tirage PADMÉ
```

Chaque visage est un flux STREAM ordinaire (spec v0, § 8), qui commence à `début` et compte `n = max(1, ⌈longueur / TB⌉)` blocs, le dernier étant partiel et portant le drapeau « dernier ». Sa taille chiffrée vaut :

```
c(L) = L + 16 × max(1, ⌈L / TB⌉)
```

Le bourrage `0x80 ‖ 0x00*` de v0 **disparaît** : la longueur est donnée par `w`, et tout ce qui n'appartient à aucun visage est de l'aléa.

---

## 4. Dérivations

```
K_entete      = HKDF(K, "janus/v1/entete")
K_corps       = HKDF(K, "janus/v1/corps")
clé_emb_i     = HKDF(ss_i, "janus/v1/emballage/xwing" ‖ octet(i))       clé publique
A             = Argon2id(mdp, sel)                                       un seul calcul
clé_emb_mdp_i = HKDF(A,    "janus/v1/emballage/mdp"   ‖ octet(i))        mot de passe

T_visage = HMAC(K_entete, BE64(F) ‖ BE64(début) ‖ BE64(longueur) ‖ sel ‖ E_0 ‖ … ‖ E_15)
```

Trois choix méritent une explication.

- **Le sel est commun et à une place fixe.** Un mot de passe peut ainsi ouvrir n'importe lequel des 16 emplacements avec **un seul** calcul Argon2id, suivi de 16 essais d'AEAD presque gratuits. Deux visages protégés par deux mots de passe partagent le sel sans inconvénient, puisque les mots de passe diffèrent.
- **`T` couvre `début` et `longueur`.** Sans cela, un auteur malveillant pourrait donner à deux destinataires d'un même visage la même `K` mais deux `début` différents, et donc deux contenus différents. La cohérence entre destinataires (P4) serait cassée. Avec `T` qui les couvre, réussir l'ouverture fixe à la fois `K`, `début` et `longueur`.
- **`T` couvre `F`.** Ajouter ou retirer des octets à la fin du fichier fait échouer **les deux** visages. On garde ainsi la détection des troncatures et des ajouts de v0.

---

## 5. Taille et réserve

```
L₁        = longueur du visage principal (le leurre)
Réserve   = max(R_min, ⌈L₁ / ρ⌉)                     fonction FIXE, publique
          = max(65 536, ⌈L₁ / 16⌉)                   valeurs retenues (QB-1)
Ref       = H + c(L₁) + Réserve
F         = entier uniforme dans [Ref, PADMÉ(Ref)]   comme en v0, mêmes raisons
```

- **Capacité du visage caché** : il faut `c(L₂) ≤ Réserve`. Sinon, Janus refuse et explique qu'il faut un leurre plus grand. On ne peut **jamais** agrandir la réserve pour faire entrer le secret, car cela rendrait sa taille dépendante du secret.
- **Position du visage caché** : `début₂` est tiré uniformément dans `[c(L₁), F − H − c(L₂)]`, ce qui couvre la réserve et la marge aléatoire de PADMÉ. Utiliser cette marge pour la *position* ne biaise rien, car sa taille a été tirée avant, indépendamment du secret.
- **Bonus** : le corps n'a plus besoin de finir sur une frontière de bloc. Les 16 tailles sur 65 552 que v0 ne produisait jamais deviennent possibles. Cette petite fuite (spec v0, § 7) disparaît.

### Coût, avec R_min = 64 Kio (taille moyenne du fichier, réserve et marge PADMÉ comprises)

| Leurre | Réserve fixe 64 Kio | `max(64 Kio, L₁/16)` | `max(64 Kio, L₁/8)` |
|---|---|---|---|
| 100 Ko | secret ≤ 65 Ko, fichier +52 % | idem | idem |
| 1 Mo | secret ≤ 65 Ko, +7 % | secret ≤ 65 Ko, +7 % | secret ≤ 125 Ko, +13 % |
| 10 Mo | secret ≤ 65 Ko, +0,3 % | secret ≤ 625 Ko, +6 % | secret ≤ 1,25 Mo, +13 % |
| 1 Go | secret ≤ 65 Ko, +0 % | secret ≤ 62 Mo, +6,5 % | secret ≤ 125 Mo, +13 % |

Les pourcentages comparent la taille moyenne d'un fichier v1 à celle d'un fichier v0 de même contenu. Ce coût s'applique à **tous** les fichiers, même sans visage caché.

> **En clair.** 64 Kio, c'est une trentaine de pages de texte, un coffre de mots de passe ou un jeu de clés : le genre de secret qu'on protège d'une contrainte. Le facteur `ρ` permet de cacher davantage (des photos, un document), au prix de quelques pour cent sur chaque fichier.

---

## 6. Règles de remplissage

- **R1 (par visage).** Un visage protégé par mot de passe n'a **que** ce mot de passe. Même raison qu'en v0 : sinon, un destinataire à clé connaissant `K` pourrait recopier l'emplacement dans un faux fichier. Les deux visages peuvent chacun avoir leur mot de passe : c'est le cas le plus courant.
- **R2.** Les emplacements des deux visages sont tirés **au hasard** parmi les 16, sans doublon. Les autres sont de l'aléa.
- **R3.** Pas plus de 16 destinataires **au total** pour les deux visages.
- **R4.** Le visage principal reçoit l'étiquette `T_0` ou `T_1` à pile ou face. Le visage caché reçoit l'autre. Sans visage caché, l'autre étiquette est `aléa(32)`.
- **R5.** Janus **refuse** :
  - le même mot de passe pour les deux visages ;
  - la même clé publique dans les deux visages ;
  - un visage caché plus grand que la réserve.
- **R6. Le leurre est toujours le visage principal.** Il commence au début du corps, comme l'unique visage d'un fichier ordinaire. Un visage qui commence au milieu du corps n'existe que dans un fichier à deux visages : son identifiant ne doit **jamais** être donné sous la contrainte.

---

## 7. Algorithmes

### 7.1 Chiffrer un leurre `M₁` et, éventuellement, un secret `M₂`

1. Calculer `Réserve` et `Ref` à partir de `L₁ = |M₁|` (§ 5). Si `M₂` est donné et que `c(L₂) > Réserve`, refuser (R5).
2. Tirer `F`, puis `début₂` s'il y a un visage caché.
3. Tirer `sel = aléa(32)`, `K₁` et, s'il y a un visage caché, `K₂`.
4. Construire les 16 emplacements (R1 à R3, § 3.1), avec dans chaque `w` les valeurs `début` et `longueur` de son visage.
5. Calculer les étiquettes selon le § 4 et les placer selon R4.
6. Écrire l'en-tête, puis le corps dans l'ordre : flux du visage 1, aléa, flux du visage 2, aléa jusqu'à `F`.

### 7.2 Ouvrir

1. Retrouver `(K, début, longueur)` :
   - avec un mot de passe, calculer `A` **une fois**, puis essayer `w_i` pour i = 0 à 15 ;
   - avec des identités, procéder comme en v0.
2. Calculer `T'` (§ 4) et le comparer **en temps constant** à `T_0` **et** à `T_1`. Accepter si l'une des deux comparaisons réussit.
3. Vérifier que `début + c(longueur) ≤ F − H`.
4. Déchiffrer les blocs du visage (STREAM, drapeau « dernier » sur le bloc final), en parallèle comme en v0.
5. Ignorer tout le reste du corps.

Une seule erreur, « impossible de déchiffrer » (J-07). Jamais de message du type « ce fichier contient un autre visage ».

*Exception, dans le prototype :* si les identifiants fournis **ensemble** ouvrent deux visages différents, Janus refuse et demande de les donner séparément. Seul quelqu'un qui possède déjà les deux identifiants peut provoquer ce message : il ne lui apprend donc rien.

---

## 8. Ce qui change par rapport à v0

| Point | v0 | v1 (deux visages) |
|---|---|---|
| En-tête | `T`, 16 × 1616 | `T_0`, `T_1`, `sel`, 16 × 1632 (+320 octets) |
| `w` | `K` | `K ‖ début ‖ longueur` |
| Mot de passe | seulement en `E_0` | dans n'importe quel emplacement, avec un seul Argon2id |
| Bourrage | `0x80 ‖ 0x00*` chiffré | aucun : la longueur est dans `w`, le reste est de l'aléa |
| Taille | `[Ref, PADMÉ(Ref)]` | idem, avec en plus une réserve fixe dans `Ref` |
| Tailles impossibles | 16 sur 65 552 | aucune |
| P2 (intégrité) | chaque octet du fichier | chaque octet **du visage ouvert**, plus la taille totale `F`. Modifier la réserve ne gêne pas le leurre, et c'est voulu |
| P3 (engagement) | une seule clé par fichier | **au plus deux** clés, une par étiquette (théorème 1 de [05-preuve-integrite.md](05-preuve-integrite.md)) |
| P4 (cohérence) | tous les destinataires lisent la même chose | tous les destinataires **d'un même visage** lisent la même chose. Deux visages peuvent montrer deux contenus (piège 10.8) |
| Coût d'ouverture par mot de passe | 1 Argon2id | 1 Argon2id + 16 AEAD de 48 octets (négligeable) |

---

## 9. Pourquoi l'adversaire contraint ne voit rien

Il possède le fichier et le leurre ouvert, donc `K₁`, `A₁`, `début₁`, `L₁` et `F`. Voici chaque élément du fichier, sans puis avec visage caché.

| Élément | Sans visage caché | Avec visage caché | Pourquoi il ne peut pas les distinguer |
|---|---|---|---|
| Étiquette inutilisée par le leurre | `aléa(32)` | `HMAC(K₂_entete, …)` | HMAC est une fonction pseudo-aléatoire, et il ignore `K₂` |
| Emplacements hors leurre | `aléa(1632)` | emplacements du secret | Encapsulation X-Wing cachée (P5 de v0, question Q2) et AEAD sous une clé inconnue |
| `sel` | aléa | aléa, partagé | Identique |
| Réserve et fin du corps | aléa | flux ChaCha20-Poly1305 sous `K₂_corps` | Un chiffré ChaCha20-Poly1305 est indistinguable de l'aléa (IND$-CPA) |
| Taille `F` | dépend de `L₁` seul | dépend de `L₁` seul | Même loi de tirage (§ 5) |
| Position du leurre | début du corps | début du corps | R6 |
| Temps d'ouverture du leurre | 16 essais | 16 essais | Même travail (à vérifier avec dudect) |

### 9.1 Jeu de sécurité (preuve : [04-preuve-deux-visages.md](04-preuve-deux-visages.md))

1. L'adversaire choisit `M₁`, l'identifiant du leurre, `M₂` (avec `c(|M₂|) ≤ Réserve(|M₁|)`) et l'identifiant du secret, à condition qu'il soit différent de celui du leurre.
2. Le défi tire `b` au hasard. Si `b = 0`, il fabrique un fichier avec le seul leurre. Si `b = 1`, il ajoute le visage caché.
3. L'adversaire reçoit le fichier **et** tous les secrets du leurre (mot de passe ou identités).
4. Il gagne s'il devine `b`.

Hypothèses : ChaCha20-Poly1305 est IND$-CPA, HMAC-SHA-256 est une fonction pseudo-aléatoire, l'encapsulation X-Wing cachée est indistinguable de l'aléa (Q2), et HKDF et Argon2id se comportent comme des oracles aléatoires. Si le secret est protégé par un mot de passe, son avantage est borné par la probabilité de deviner ce mot de passe hors ligne, au coût d'un Argon2id par essai.

---

## 10. Pièges et limites

1. **Plusieurs versions du même fichier.** Si l'adversaire voit deux versions d'un fichier dont le leurre n'a **pas changé** mais dont tous les octets ont changé, il peut se demander pourquoi l'auteur a rechiffré un leurre identique. C'est le talon d'Achille connu des volumes cachés de VeraCrypt (adversaire à plusieurs instantanés). Conseil : modifier le leurre chaque fois qu'on modifie le secret. *Outil : `janus modifier` avertit quand le leurre n'a pas changé.*
2. **Pas de modification en place.** Rechiffrer le leurre avec le seul mot de passe du leurre produit un fichier **sans** visage caché : le secret disparaît, sans avertissement possible, puisque Janus ignore son existence. C'est l'équivalent de l'écrasement d'un volume caché VeraCrypt. Pour changer un visage, il faut refabriquer le fichier avec les deux. *Outil : `janus modifier` exige l'identifiant de chaque visage et refuse de produire un fichier qui en perdrait un.*
3. **Le leurre doit être crédible.** Un fichier de 2 Mo dont le leurre est une liste de courses de 12 octets ne trahit rien par sa taille, puisque la réserve est fixe (64 Kio). En revanche, ce leurre est peu vraisemblable comme chose à chiffrer. La cryptographie ne remplace pas le bon sens.
4. **Deux visages au plus.** Avec deux étiquettes, l'adversaire sait qu'il n'existe pas de troisième visage. S'il obtient deux identifiants valides, il sait qu'il a tout. Passer à 4 étiquettes ne coûterait que 64 octets et permettrait de toujours prétendre « il n'y en a pas d'autre » (QB-3).
5. **Signature (piste E) incompatible.** Un leurre signé reste possible, mais le secret ne doit pas être signé avec la même clé.
6. **Traces du système.** Ouvrir le secret écrit son clair sur le disque. Il vaut mieux l'ouvrir dans un dossier lui-même chiffré, ou **en mémoire** : `janus dechiffrer … -` vérifie tout en mémoire et écrit sur la sortie standard, sans créer de fichier en clair.
7. **La ligne de commande doit rester muette.** Aucune option, aucun message, aucun code de retour ne doit différer selon qu'il existe un visage caché.
8. **Un même fichier peut montrer deux contenus à deux destinataires.** Un auteur malveillant peut mettre Alice dans un visage et Bob dans l'autre. Comparer l'empreinte du fichier chiffré ne prouve donc pas qu'on a lu la même chose : il faut comparer l'empreinte **du clair**. C'est le prix du déni, et c'est borné à deux contenus ([05-preuve-integrite.md](05-preuve-integrite.md), § 7.1).
9. **Un tiers peut effacer le secret sans que le leurre s'en aperçoive.** Il lui suffit d'écraser la réserve. Garde une copie, et vérifie de temps en temps, avec le second identifiant, que le secret s'ouvre encore ([05-preuve-integrite.md](05-preuve-integrite.md), § 7.2).

---

## 11. Ce qui existe ailleurs

| Système | Niveau | Différence avec Janus |
|---|---|---|
| VeraCrypt, volumes cachés | volume disque | Mono-utilisateur, pas post-quantique, pas un fichier qu'on envoie |
| Shufflecake (2023) | volume disque Linux | Plusieurs niveaux cachés, mais pour des disques, pas pour des fichiers |
| Rubberhose (1997) | disque | Ancêtre du principe, abandonné |
| « Deniable encryption » (Canetti, Dwork, Naor, Ostrovsky, 1997) | théorie | Une autre notion : l'expéditeur fabrique un faux aléa |
| age, gpg | fichier | Aucun déni. Leurs en-têtes affichent d'ailleurs outil et destinataires (voir `janus inspect`) |

À notre connaissance, aucun format de **fichier** ne combine le déni à deux visages, le chiffrement post-quantique hybride, plusieurs destinataires par visage et une indistinguabilité totale pour les tiers. C'est la fonction que les autres outils n'ont pas (décision D-1).

---

## 12. Ligne de commande proposée

```
janus chiffrer -m vacances.zip coffre.janus --cache -m journal.txt
janus chiffrer -R moi.pub rapport.pdf coffre.janus --cache -R moi-secret.pub notes.md
janus dechiffrer -m coffre.janus sortie        ouvre le visage qui correspond au mot de passe saisi
```

Tout ce qui suit `--cache` décrit le visage caché : ses destinataires, puis son fichier d'entrée. `dechiffrer` ne change pas : il ouvre le visage correspondant à l'identifiant donné, sans jamais signaler l'autre.

---

## 13. Tests prévus

- **Vue contrainte** : sur des paires de fichiers construits avec le même leurre, avec et sans secret, appliquer à tout ce que l'adversaire ne peut pas ouvrir (étiquette inutilisée, emplacements libres, réserve) les tests χ² et, plus tard, NIST STS. Comparer aussi les lois de taille, qui doivent être **identiques**. *Fait (`tests/visages.rs`) : test d'homogénéité du χ² sur 7,5 millions d'octets, p = 0,31, avec un témoin de puissance ; lois de taille identiques. NIST STS reste à faire.*
- **dudect** : ouverture du leurre dans un fichier avec et sans visage caché. *Fait : |t| = 1,34 sur 1 000 mesures.*
- **Fonctionnels** : chaque identifiant ouvre son visage et seulement le sien, refus R5, frontières de capacité (`c(L₂) = Réserve` accepté, `+1` refusé), leurre vide. *Fait.*
- **Robustesse** : les mutations dans la réserve ne gênent pas le leurre, mais font échouer le secret ; toute troncature ou tout ajout fait échouer les deux ; reprise du fuzzing par mutations. *Fait : 50 000 mutations (19 novembre 2026, après les correctifs issus des preuves), jamais un autre clair.*
- **Vecteurs v1**, dont un fichier à deux visages publié avec ses deux mots de passe. *Fait : `janus-rs/vecteurs/deux-visages.janus`.*
- **`inspect`** : nouvelle hypothèse « fichier Janus v1 » avec la plage de `L₁`. *Fait, avec la capacité du visage caché possible.*

---

## 14. Questions à trancher

| N° | Question | Recommandation |
|---|---|---|
| **QB-1** | Taille de la réserve : fixe (64 Kio), `max(64 Kio, L₁/16)` ou `max(64 Kio, L₁/8)` ? | **Décidé le 18 novembre 2026 : `Réserve = max(64 Kio, ⌈L₁/16⌉)`**, soit `R_min` = 65 536 et `ρ` = 16. Environ 6 % de plus par fichier, de quoi cacher un document, et un secret de 64 Kio possible même derrière un petit leurre |
| *QB-2 à QB-4* | *Recommandations ci-dessous adoptées provisoirement pour le prototype* | |
| **QB-2** | Une option « sans réserve » ? Elle produirait des fichiers dont on peut prouver qu'ils n'ont pas de visage caché | Pas en v1. Si elle existe, la réserve doit rester le comportement par défaut, pour que « j'ai utilisé le réglage par défaut » reste une réponse crédible |
| **QB-3** | 2 ou 4 étiquettes (donc visages) ? | 2 pour v1, fidèle au nom. Le passage à 4 ne coûte que 64 octets et pourra se décider après le prototype |
| **QB-4** | v1 remplace-t-il v0 ? | Oui : v0 n'est ni figé ni diffusé, et une structure unique est le cœur du déni |
| **QB-5** | Preuve formelle | **Rédigée : [04-preuve-deux-visages.md](04-preuve-deux-visages.md)** (preuve papier par séquence de jeux, non vérifiée par machine). Elle a révélé que le scalaire éphémère clampé du code casse le déni face à un adversaire quantique, et que la discrétion repose sur MLWE seul. Correctifs proposés au § 8 de ce document |
