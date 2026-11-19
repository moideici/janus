# Janus : confidentialité face aux fichiers piégés (recollement IND-CCA)

*Brouillon 0.1, 19 novembre 2026. Preuve « papier », non vérifiée par machine et non relue. Elle assemble les documents [04](04-preuve-deux-visages.md) (confidentialité passive, déni) et [05](05-preuve-integrite.md) (intégrité).*

## 0. En bref

**La question.** Un attaquant t'envoie des fichiers qu'il a fabriqués ou modifiés, puis observe ce que donne leur ouverture : un clair, ou « impossible de déchiffrer ». Peut-il en tirer des informations sur **un autre** fichier, que tu as chiffré et qu'il possède sans pouvoir l'ouvrir ? C'est la notion classique d'**IND-CCA** (chiffrés choisis).

**La réponse, en trois points.**

1. **Janus n'est pas IND-CCA au sens strict, et ne peut pas l'être avec deux visages.** L'attaquant modifie un octet de la réserve du fichier défi et te le fait ouvrir. Tu obtiens le même clair, et lui aussi s'il voit le résultat. Le jeu IND-CCA strict compte cela comme une victoire, alors que l'attaquant n'a rien appris de plus qu'en te faisant ouvrir l'original. Cette **malléabilité bénigne** est le prix du déni : la réserve ne doit pas être couverte par le leurre (§ 1).
2. **Janus est IND-RCCA** (*Replayable CCA*, Canetti, Krawczyk, Nielsen, 2003). C'est la notion faite exactement pour ce cas. L'attaquant peut fabriquer une autre version d'un fichier qui donne **le même** clair, mais aucune qui donne un clair **lié** au premier. Le théorème du § 4 le prouve, avec une borne négligeable.
3. **Une condition d'usage : jeter la sortie d'une ouverture ratée.** `dechiffrer_flux` écrit les lots vérifiés au fur et à mesure. Un fichier piégé peut donc faire sortir un préfixe **authentique** du clair avant d'échouer. La ligne de commande et `dechiffrer` (en mémoire) jettent cette sortie, et la preuve tient pour eux. Un programme tiers qui utiliserait `dechiffrer_flux` doit faire de même (§ 5).

> **En clair.** Janus te protège contre quelqu'un qui tripote tes fichiers pour en apprendre le contenu. La seule chose qu'il peut faire, c'est produire une autre copie qui donne exactement le même contenu. Ça ne lui apprend rien qu'il ne saurait déjà en te faisant ouvrir l'original.

---

## 1. Pourquoi IND-CCA strict est impossible avec deux visages

**L'attaque contre le jeu strict.**
1. L'attaquant reçoit le fichier défi `f*`, qui chiffre `M₀` ou `M₁`.
2. Il inverse un bit dans la réserve, ou dans l'étiquette de l'autre visage, et obtient `f' ≠ f*`.
3. Il demande l'ouverture de `f'`, qu'il a le droit de demander puisque `f' ≠ f*`. Il reçoit `M_b` et gagne.

**Pourquoi on ne peut pas l'empêcher.** Pour que `f'` échoue, l'étiquette du visage défi devrait couvrir :
- **la réserve**, ce qui est possible (§ 6, option) ;
- **l'autre étiquette**, ce qui est impossible pour les deux visages à la fois. Si `T_0` couvre `T_1`, alors `T_1` ne peut pas couvrir `T_0`, car chacune devrait être calculée avant l'autre.

Au moins un visage reste donc toujours malléable sur l'étiquette de l'autre. Pour supprimer cette malléabilité, il faudrait une seule étiquette, donc un seul visage.

**Pourquoi ce n'est pas grave.** La modification ne change jamais le clair (document 05, cas a). L'attaquant obtient une **rediffusion** du message défi, pas un message lié. C'est exactement ce que la notion RCCA tolère, et rien de plus.

---

## 2. Le jeu IND-RCCA

```
Jeu RCCA_b(𝒜) :
  1. Le défi crée les identités honnêtes (sk_j, pk_j) et donne les pk_j à 𝒜.
     Pour un visage protégé par mot de passe : m ← D, d'entropie minimale h.
  2. 𝒜 choisit M₀, M₁ de même longueur, et la place du visage défi
     (principal ou caché). Il choisit librement l'AUTRE visage, s'il y en a un :
     son contenu et ses identifiants, qu'il connaît (R5 respectée).
  3. f* ← Chiffrer(…, M_b pour le visage défi avec les identifiants honnêtes, …)
  4. 𝒜 reçoit f*. Il a accès, avant et après, à :
       Ouvrir(f) : ouvre f avec les identifiants honnêtes et renvoie
                   « test »               si le clair obtenu est M₀ ou M₁,
                   le clair               sinon,
                   ⊥ ou « plusieurs visages »  en cas d'échec.
     et aux oracles aléatoires (HKDF, SHA3, SHAKE, Argon2id).
  5. 𝒜 renvoie b'.
```

- **Ce que change RCCA.** L'oracle refuse de répondre seulement quand le clair **est** l'un des deux messages défis. Il répond normalement pour tout autre clair, même si le fichier soumis ressemble à `f*`.
- **Ce que l'attaquant peut faire de plus que dans le document 04** : soumettre autant de fichiers fabriqués qu'il veut et voir leur ouverture.
- **L'ouverture est « atomique ».** Elle renvoie le résultat final, sans préfixe partiel. Le § 5 traite le cas de la sortie en flux.

---

## 3. Hypothèses

Ce sont celles des documents 04 (H1 à H7) et 05 (I1 à I6), plus deux renforcements standard.

| N° | Hypothèse | Pourquoi elle est nécessaire ici |
|---|---|---|
| C1 | **ML-KEM-768 est IND-CCA** (transformée de Fujisaki-Okamoto avec rejet implicite, sous MLWE et dans le modèle de l'oracle aléatoire) | L'attaquant fait décapsuler des emplacements de son choix |
| C2 | **gap-DH sur Curve25519** : le problème Diffie-Hellman reste difficile même avec un oracle qui *décide* si un triplet est Diffie-Hellman | La même raison, pour la moitié X25519. C'est l'hypothèse de la preuve IND-CCA d'X-Wing |
| C3 | **ChaCha20-Poly1305 est un chiffrement authentifié** (IND$ et INT-CTXT à la fois) | Les emballages `w` et les blocs peuvent être soumis modifiés à l'oracle |

Comme dans le document 04, **un seul** des deux chemins C1 et C2 sert à la fois : la confidentialité reste hybride.

---

## 4. Théorème : Janus est IND-RCCA

**Énoncé.** Pour tout adversaire `𝒜` faisant `q_O` appels à l'oracle d'ouverture, `q_H` requêtes aux oracles de hachage et `q_A` requêtes à Argon2id, avec `n` destinataires honnêtes dans le visage défi :

```
Adv^RCCA(𝒜) ≤ n · min( Adv^IND-CCA_ML-KEM + Adv^MLWE + ε_K , Adv^gapDH )     (G₁, clé publique)
            + (q_A + 2·q_O) / 2^h                                             (G₁, mot de passe)
            + n · ε_E                                                         (G₂)
            + n · (Adv^IND$_AEAD + q_O · Adv^INT-CTXT_AEAD)                   (G₃)
            + q_O · (Adv^MAC_HMAC + Adv^INT-CTXT_STREAM) + Adv^CR_SHA-256      (G₄)
            + Adv^PRF_HMAC + Adv^IND$_AEAD                                    (G₅, G₆)
            + O(q_H · (q_O + n) / 2²⁵⁶)
```

Tous les termes sont négligeables, sauf pour un visage à mot de passe. Celui-ci vaut ce que vaut le mot de passe : `q_A` essais hors ligne, plus **au plus 2 essais par ouverture** que tu acceptes de faire (théorème 4 du document 05).

### 4.1 La séquence de jeux

On part de `RCCA_b` et on arrive à un jeu où `f*` ne dépend plus de `b`. La difficulté nouvelle par rapport au document 04 : il faut répondre à l'oracle d'ouverture **sans les clés secrètes honnêtes**, ou du moins sans la partie que l'on remplace par de l'aléa.

**G₀.** Le jeu `RCCA_b`.

**G₁. Le secret de chaque emplacement défi devient aléatoire, et l'oracle reste cohérent.**
Pour chaque destinataire honnête `j` du visage défi, `ss*_j` devient `U₃₂`. L'oracle l'utilise chaque fois qu'un emplacement soumis se décapsule vers le **même chiffré** que l'emplacement défi. Les modifications bénignes, comme les bits hauts de `r`, les doublons Kemeleon ou le masque, y conduisent toutes.

Deux chemins, dont un seul suffit, comme au document 04 :

- **Chemin ML-KEM (C1).** `B` fabrique lui-même la clé X25519 honnête, donc il connaît `sk_X`. Il reçoit la clé ML-KEM du défi et un oracle de décapsulation ML-KEM. Pour un emplacement soumis `(r', κ')`, il procède ainsi :
  1. il calcule `ct'_X` depuis `r'` ;
  2. il calcule `ss'_X = X25519(sk_X, ct'_X)`, puis démasque `κ'` et décode `ct'_M` ;
  3. si `ct'_M = ct*_M`, il prend `ss*_M` ; sinon, il interroge l'oracle ML-KEM ;
  4. il combine le tout.

  La simulation est parfaite. Le `κ*` du défi est ensuite rendu aléatoire par MLWE, comme au document 04.

- **Chemin X25519 (C2).** `B` fabrique lui-même la clé ML-KEM honnête et reçoit le défi Diffie-Hellman. Il ne connaît pas `ss'_X = sk_X · ct'_X`, mais cette valeur est **entièrement déterminée par `ct'_X`**. `B` tient donc deux tables, indexées par `ct'_X` :
  - une pour le masque de `κ'` ;
  - une pour la sortie du combineur.

  Il les remplit au hasard à la première utilisation. Quand `𝒜` interroge lui-même l'oracle SHAKE ou SHA3 sur `(Z, ct'_X, …)`, `B` demande à l'oracle de décision Diffie-Hellman si `Z = sk_X · ct'_X`. Si oui, il renvoie la valeur de la table.

  Avec le masque ainsi tiré, `B` peut démasquer `κ'`, décoder `ct'_M` et décapsuler avec sa propre clé ML-KEM. Un `𝒜` qui interrogerait l'oracle sur le vrai `ss*_X` du défi aurait résolu gap-DH.

  **Le masquage de `κ` est compatible avec la preuve IND-CCA** précisément parce que sa clé ne dépend que de `ct_X`, ce qui permet à `B` de la tirer sans connaître `sk_X`.

- **Visage défi à mot de passe.**
  - `A* = Argon2id(m, sel*)` devient `U₃₂`. Cela n'est visible que si `𝒜` interroge Argon2id sur `(m, sel*)`, avec une probabilité d'au plus `q_A / 2^h`.
  - L'oracle d'ouverture, lui, calcule `Argon2id(m, sel')` pour les `sel'` des fichiers soumis. Le résultat d'une ouverture dépend du mot de passe pour **au plus 2** candidats (théorème 4 du document 05), d'où le terme `2·q_O / 2^h`.

**G₂. Le représentant `r*` devient aléatoire** : statistique (H6), comme au document 04.

**G₃. Les emballages `w*` deviennent aléatoires**, et l'oracle reste cohérent.
- La clé d'emballage `HKDF(ss*_j, j)` est maintenant uniforme, et elle ne chiffre qu'une fois.
- On passe au monde « idéal » du chiffrement authentifié. `w*_j` est remplacé par de l'aléa, et l'oracle **mémorise** que `w*_j`, sous cette clé, se déballe en `K* ‖ d* ‖ l*`. Tout autre `w'` soumis sous cette clé donne `⊥`.
- L'écart avec le monde réel est l'avantage contre IND$ (pour `w*`) et contre INT-CTXT (pour les `w'` modifiés).

**G₄. Toute ouverture qui retrouve `K*` répond « test ».**
- Depuis G₃, `K*` n'est plus visible qu'à travers l'étiquette `T*` et le corps du visage défi.
- Un fichier soumis qui redonne `K*` est, par le document 05 (cas a), soit rejeté, soit ouvert sur `M_b`, sauf contrefaçon de l'étiquette ou du flux sous `K*`. Dans le jeu réel, la réponse était donc déjà « test » ou `⊥`.
- Il reste un cas à vérifier : celui où `K*` est retrouvé, mais où un **autre** triplet valide fait répondre « plusieurs visages ». Le jeu peut le calculer sans connaître `b`, car `(K*, d*, l*)` ne dépend pas de `b`.
- L'oracle n'utilise donc plus jamais `K*` pour déchiffrer.

**G₅. L'étiquette `T*` devient aléatoire** : HMAC est une PRF, et sa clé `HKDF(K*, « entete »)` est uniforme et ne sert plus qu'une fois.

**G₆. Le flux du visage défi devient aléatoire** : IND$ de ChaCha20-Poly1305 sous `HKDF(K*, « corps »)`, avec des nonces distincts.

**Fin.** Dans G₆, `f*` ne contient plus rien qui dépende de `b`. Sa taille dépend de `|M_b|`, et `|M₀| = |M₁|`. L'oracle ne déchiffre plus jamais avec `K*`, et ses autres réponses ne dépendent pas de `b`. L'avantage de `𝒜` dans G₆ est donc nul. ∎

### 4.2 Remarques

- **Plusieurs destinataires.** L'argument hybride sur les `n` emplacements est le même qu'au document 04.
- **L'autre visage**, choisi par `𝒜`, est simulé honnêtement, puisque `𝒜` en connaît tout. Ce sont les tests R5 qui empêchent qu'il partage une clé ou un mot de passe avec le visage défi.
- **Le déni et RCCA se combinent.** Les jeux G₁ à G₆ sont ceux du document 04, enrichis de l'oracle. Le déni reste donc vrai face à un adversaire qui te fait ouvrir des fichiers piégés **avec l'identifiant du leurre**, puisqu'il possède déjà cet identifiant.

---

## 5. La sortie en flux : une condition d'usage

**Le constat.**
- `dechiffrer_flux` déchiffre lot par lot et écrit chaque lot **vérifié** dans `sortie`, avant d'avoir lu la suite du fichier.
- Un attaquant soumet `f*` dont il a abîmé le **dernier** bloc. L'ouverture échoue à la fin, mais elle a déjà écrit `M_b` presque entier.
- Si l'attaquant voit cette sortie partielle, il a gagné.

**Pourquoi ce n'est pas une faille de construction.**
- Le préfixe sorti est **authentique** : c'est un vrai morceau de `M_b`.
- L'attaquant l'obtient en **rediffusant** une partie de `f*`. C'est le même phénomène que la rediffusion entière, que RCCA neutralise en répondant « test ».
- La notion en ligne qui correspond (nOAE, Hoang, Reyhanitabar, Rogaway, Vizár, 2015) traite les préfixes de la même façon.

**La condition.** La garantie RCCA vaut pour une ouverture **atomique**, qui rend tout ou rien :
- **La ligne de commande l'est** : elle écrit dans un fichier temporaire, supprimé en cas d'échec (J-06).
- **`dechiffrer` (en mémoire) l'est** : il ne rend le tampon qu'en cas de succès.
- **`dechiffrer_flux` ne l'est pas.** Son appelant doit jeter tout ce qui a été écrit si la fonction renvoie une erreur. C'est déjà écrit dans sa documentation. Il faudra le répéter en tête de la bibliothèque si elle est publiée.

---

## 6. Ce que la preuve a révélé, et une option

**Constats.**
1. **La notion exacte est RCCA, et non CCA.** C'est inévitable avec deux étiquettes (§ 1). Ce n'était écrit nulle part : le document 05 annonçait seulement le recollement IND-CCA.
2. **Le masquage de `κ` est compatible avec IND-CCA**, ce qui n'allait pas de soi : sa clé ne dépend que de `ct_X` (§ 4.1, chemin X25519). Il faut le conserver ainsi. Faire dépendre le masque d'autre chose, par exemple de `κ` lui-même, casserait la simulation.
3. **La condition d'usage sur la sortie en flux** (§ 5).
4. **Aucun défaut d'implémentation nouveau.** Les erreurs liées au contenu donnent toutes la même réponse, « impossible de déchiffrer ». Seules les vraies erreurs d'entrée-sortie (disque plein, par exemple) diffèrent, et un attaquant distant ne les contrôle pas.

**Option à trancher (QI-1) : faire couvrir tout le corps par chaque étiquette.**
- *Gain.* Toute modification de la réserve serait détectée par le leurre. L'effacement silencieux du secret (document 05, § 7.2) deviendrait un effacement **visible**. Le déni n'en souffre pas : dans un fichier sans secret, la réserve aléatoire serait couverte de la même façon.
- *Ce qu'elle n'apporte pas.* IND-CCA strict, à cause de l'autre étiquette (§ 1).
- *Coût.*
  - Il faudrait hacher tout le corps à chaque ouverture, y compris celle du secret, ce qui diviserait environ par deux le débit sur un cœur.
  - L'écriture demanderait de revenir au début du fichier pour y placer les étiquettes. La sortie devrait donc permettre les déplacements (`Seek`), ou bien les étiquettes devraient aller en fin de fichier.
  - Le format changerait.
- *Recommandation :* **ne pas le faire pour l'instant**. Le gain est réel mais modeste, et une sauvegarde suffit à se prémunir contre l'effacement.

---

## 7. Bilan des trois preuves

| Propriété | Notion | Document | Hypothèses principales |
|---|---|---|---|
| Confidentialité passive, discrétion, déni | IND$ et DENI | 04 | MLWE **ou** gap-DH ; Elligator statistique |
| Engagement, cohérence par visage, intégrité par visage | collisions, INT-CTXT | 05 | SHA-256, HMAC, ChaCha20-Poly1305 |
| Confidentialité face aux fichiers piégés | **IND-RCCA** | 06 | les précédentes, plus IND-CCA de ML-KEM **ou** gap-DH |

**Ce qui manque encore pour une confiance sérieuse :**
- la vérification par machine (CryptoVerif) ;
- le modèle quantique de l'oracle aléatoire (QROM) ;
- la relecture par un cryptographe.
