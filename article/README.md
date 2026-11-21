# Article

[`janus.tex`](janus.tex), en anglais, et le PDF compilé [`janus.pdf`](janus.pdf) (10 pages) : *Janus: Post-Quantum File Encryption with Uniform Ciphertexts and Deniable Hidden Faces*. Il résume pour des cryptographes la conception, les preuves (documents 04 à 06 et 09), la vérification par CryptoVerif, l'analyse de la taille et l'implémentation, dans le but d'obtenir une relecture.

## Compiler

Avec une distribution LaTeX (paquets `latex-base`, `latex-recommended`, `latex-extra`, `fonts-recommended`, `science`) :

```bash
latexmk -pdf janus.tex
```

La bibliographie est écrite à la main dans le fichier : pas de BibTeX à lancer.

## Soumettre à IACR ePrint

La soumission se fait à la main, par l'auteur :

1. Créer un compte sur https://eprint.iacr.org (menu *Submit*).
2. Renseigner :
   - le titre ;
   - l'auteur, `moideici` ;
   - le résumé (celui du PDF, éventuellement raccourci) ;
   - les mots-clés : *file encryption, post-quantum, hybrid KEM, deniable encryption, Elligator, Kemeleon, X-Wing, CryptoVerif, padding* ;
   - la catégorie *Applications* ou *Public-key cryptography*.
3. Joindre `janus.pdf`, et accepter la licence de diffusion proposée (CC BY recommandée).
4. Une fois l'article en ligne, mettre son numéro (`2026/xxxx`) dans le README du dépôt et sur le site de documentation.

Les relecteurs les plus pertinents sont les auteurs des briques utilisées (X-Wing, Kemeleon, CryptoVerif, PADMÉ) et la liste CFRG de l'IETF.
