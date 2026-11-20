# Politique de sécurité

## Statut

Janus est un **prototype de recherche** :
- son format est candidat au gel, mais pas définitivement gelé ;
- son code n'a eu aucun audit externe ;
- ses preuves de sécurité n'ont été relues par personne.

**Ne l'utilise pas pour de vrais secrets.** Toutes les versions 0.x sont des aperçus, et seule la dernière reçoit des correctifs.

## Vérifier un binaire

Les releases à partir de la v0.2.0-alpha portent une attestation de provenance Sigstore, et le binaire Linux est reproductible ([docs/08](docs/08-durcissement.md), § 5) :

```bash
gh attestation verify <archive> --repo moideici/janus
```

## Signaler une faille

Une faille dans un outil de chiffrement peut exposer des données. Merci de la signaler **en privé** avant toute publication :

1. Ouvre l'onglet **Security** du dépôt [moideici/janus](https://github.com/moideici/janus), puis **Report a vulnerability**. Cela crée un avis de sécurité privé, visible seulement par le mainteneur.
2. Décris :
   - la version (`janus --version`) ;
   - la propriété en cause : confidentialité, intégrité, discrétion, déni ou temps constant ;
   - un fichier ou un scénario qui la met en défaut, si possible.

Tu peux t'attendre à une première réponse sous 7 jours. Une fois la faille corrigée, ou au bout de 90 jours, elle peut être publiée, en te citant si tu le souhaites.

## Ce qui est particulièrement bienvenu

- Une erreur dans une des preuves ([`docs/04`](docs/04-preuve-deux-visages.md), [`05`](docs/05-preuve-integrite.md), [`06`](docs/06-preuve-confidentialite-active.md)).
- Un moyen de **distinguer** un fichier Janus de l'aléa, ou un fichier à deux visages d'un fichier à un seul, avec l'identifiant du leurre.
- Une fuite de temps que les mesures dudect n'auraient pas vue.
- Un fichier piégé qui fait paniquer `janus`, ou qui rend un clair différent de l'original.

## Ce qui n'est pas une faille

Les limites documentées ne sont pas des failles :
- l'absence d'IND-CCA strict ;
- deux contenus pour deux visages ;
- l'effacement du visage caché par un tiers ;
- la taille du clair connue à quelques pour cent près.

Elles sont décrites dans les documents [05](docs/05-preuve-integrite.md) et [06](docs/06-preuve-confidentialite-active.md).
