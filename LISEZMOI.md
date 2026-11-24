# Vigie

Diagnostic de sécurité pour petites entreprises. Version 0.1.0 (socle).

Vigie lance des contrôles, traduit les résultats en français de patron et
produit un rapport : une page à imprimer, un texte et un fichier de données.

## Règles d'usage

1. Vigie ne s'utilise que sur la société d'un client qui a donné son accord écrit.
2. Un contrôle « actif » (scan de ports, recherche de failles) ne se lance
   jamais sans autorisation signée. Vigie le refuse sans le fichier.
3. La recherche des comptes du dirigeant exige ses pseudos, donnés par lui,
   et son accord écrit. Jamais sur un tiers.
4. Chaque rapport est relu par un humain avant d'être envoyé.

## Démarrer

Il faut Python 3.9 ou plus récent. Aucune autre installation pour le socle.

    cd vigie
    python3 -m unittest discover -s tests        # les essais : tout doit finir par OK
    python3 -m vigie diagnostic exemple.fr --societe "Nom de la société"
    python3 -m vigie interface                   # Vigie dans le navigateur

Les rapports arrivent dans le dossier `rapports/`.

### Sur le téléphone

    python3 -m vigie interface --reseau-local

Vigie affiche une adresse avec un code. Ouvrez-la sur le téléphone, connecté
au même Wi-Fi que l'ordinateur. Le moteur tourne sur l'ordinateur, le téléphone
sert d'écran. Pour l'utiliser hors de chez soi, il faudra un hébergement :
ce sera une étape ultérieure.

## Les commandes

| Commande | Rôle |
| --- | --- |
| `python3 -m vigie diagnostic domaine.fr` | Lance le diagnostic et écrit les rapports |
| `python3 -m vigie interface` | Ouvre Vigie dans le navigateur |
| `python3 -m vigie modules` | Liste les contrôles disponibles |
| `python3 -m vigie outils` | Liste les outils externes : installés, branchés, licence |

Options utiles de `diagnostic` : `--societe`, `--complet` (les 42 outils du diagnostic
gratuit, 30 min à 1 h), `--modules mail,site` ou `--modules tous`, `--pseudo` et `--accord-dirigeant`, `--autorisation fichier.pdf`,
`--sortie dossier`.

## Ce qui existe

| Module | Bloc | Ce qu'il contrôle | Besoin |
| --- | --- | --- | --- |
| `mail` | Exposition | Peut-on envoyer un faux mail au nom de la société (SPF, DKIM, DMARC) | Rien |
| `checkdmarc` | Exposition | 2e avis mail, plus MTA-STS, rapports TLS, DNSSEC | checkdmarc |
| `site` | Exposition | Certificat, chiffrement, protections de base du site | Rien |
| `chiffrement` | Exposition | Versions du chiffrement acceptées (sans test de faille) | SSLyze |
| `qualite_site` | Exposition | Protections et vitesse de la page, vues par Chrome | Lighthouse + Chrome |
| `technos` | Exposition | Logiciels visibles (WordPress, PHP…), autres sites qui répondent | httpx |
| `sousdomaines` | Exposition | Adresses annexes de la société, sources publiques | Subfinder |
| `domaines` | Exposition | Domaines imitateurs enregistrés | dnstwist[full] |
| `archives` | Exposition | Fichiers sensibles gardés par les archives d'internet | gau |
| `metadonnees` | Exposition | Noms, logiciels, GPS cachés dans les fichiers publiés (comptés, jamais listés) | ExifTool |
| `adresses` | Exposition | Adresses mail visibles publiquement (comptées, sans source de fuite) | theHarvester |
| `apercu` | — | Capture de la page d'accueil, en tête du rapport | gowitness + Chrome |
| `pseudos` | Exposition | Comptes publics du dirigeant, via Sherlock | Pseudos et accord écrit |

### Diagnostic complet (24/11/2026)

Choix par défaut dans l'interface (« Complet »), ou `--complet` en commande. Il lance
**les 42 outils de la famille « diagnostic gratuit »**, 6 à la fois (2 au plus qui
ouvrent Chrome), avec un délai par outil. Chaque outil reçoit l'entrée qu'il attend,
tirée du domaine (`vigie/indices.py`) : comptes de réseaux sociaux affichés sur le
site, nom de la société, numéros affichés (en mémoire seulement), adresses annexes
trouvées par Subfinder et Amass. Nouveaux contrôles : `vigie/modules/complet.py`
(Amass passif, dnsx, WhatWeb, sitespeed.io, EyeWitness, uncover, Metagoofil, Exiv2,
Instaloader, PhoneInfoga, ArchiveBox, GHunt, et Sherlock/Maigret/user-scanner/Social
Analyzer sur le nom de la société).

Le rapport technique finit par **une ligne par outil des 42** (`vigie/diag_gratuit.py`) :
lancé (avec sa durée), à installer, pas réalisé (et pourquoi), pas lançable ici
(service, appli, extension…) ou écarté par la règle légale (Robin : dark web).

Tous sont lancés par défaut, sauf `pseudos` et `conformite`. Un outil absent ne bloque
rien : son contrôle est listé « non réalisé ». Premier essai réel complet : 21/11/2026
sur pavillon-noir.tech.

## Comment c'est rangé

    vigie/
      modeles.py        le vocabulaire : Cible, Constat, niveaux, note
      reseau.py         tout ce qui sort vers internet
      outils.py         le catalogue des outils externes et leur lancement
      autorisation.py   le garde-fou des contrôles actifs
      rapport.py        la mise en forme (texte, page imprimable, données)
      cli.py            la commande
      interface.py      l'écran dans le navigateur
      modules/          un fichier par contrôle
    tests/              les essais, sans internet

## Brancher un outil GitHub

Vigie ne copie le code d'aucun outil. Il appelle les outils installés sur la
machine. Trois raisons : chaque outil garde sa licence, se met à jour seul,
et Vigie continue de marcher quand l'un d'eux manque.

1. Inscrire l'outil dans `CATALOGUE` (fichier `vigie/outils.py`).
2. Écrire un adaptateur dans `vigie/modules/` : il appelle `outils.executer()`
   et traduit ce que l'outil affiche en constats. Modèle : `modules/pseudos.py`.
3. Inscrire l'adaptateur dans `vigie/modules/__init__.py`.
4. Ajouter un essai avec une sortie d'exemple dans `tests/`.

## Les étapes

| Semaine | Livrable |
| --- | --- |
| 21 au 28 novembre | Bloc exposition : sous-domaines (subfinder), domaines imitateurs (dnstwist), adresses visibles (theHarvester), fuites de données |
| 29 novembre au 5 décembre | Scan externe sur autorisation : sites (httpx), ports (naabu), failles connues (nuclei), chiffrement (sslscan). Autorisation type |
| 6 au 12 décembre | Bloc accès et bloc réseau et postes : questionnaire, Lynis, HardeningKitty, Maester |
| 13 au 19 décembre | Bloc sauvegardes, fiche assureur, rapport final en PDF |
| 20 au 26 décembre | 3 diagnostics complets sur de vraies sociétés, corrections |
| 27 décembre au 3 janvier | Démo, vidéo, devis |
| 4 janvier | Lancement |

## Limites connues de la version 0.1.0

- Les contrôles réseau n'ont pas encore tourné sur un vrai domaine.
- La signature DKIM est cherchée sous 15 noms courants. Une signature rangée
  sous un autre nom n'est pas vue : le rapport le dit.
- Sherlock donne parfois de faux résultats : le rapport demande une
  confirmation compte par compte.
- Les licences du catalogue viennent du relevé du 20/11/2026. Celle de
  Sherlock a été vérifiée. Les autres sont à relire avant un usage commercial.
