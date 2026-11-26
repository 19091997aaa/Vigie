# Vigie — contexte pour Claude Code

Vigie est un logiciel de **diagnostic de cybersécurité pour TPE/PME françaises**.
Il lance des contrôles, traduit les résultats en « français de patron » et produit
un rapport (page imprimable, texte, données). Développeur : **Anass**, solo.

> Ce fichier est le point d'entrée. Pour le détail technique et la feuille de route
> semaine par semaine, voir **`LISEZMOI.md`**. Pour les décisions produit prises avec
> Anass (format du livrable, accroches, critères de tri des outils), voir **`VISION.md`**.
> Pour le marché, la cible et surtout le **cadre légal du diag gratuit**, voir **`MARCHE.md`**.
> Pour le positionnement (« le cyber accessible, comme un plombier ») et la première
> niche (cabinets comptables), voir **`POSITIONNEMENT.md`**.

## Comment travailler ici (IMPORTANT)

- **Réponds toujours en français**, direct, concis, phrases courtes. Anass a un
  **très faible niveau d'anglais** : rien en anglais, et traduis tout texte étranger.
- **Zéro ligne de code pour Anass.** L'objectif est : il clique un bouton, ça marche
  (« un bouton = boum »). Il pilote Vigie par l'**interface web**
  (`python3 -m vigie interface`) ou les installeurs double-clic
  (`installer-mac.command`, `installer-windows.ps1`). Quand une commande est
  inévitable, tu la lances toi-même ou tu la mets dans un script double-cliquable —
  tu ne lui fais pas taper des lignes.
- Explique simplement, montre les résultats, finis par **une seule** prochaine action.
- Avant d'exécuter, signale en une ligne tout risque légal/fiscal.
- Chiffres : en toutes lettres seulement s'il te parle en vocal (sinon il les entend
  en anglais) ; à l'écrit, chiffres normaux.

## Le produit

Deux offres :
1. **Diagnostic externe GRATUIT** — à partir d'**informations publiques uniquement**
   (OSINT passif). C'est l'accroche commerciale : révéler au dirigeant un problème
   concret et tangible, pour donner envie de la sécurisation.
2. **Sécurisation (payant)** — durcissement / hardening après le diag.

Plus tard : **audit payant** = scan actif sur autorisation signée.

Cible : TPE/PME françaises. But d'Anass : activité à distance, nomade.

## Cahier des charges UX (priorité absolue)

Anass n'est pas développeur (il est TSSR). L'app doit respecter, sans compromis :

- **Tout en local sur son Mac.** Il lance tout depuis chez lui, en local — c'est assumé.
- **Un bouton = boum.** Il tape un domaine, il clique, ça part. **Aucune ligne de
  code, aucun jargon, aucun « blabla ».**
- **Il voit ce qui se passe en direct** : quel dépôt / outil tourne en ce moment, en clair.
- **Les outils s'enchaînent** automatiquement (pipeline), sorties agrégées.
- **Retranscription naturelle** : les sorties techniques brutes sont **traduites en
  langage clair** pour un non-technicien. C'est le rôle de `vigie/rapport.py` et
  `vigie/scenarios.py` — à soigner en priorité. Pas de sortie brute incompréhensible
  à l'écran : toujours « ce que ça veut dire » en français simple.
- **Interface claire et stylisée.** Le design fin viendra plus tard, mais ça doit
  être limpide dès maintenant.
- **Trouver les meilleurs combos d'outils** est un objectif central : lancer plusieurs
  dépôts sur la même cible, comparer les sorties, garder ceux qui rendent le mieux
  (`vigie/banc.py` / `vigie/comparaison.py`). On peut garder les 222 outils tant
  qu'ils s'enchaînent proprement et que leurs sorties restent lisibles.

## Les règles d'or (garde-fou légal — voir `vigie/autorisation.py`)

- Un **scan actif** (ports, failles) ne se lance **jamais sans autorisation signée**
  du client. Vigie le refuse sans le fichier (art. 323-1 du Code pénal).
- Le **diag gratuit** n'utilise que des sources **publiques / passives**.
- Les **outils offensifs** (famille GATE, voir plus bas) ne sont **jamais** dans un
  pipeline automatique ni dans le diag gratuit.
- **Les fuites de données (HIBP, dark web) ne sont PAS dans le diag gratuit à froid.**
  Chercher les adresses d'un prospect dans des fuites est interdit (CNIL : réutilisation
  de données de fuite interdite ; recel art. 321-1) tant qu'il n'a pas prouvé qu'il
  contrôle son domaine. → seulement **après son accord** et vérification de domaine
  (offre payante). Le gratuit à froid se limite à : DNS/email usurpable, typosquatting,
  exposition publique du site. Cadre complet : `MARCHE.md` §2.
- Chaque rapport est **relu par un humain** avant envoi.

## Où en est le code (socle v0.1.0)

Application Python structurée, mécanique fonctionnelle. Points d'entrée :
- `python3 -m vigie diagnostic domaine.fr --societe "..."` → lance le diag, écrit
  les rapports dans `rapports/`
- `python3 -m vigie interface` → **Vigie dans le navigateur** (+ `--reseau-local`
  pour piloter depuis le téléphone sur le même Wi-Fi)
- `python3 -m vigie modules` / `python3 -m vigie outils` → liste les contrôles et
  les outils externes (installés, branchés, licence)

Modules de contrôle déjà écrits (bloc Exposition) : `mail` (SPF/DKIM/DMARC),
`site` (TLS/certificat/en-têtes), `pseudos` (Sherlock), `domaines` (dnstwist),
`checkdmarc`, `conformite` (questionnaire assureur), et depuis le 21/11/2026 le
premier lot d'outils : `chiffrement` (SSLyze), `qualite_site` (Lighthouse),
`technos` (httpx), `sousdomaines` (Subfinder), `archives` (gau), `metadonnees`
(ExifTool), `adresses` (theHarvester), `apercu` (capture gowitness dans le rapport).
Tableau complet : `LISEZMOI.md`, « Ce qui existe ».

Règles apprises sur le premier vrai scan (21/11/2026) :
- **Une clé de constat = un seul problème.** Deux problèmes sous la même clé
  fusionnent et l'un disparaît du rapport (c'est arrivé avec DMARC).
- **Résolveurs publics** pour les outils (`reseau.SERVEURS_DNS`) : la box internet
  sature et met ~2 s par question.
- **Jamais installer un paquet sur son seul nom** (npm/PyPI) : 63 faux outils
  avaient été posés ainsi. `installeur.methodes()` n'essaie que la doc de l'outil
  et son dépôt exact.
- **Lighthouse** : pour les protections, lire le détail (`severity`), pas la note.
- **theHarvester** : uniquement `adresses.SOURCES` (aucune source de fuite) ;
  ExifTool et theHarvester **comptent** les noms, ne les listent jamais.

**Audits sur autorisation (21/11/2026)** : `vigie/mandat.py` prépare l'autorisation à
faire signer (`python3 -m vigie autorisation ...`) ; `vigie/manuel.py` lance un outil
actif (nmap, nuclei) seulement si la fiche couvre cible + test + date, avec le scan
signé et la cible retapée, et note tout dans `journal/lancements.jsonl` ;
`vigie/interface_manuel.py` = l'onglet « Outils manuels » de l'interface. Aucun outil
GATE branché : ils attendent le serveur d'entraînement d'Anass (à louer plus tard).
`vigie/ports.py` traduit un scan Nmap en français ; `essais/scanner-ma-maison.command`
scanne le réseau privé d'Anass, lancé par lui.

Brique de **sélection d'outils** — le cœur de la méthode d'Anass : lancer plusieurs
dépôts GitHub sur une même cible, comparer les sorties en chiffres, garder les
meilleurs. Fichiers : `vigie/lanceur.py`, `vigie/banc.py`, `vigie/comparaison.py`,
`vigie/decouverte.py` (devine la ligne de lancement d'un outil en lisant son aide).

Installation en masse des outils du catalogue : `vigie/installeur.py` +
`installer-mac.command` / `installer-windows.ps1` / `installer-linux.command`.
`vigie/presence.py` dit quels outils du catalogue sont **installés sur la machine**
(badge « installé » dans l'onglet « Lancer un outil », et `python3 -m vigie registre`).
Attention : **le nom d'un outil n'est pas toujours sa commande** (ClamAV → `clamscan`,
The Sleuth Kit → `fls`, Fail2ban → `fail2ban-client`) ; `vigie outils` ne liste que
la quarantaine d'outils de l'enchaînement automatique, pas les 216.

**Explications en français (24/11/2026)** : `vigie/fiches_outils.py` donne pour chaque outil lançable seul son rôle, la cible attendue (domaine, URL, pseudo, e-mail, téléphone, fichier, dossier, aucune) et son mode (cible / service / appli / Windows / capture / règles / compte / à la main). « Lancer un outil » vérifie la cible AVANT de lancer et explique en français si ça ne colle pas ; `vigie/erreurs.py` traduit les erreurs courantes des outils et des installations. La sortie brute reste dans « Détail technique ». Un message d'erreur non reconnu = ajouter un motif dans `erreurs.py`.

**Diagnostic complet (24/11/2026)** : demande d'Anass, les **42 outils du diag gratuit
tournent ensemble** (choix « Complet » par défaut dans l'interface, `--complet` en
commande). `cli.lancer` lance les contrôles en parallèle (6 à la fois, 2 Chrome au plus,
délai par contrôle, un plantage n'arrête plus le diagnostic). `vigie/indices.py` tire du
domaine les entrées des outils (réseaux sociaux du site, nom de la société, numéros —
jamais écrits). `vigie/modules/complet.py` = les nouveaux branchements.
`vigie/diag_gratuit.py` = une ligne par outil des 42 dans le rapport technique, y compris
ceux qui ne peuvent pas tourner (AdGuard Home, Pi-hole, Web-Check, Datashare, Flowsint,
InVID, geo-sleuth, IVRE, auto-archiver, Toutatis) et **Robin, écarté (dark web)**.

**Fiabilité du diag complet (24/11/2026, 1er complet sur la VM Ubuntu, 58/100)** :
- **Jamais un point « important » sur l'avis d'un seul outil réseau.** httpx « pas
  chiffré » est recoupé par `reseau.https_repond()` (2 essais) : oui = rien, non = important,
  pas de réponse claire = « à confirmer », hors note. SSLyze et WhatWeb réessaient une fois
  et disent si Vigie, lui, arrive à se connecter.
- Un outil muet dit **pourquoi** (`outils.pourquoi()` + `erreurs.py`), jamais « réinstaller ».
- dnstwist muet en 0 s = installé **sans dnspython** : Vigie le relance sur le DNS de la
  machine ; l'installeur ajoute le module. dnsrecon : repli sur le DNS de la machine.
- LinkChecker borné (4 min, 400 liens) ; les 4 outils de pseudo tournent **en parallèle**,
  5 min max chacun, résultat partiel gardé.
- `vigie/recettes.py` : installation à part des outils que la doc fait rater sous Ubuntu
  (EyeWitness, Metagoofil, PhoneInfoga, uncover, sitespeed.io et Unlighthouse avec un
  Node 22 posé à part, dnstwist + dnspython). Empreintes vérifiées, dépôt exact.

**Installeur Linux (25/11/2026, 1re install complète sur la VM Ubuntu, Python 3.14 :
93 prêts / 117 ratés)** : apt passe **un par un** et sans question à l'écran (verrou
dpkg) ; npm s'installe dans le dossier de Vigie avec Node 22 (plus de droits admin) ;
un outil pipx qui rate ou ne démarre pas est retenté avec un **Python 3.12 à part**
(`pipx --fetch-missing-python`), et `pkg_resources` manquant = on ajoute setuptools ;
nouvelles recettes dans `vigie/recettes.py` (go aux bons modules, programmes officiels
GitHub vérifiés, scripts Python copiés depuis leur dépôt) ; `recettes.MANUELS` = outils
à poser à la main (serveurs, Windows, Kali, Kubernetes), comptés à part dans le bilan.
« ne démarre pas » note maintenant la raison. Un bilan vide ne fait plus planter la relance.
**26/11/2026 : Ubuntu a tué l'installeur (mémoire pleine, signal 9) vers l'outil 108.**
Depuis : nombre d'installations de front = « auto » d'après la mémoire libre (4 au plus,
`--parallele N` ou `VIGIE_PARALLELE=N` pour forcer) ; les compilations (pip, pipx, go)
passent **une par une** et attendent 1 Go libre (`recettes.chantier`, `--compilations`) ;
Go/make limités à 2 cœurs ; le bilan est écrit **après chaque outil** (une coupure ne perd
plus rien, la relance reprend). build-essential + python3-dev ajoutés à la base apt.
**Outils installés à la main (26/11/2026)** : onglet « Lancer un outil », section
« Je l'ai installé à la main » (`vigie/a_la_main.py`, route `/outil/brancher`, depuis la
machine seulement) : Anass montre le programme ou son dossier, Vigie écrit un lanceur au nom
de la commande attendue (jamais par-dessus un vrai programme), vérifie qu'il démarre (pas
pour une appli ou un service) et le note dans `~/vigie-installation.json`. L'installeur
reconnaît un outil « à la main » déjà présent au lieu de le noter en échec.
**2e installation complète (26/11/2026, 130 prêts / 2 vrais échecs)** : pipx **ignore
`--python` quand on lui passe `--force`** → la réparation « Python 3.12 » désinstalle
d'abord puis réinstalle ; un « déjà installé » de pipx (reste d'une installation coupée)
est vérifié et refait. Un outil qui ne démarre pas dit toujours pourquoi (commande
introuvable, arrêt par le système, code). Disque : restes `go-build*`/`pip-*` et caches
Go/pip/uv vidés quand il reste < 6 Go et qu'aucune autre compilation ne tourne
(`recettes.chantier`), cache Go vidé après chaque `go install`, dossier temporaire vidé au
départ. npm ENOTEMPTY = reste retiré puis 2e essai. Une recette qui rate ne retombe plus
sur un module deviné « (dépôt) ». garak et Nebula pèsent ~6 Go chacun (torch + CUDA).
Rappel honnête : Vigie pilote le **moteur en ligne de commande** des outils (sorties JSON/XML
traduites) ; services (Wazuh, OpenVAS), applis (Burp, Ghidra) et exploration à la main
restent dans l'interface de l'outil.

**Tri des 84 outils « à la main » (26/11/2026)** : 4 passent en automatique
(`recettes.py`) : Nuclei Templates (`nuclei -update-templates`, sinon copie du dépôt),
Maester et Monkey365 (audit Microsoft 365 : PowerShell 7 officiel posé à part, empreinte
vérifiée, puis PowerShell Gallery), OWASP ZAP (archive officielle, empreinte lue dans
`ZapVersions.xml`, Java d'Ubuntu si absent). Chaque outil à la main a sa vraie raison ;
`recettes.PAS_ICI` = rien à faire sur la machine de Vigie (chez le client, Windows,
offensif, doublon) et le bilan les compte à part (`pas_ici` / `a_poser`). Utiles à la main :
OpenVAS et Wazuh (plus tard sur un serveur loué), Burp, ScubaGear et HardeningKitty (PC
Windows), BloodHound (client avec Active Directory).

**Relecture du 1er rapport complet (26/11/2026, 68/100)** : un texte de conséquence peut
avoir des **variantes** selon la situation réelle (`consequences.VARIANTES`, ex. DMARC en
quarantaine ≠ absent). Une même mesure = **une seule ligne** (vitesse de l'accueil : clé
`lenteur` pour Lighthouse et sitespeed.io ; Unlighthouse ne recompte pas l'accueil). Un
constat porte le nom de l'outil **qui l'a vu** (`sources=`, ex. tlsx dans le module SSLyze).
**Jamais un « correct » sans vraie recherche** : Metagoofil fini en < 5 s = non réalisé ;
gau muet = Vigie relit la Wayback Machine. Faux positifs écartés : `pseudos.FAUX_POSITIFS`
(Myspace), `liens.TECHNIQUES_WORDPRESS` (wp-json, feed, miniatures) et refus anti-robots.
Pannes : dnstwist trop long = recherche réduite aux fautes courantes, 9 min au total, durée
vraie dans le message ; dnsrecon planté = Vigie lit lui-même SRV/IPv6 et le bilan dit
« en panne » (`panne` dans les données) ; WhatWeb lancé avec un correctif Ruby (`RUBYOPT`) ;
sitespeed.io avec `analysisstorer` + lecture du résumé. `outils.pourquoi` donne maintenant
la **vraie ligne d'erreur** d'une trace Python ou Ruby.

**Conséquences pour le dirigeant (24/11/2026)** : demande d'Anass, chaque constat non
« Correct » a un onglet **Conséquences** (ce qu'un attaquant peut faire / ce que ça coûte /
côté loi / côté assurance / exemple réel sourcé) à côté de l'onglet **À corriger
(technique)**. Données dans `vigie/consequences.py` (une clé = la clé du constat ; un
nouveau constat = ajouter sa fiche, un test le vérifie). Sources : `docs/sources-consequences.md`.
Règle : toujours « peut », aucun montant d'amende par constat (plafonds une seule fois dans
le cadre légal). La phrase d'en-tête suit la lettre : un D dit clairement qu'il faut agir.

**Ouvrir un outil (26/11/2026)** : demande d'Anass, l'onglet « Ouvrir un outil » (`/ouvrir`,
`vigie/graphiques.py` + `vigie/interface_graphiques.py`) ouvre ~40 outils avec **leur propre
interface** : logiciel à fenêtres (Ghidra, Burp, ZAP, Autopsy…), service web démarré si
besoin (commande, service systemd via `pkexec`, conteneur ou `docker compose`) puis page
ouverte (Wazuh, OpenVAS, SpiderFoot, Uptime Kuma…), console dans un terminal (Metasploit,
Shannon, Strix…). Rien n'est scanné à l'ouverture. Outils d'audit et GATE : case
« labo ou autorisation signée » obligatoire, chaque ouverture notée dans
`journal/ouvertures.jsonl`. Toujours jamais dans un diagnostic ni en automatique. Les lignes
de démarrage viennent des docs : à confirmer sur la VM.

**Table des failles F01-F34 (26/11/2026)** : la table « telle faille, telle conséquence »
d'Anass est dans `vigie/donnees_failles/` (JSON = source lue ; 2 CSV pour Excel, un test
vérifie qu'ils collent). `vigie/failles.py` relie les codes de constat à Fxx
(`CORRESPONDANCE`, détail dans `docs/failles-correspondance.md`) et l'ajoute à l'onglet
Conséquences. Garde-fous : jamais `phrase_telephone` / `place_dans_l_offre` / `statut` ;
seulement les cas « forte » ; case C (et F01, F02, F34 = fuites) seulement avec
autorisation signée ; F33 « à construire » jamais.

Principe : **Vigie ne copie le code d'aucun outil**. Il appelle les outils installés
sur la machine (chaque outil garde sa licence, se met à jour seul, et Vigie continue
de marcher si l'un manque). Pour brancher un nouvel outil GitHub : voir la section
« Brancher un outil GitHub » du `LISEZMOI.md`.

**Premier vrai scan fait le 21/11/2026** sur le Mac d'Anass (pavillon-noir.tech,
note 72/100 avant le lot d'outils). Le Mac d'Anass est l'environnement de scan.

## Le catalogue d'outils (chantier terminé le 21/11/2026)

- `vigie/docs_outils.json` — **222 outils** documentés (nom, lien, catégorie,
  facette, install, usage, annexes, clé API, statut). **220 lus**, 2 introuvables
  (Xingrin, ARL-Next, catégorie OSINT référencement).
- `chantier/synthese_familles.md` — les 222 classés en **4 familles** :
  1. **Diag gratuit** (42) — OSINT passif/public → pipeline auto du gratuit
  2. **Audit** (57) — scan actif + accord → offre audit
  3. **Sécurisation** (55) — défensif / durcissement / DFIR → offre hardening
  4. **GATE** (66) — offensif, accord signé, **jamais en auto ni en gratuit**
- `vigie/catalogue_outils.json` — les outils effectivement **branchés** dans l'app
  (sous-ensemble du catalogue complet).
- `chantier/maj.py`, `chantier/familles.py` — scripts qui ont produit le catalogue
  et la synthèse (régénérables).

11 catégories dans le catalogue : Défense/détection/durcissement (33), Scan de
vulnérabilités (29), Pentest web (25), OSINT référencement (24), OSINT
pseudos/mails/images (23), Pentest IA/LLM (21), Analyse réseau et forensic (19),
Reconnaissance réseau (16), Active Directory (14), Mots de passe (9), Sans fil (9).

## Contrainte d'exécution (découverte le 21/11/2026)

Vigie doit tourner sur une **machine à internet ouvert** : le **Mac d'Anass en
direct**, ou un petit serveur (VPS). Les environnements cloud de Claude côté web
sont **bridés** (seuls GitHub et les dépôts de paquets passent ; les sources OSINT
comme crt.sh sont bloquées) → ils **ne peuvent pas scanner**. Conséquence : on peut
coder et tester la *mécanique* n'importe où, mais le **vrai scan se lance sur la
machine d'Anass** (ou un VPS que Claude Code configure).

## Prochaine étape concrète

Terrain de test : **pavillon-noir.tech** (le domaine d'Anass, aucun problème
d'autorisation), puis les sociétés de son père et de son oncle (sécurité physique)
**avec leur accord**. Objectif immédiat :
1. Faire tourner le **bloc Exposition** (famille 1) sur `pavillon-noir.tech`.
2. Lire les sorties, garder les dépôts qui sortent le mieux (via le banc de comparaison).
3. Produire le premier **rapport** réel et le relire.

Feuille de route détaillée (sous-domaines → scan sur autorisation → accès/réseau →
sauvegardes/assureur → PDF → 3 diagnostics réels → démo/devis → lancement) :
voir le tableau « Les étapes » du `LISEZMOI.md`.
