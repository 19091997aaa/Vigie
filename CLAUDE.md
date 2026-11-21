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
`installer-mac.command` / `installer-windows.ps1`.

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
