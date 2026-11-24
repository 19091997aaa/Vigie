"""Le point d'entrée des outils externes (projets GitHub et autres).

Vigie n'embarque le code d'aucun outil : il les appelle s'ils sont installés
sur la machine. Trois raisons :
  - chaque outil garde sa licence (certaines interdisent d'être fondues dans
    un autre logiciel) ;
  - chaque outil se met à jour tout seul ;
  - Vigie continue de fonctionner quand l'un d'eux manque.

Pour brancher un nouvel outil :
  1. l'inscrire dans CATALOGUE ci-dessous ;
  2. écrire un adaptateur dans vigie/modules/ qui appelle executer() et
     traduit la sortie de l'outil en constats ;
  3. inscrire l'adaptateur dans vigie/modules/__init__.py.
"""
import os
import shutil
import subprocess
import sys

from .modeles import ControleImpossible

# "actif"   : l'outil touche aux machines du client -> autorisation signée obligatoire.
# "licence" : relevé du catalogue du 20/11/2026. À relire sur le dépôt avant usage commercial.
# "installation" : commande pour macOS, à confirmer au moment de l'installation.
CATALOGUE = {
    # --- Bloc Exposition : informations publiques ---
    "sherlock": {
        "role": "Comptes publics ouverts sous un pseudo",
        "commande": "sherlock", "installation": "pipx install sherlock-project",
        "depot": "https://github.com/sherlock-project/sherlock",
        "licence": "MIT (vérifiée)", "actif": False, "adaptateur": "pseudos",
    },
    "subfinder": {
        "role": "Sous-domaines visibles de la société",
        "commande": "subfinder", "installation": "brew install subfinder",
        "depot": "https://github.com/projectdiscovery/subfinder",
        "licence": "MIT", "actif": False, "adaptateur": "sousdomaines",
    },
    # Comparé à Subfinder le 21/11/2026 sur pavillon-noir.tech : 0 trouvé contre 1, et il
    # laisse un « moteur » tourner après coup. Gardé hors de l'enchaînement, pour le banc.
    "amass": {
        "role": "Sous-domaines visibles de la société (2e avis, plus lourd)",
        "commande": "amass", "installation": "brew install amass",
        "depot": "https://github.com/owasp-amass/amass",
        "licence": "Apache-2.0", "actif": False, "adaptateur": "sousdomaines_amass",
    },
    "gau": {
        "role": "Anciennes pages du site gardées par les archives d'internet",
        "commande": "gau", "installation": "brew install gau",
        "depot": "https://github.com/lc/gau",
        "licence": "MIT", "actif": False, "adaptateur": "archives",
    },
    "exiftool": {
        "role": "Informations cachées dans les documents et photos publiés",
        "commande": "exiftool", "installation": "brew install exiftool",
        "depot": "https://github.com/exiftool/exiftool",
        "licence": "Artistic ou GPL (comme Perl)", "actif": False, "adaptateur": "metadonnees",
    },
    # Lot 2 (21/11/2026), comparés point par point (chantier/comparaisons_2026-11-21.md).
    # dnsrecon voit EN PLUS les réglages SRV de la messagerie et l'IPv6 : pas des failles,
    # mais de l'information. dnsx : rien de plus. Exiv2 : moins complet qu'ExifTool.
    "dnsrecon": {
        "role": "Fiche DNS complète du domaine (2e avis)",
        "commande": "dnsrecon",
        "installation": "pipx install --python python3.13 dnsrecon (cassé sous 3.14)",
        "depot": "https://github.com/darkoperator/dnsrecon",
        "licence": "GPL-2.0", "actif": False, "adaptateur": "dns_complet",
    },
    "dnsx": {
        "role": "Réponses DNS des adresses de la société (alias oubliés)",
        "commande": "dnsx", "installation": "brew install dnsx",
        "depot": "https://github.com/projectdiscovery/dnsx",
        "licence": "MIT", "actif": False, "adaptateur": "alias_dns",
    },
    # Comme Sherlock, plus complet (68 comptes « vigie » sur 200 sites le 21/11/2026, la
    # plupart d'homonymes). Pseudos du dirigeant + accord écrit uniquement.
    "maigret": {
        "role": "Comptes publics ouverts sous un pseudo (2e avis)",
        "commande": "maigret", "installation": "pipx install --python python3.14 maigret",
        "depot": "https://github.com/soxoj/maigret",
        "licence": "MIT", "actif": False, "adaptateur": "pseudos",
    },
    # Lot 3 (21/11/2026) : Lighthouse sur TOUTES les pages. pavillon-noir.tech : 31 pages
    # en 95 s, rien de plus que Lighthouse sur l'accueil. Banc seulement (trop long).
    "unlighthouse": {
        "role": "Protections et vitesse de toutes les pages du site (2e avis)",
        "commande": "unlighthouse-ci", "installation": "npm install -g unlighthouse",
        "depot": "https://github.com/harlan-zw/unlighthouse",
        "licence": "MIT", "actif": False, "adaptateur": "toutes_pages",
    },
    "user-scanner": {
        "role": "Comptes publics ouverts sous un pseudo (3e avis, inclut Instagram et LinkedIn)",
        "commande": "user-scanner", "installation": "pipx install user-scanner",
        "depot": "https://github.com/kaifcodec/user-scanner",
        "licence": "MIT", "actif": False, "adaptateur": "pseudos",
    },
    "holehe": {
        "role": "Sites où une adresse mail est inscrite (sans alerter la personne)",
        "commande": "holehe", "installation": "pipx install holehe",
        "depot": "https://github.com/megadose/holehe",
        "licence": "GPL-3.0", "actif": False, "adaptateur": "comptes_mail",
    },
    "phoneinfoga": {
        "role": "Ce qu'un numéro de téléphone révèle (pays, opérateur, type de ligne)",
        "commande": "phoneinfoga", "installation": "brew install phoneinfoga",
        "depot": "https://github.com/sundowndev/phoneinfoga",
        "licence": "GPL-3.0", "actif": False, "adaptateur": "telephone",
    },
    "retire": {
        "role": "Bibliothèques JavaScript trouées sur le site",
        "commande": "retire", "installation": "npm install -g retire",
        "depot": "https://github.com/RetireJS/retire.js",
        "licence": "Apache-2.0", "actif": False, "adaptateur": "bibliotheques",
    },
    # Lot 4 (21/11/2026), outils qui lisent du code ou des fichiers, comparés deux à deux
    # (chantier/comparaisons_2026-11-21.md). Gardés pour le banc et l'offre sécurisation.
    "gitleaks": {"role": "Mots de passe oubliés dans du code (plus de motifs)",
                 "commande": "gitleaks", "installation": "brew install gitleaks",
                 "depot": "https://github.com/gitleaks/gitleaks", "licence": "MIT",
                 "actif": False, "adaptateur": None},
    "trufflehog": {"role": "Mots de passe oubliés dans du code (vérifie s'ils marchent)",
                   "commande": "trufflehog", "installation": "brew install trufflehog",
                   "depot": "https://github.com/trufflesecurity/trufflehog", "licence": "AGPL-3.0",
                   "actif": False, "adaptateur": None},
    "grype": {"role": "Logiciels installés avec des failles connues",
              "commande": "grype", "installation": "brew install grype",
              "depot": "https://github.com/anchore/grype", "licence": "Apache-2.0",
              "actif": False, "adaptateur": None},
    "trivy": {"role": "Logiciels installés avec des failles connues (2e avis)",
              "commande": "trivy", "installation": "brew install trivy",
              "depot": "https://github.com/aquasecurity/trivy", "licence": "Apache-2.0",
              "actif": False, "adaptateur": None},
    "tlsx": {"role": "Chiffrement et certificat d'un site (2e avis de SSLyze)",
             "commande": "tlsx", "installation": "brew install tlsx",
             "depot": "https://github.com/projectdiscovery/tlsx", "licence": "MIT",
             "actif": False, "adaptateur": "chiffrement"},
    "linkchecker": {
        "role": "Liens cassés du site, et liens vers des domaines disparus",
        "commande": "linkchecker", "installation": "pipx install linkchecker",
        "depot": "https://github.com/linkchecker/linkchecker",
        "licence": "GPL-2.0", "actif": False, "adaptateur": "liens",
    },
    "pa11y": {
        "role": "Accessibilité de la page d'accueil (WCAG 2 AA)",
        "commande": "pa11y", "installation": "npm install -g pa11y",
        "depot": "https://github.com/pa11y/pa11y",
        "licence": "LGPL-3.0", "actif": False, "adaptateur": "accessibilite",
    },
    # Les quatre suivants lisent ce que le site publie à un visiteur (page d'accueil,
    # poignée de main du chiffrement) : zone sûre du cadre légal (MARCHE.md §2).
    # Aucune recherche de faille : Vigie ne leur passe que ces réglages-là.
    "httpx": {
        "role": "Sites qui répondent, technologie et version",
        "commande": "httpx", "installation": "brew install httpx",
        "depot": "https://github.com/projectdiscovery/httpx",
        "licence": "MIT", "actif": False, "adaptateur": "technos",
    },
    "sslyze": {
        "role": "Versions du chiffrement acceptées par le site",
        "commande": "sslyze",
        "installation": "pipx install --python python3.14 sslyze (pas encore compatible 3.15)",
        "depot": "https://github.com/nabla-c0d3/sslyze",
        "licence": "AGPL-3.0", "actif": False, "adaptateur": "chiffrement",
    },
    "lighthouse": {
        "role": "Protections et vitesse de la page d'accueil, vues par Chrome",
        "commande": "lighthouse", "installation": "npm install -g lighthouse",
        "depot": "https://github.com/GoogleChrome/lighthouse",
        "licence": "Apache-2.0", "actif": False, "adaptateur": "qualite_site",
    },
    "gowitness": {
        "role": "Capture d'écran de la page d'accueil, pour le rapport",
        "commande": "gowitness", "installation": "go install github.com/sensepost/gowitness@latest",
        "depot": "https://github.com/sensepost/gowitness",
        "licence": "GPL-3.0", "actif": False, "adaptateur": "apercu",
    },
    "dnstwist": {
        "role": "Noms de domaine qui imitent celui de la société",
        "commande": "dnstwist", "installation": "pipx install \"dnstwist[full]\"",
        "depot": "https://github.com/elceef/dnstwist",
        "licence": "Apache-2.0", "actif": False, "adaptateur": "domaines",
    },
    "checkdmarc": {
        "role": "Réglages mail, deuxième avis (SPF, DMARC, MTA-STS, DNSSEC)",
        "commande": "checkdmarc", "installation": "pipx install checkdmarc",
        "depot": "https://github.com/domainaware/checkdmarc",
        "licence": "Apache-2.0", "actif": False, "adaptateur": "checkdmarc",
    },
    "theHarvester": {
        "role": "Adresses mail de la société visibles publiquement",
        "commande": "theHarvester", "installation": "brew install theharvester",
        "depot": "https://github.com/laramies/theHarvester",
        "licence": "GPL-2.0", "actif": False, "adaptateur": "adresses",
    },
    # Lot « diagnostic complet » (24/11/2026) : les outils de la famille « diag gratuit »
    # qui n'étaient pas encore dans l'enchaînement. Tous lisent ce qui est public.
    "whatweb": {
        "role": "Technologies du site, 2e avis (mode discret : une seule visite)",
        "commande": "whatweb", "installation": "sudo apt install whatweb",
        "depot": "https://github.com/urbanadventurer/WhatWeb",
        "licence": "GPL-2.0", "actif": False, "adaptateur": "technos_whatweb",
    },
    "sitespeed.io": {
        "role": "Vitesse de la page d'accueil, vue par un navigateur",
        "commande": "sitespeed.io", "installation": "npm install -g sitespeed.io",
        "depot": "https://github.com/sitespeedio/sitespeed.io",
        "licence": "MIT", "actif": False, "adaptateur": "vitesse",
    },
    "eyewitness": {
        "role": "Capture d'écran de la page d'accueil (2e avis de gowitness)",
        "commande": "eyewitness", "installation": "sudo apt install eyewitness",
        "depot": "https://github.com/RedSiege/EyeWitness",
        "licence": "GPL-3.0", "actif": False, "adaptateur": "captures",
    },
    "uncover": {
        "role": "Ce que les moteurs Shodan/Censys ont déjà indexé sur la société",
        "commande": "uncover",
        "installation": "go install github.com/projectdiscovery/uncover/cmd/uncover@latest",
        "depot": "https://github.com/projectdiscovery/uncover",
        "licence": "MIT", "actif": False, "adaptateur": "moteurs_exposition",
    },
    "metagoofil": {
        "role": "Documents publics de la société trouvés par les moteurs de recherche",
        "commande": "metagoofil", "installation": "sudo apt install metagoofil",
        "depot": "https://github.com/opsdisk/metagoofil",
        "licence": "GPL-2.0", "actif": False, "adaptateur": "documents_publics",
    },
    "exiv2": {
        "role": "Informations cachées des photos (2e avis d'ExifTool)",
        "commande": "exiv2", "installation": "brew install exiv2",
        "depot": "https://github.com/exiv2/exiv2",
        "licence": "GPL-2.0", "actif": False, "adaptateur": "photos",
    },
    "instaloader": {
        "role": "Fiche publique du compte Instagram de la société",
        "commande": "instaloader", "installation": "pipx install instaloader",
        "depot": "https://github.com/instaloader/instaloader",
        "licence": "MIT", "actif": False, "adaptateur": "instagram",
    },
    "social-analyzer": {
        "role": "Comptes publics ouverts sous un pseudo (4e avis)",
        "commande": "social-analyzer", "installation": "pipx install social-analyzer",
        "depot": "https://github.com/qeeqbox/social-analyzer",
        "licence": "AGPL-3.0", "actif": False, "adaptateur": "pseudos_societe",
    },
    "archivebox": {
        "role": "Copie datée de la page d'accueil (preuve de l'état du site)",
        "commande": "archivebox", "installation": "pipx install archivebox",
        "depot": "https://github.com/ArchiveBox/ArchiveBox",
        "licence": "MIT", "actif": False, "adaptateur": "archive_page",
    },
    "ghunt": {
        "role": "Ce que Google montre sur l'adresse Gmail du dirigeant (avec son accord)",
        "commande": "ghunt", "installation": "pipx install ghunt",
        "depot": "https://github.com/mxrch/GHunt",
        "licence": "AGPL-3.0", "actif": False, "adaptateur": "google_dirigeant",
    },
    # --- Bloc Exposition : scan externe (autorisation signée) ---
    "naabu": {
        "role": "Services ouverts sur internet (ports)",
        "commande": "naabu", "installation": "brew install naabu",
        "depot": "https://github.com/projectdiscovery/naabu",
        "licence": "MIT", "actif": True, "adaptateur": None,
    },
    "nuclei": {
        "role": "Failles connues (CVE) sur les services exposés",
        "commande": "nuclei", "installation": "brew install nuclei",
        "depot": "https://github.com/projectdiscovery/nuclei",
        "licence": "MIT", "actif": True, "adaptateur": None,
    },
    "sslscan": {
        "role": "Protocoles de chiffrement acceptés par le site",
        "commande": "sslscan", "installation": "brew install sslscan",
        "depot": "https://github.com/rbsec/sslscan",
        "licence": "GPL-3.0", "actif": True, "adaptateur": None,
    },
    # --- Bloc Réseau et postes (autorisation signée, lancé chez le client) ---
    "lynis": {
        "role": "Audit de sécurité d'un serveur ou d'un poste Linux et macOS",
        "commande": "lynis", "installation": "brew install lynis",
        "depot": "https://github.com/CISOfy/lynis",
        "licence": "GPL-3.0", "actif": True, "adaptateur": None,
    },
    # --- Outils d'attaque : installés et lançables À LA MAIN, sur autorisation signée.
    #     JAMAIS dans l'enchaînement automatique (adaptateur volontairement None). ---
    "nmap": {
        "role": "Cartographie fine des services (attaque)",
        "commande": "nmap", "installation": "brew install nmap",
        "depot": "https://github.com/nmap/nmap",
        "licence": "NPSL (usage commercial encadré)", "actif": True, "adaptateur": None,
        "attaque": True,
    },
    "sqlmap": {
        "role": "Test d'injection SQL (attaque)",
        "commande": "sqlmap", "installation": "pipx install sqlmap",
        "depot": "https://github.com/sqlmapproject/sqlmap",
        "licence": "GPL-2.0", "actif": True, "adaptateur": None, "attaque": True,
    },
    "metasploit": {
        "role": "Cadre d'exploitation (attaque)",
        "commande": "msfconsole", "installation": "installeur officiel Rapid7",
        "depot": "https://github.com/rapid7/metasploit-framework",
        "licence": "BSD-3-Clause", "actif": True, "adaptateur": None, "attaque": True,
    },
    "hydra": {
        "role": "Test de mots de passe par force brute (attaque)",
        "commande": "hydra", "installation": "brew install hydra",
        "depot": "https://github.com/vanhauser-thc/thc-hydra",
        "licence": "AGPL-3.0", "actif": True, "adaptateur": None, "attaque": True,
    },
    "responder": {
        "role": "Interception d'identifiants sur réseau Windows (attaque)",
        "commande": "responder", "installation": "pipx install responder",
        "depot": "https://github.com/lgandx/Responder",
        "licence": "GPL-3.0", "actif": True, "adaptateur": None, "attaque": True,
    },
}

# Outils Windows (PowerShell), à brancher quand le bloc « Réseau et postes » démarre :
# HardeningKitty (MIT) pour la configuration de Windows, Maester (MIT) pour Microsoft 365.


# Où les installeurs posent les outils (pipx, go, Homebrew). Lancé par un double-clic,
# Vigie n'hérite pas toujours de ces dossiers : sans eux, un outil bien installé passe
# pour absent, et un outil écrit en JavaScript ne trouve pas « node ».
DOSSIERS_OUTILS = ["~/.local/bin", "~/go/bin", "/opt/homebrew/bin", "/usr/local/bin",
                   # Dossier où « installer --dest /opt/vigie-outils » pose les outils :
                   # Vigie les retrouve seul, même si le PATH de la personne ne le liste pas.
                   "/opt/vigie-outils/bin"]


def chemin_recherche():
    dossiers = os.environ.get("PATH", "").split(os.pathsep)
    for dossier in DOSSIERS_OUTILS:
        dossier = os.path.expanduser(dossier)
        if dossier not in dossiers:
            dossiers.append(dossier)
    return os.pathsep.join(d for d in dossiers if d)


def trouver(commande):
    return shutil.which(commande, path=chemin_recherche())


def disponible(nom):
    return trouver(CATALOGUE[nom]["commande"]) is not None


# Sous Linux, la commande à montrer selon ce que la documentation de l'outil indique.
_AFFICHAGE = [("apt", "sudo apt install {}"), ("pipx", "pipx install {}"),
              ("go", "go install {}"), ("npm", "npm install -g {}")]


def astuce_installation(nom, systeme=None):
    """La commande d'installation à montrer pour cet outil, sur CE système.

    Le catalogue note la commande macOS (Homebrew). « brew » n'existe pas sous Linux :
    on y montre la commande écrite dans la documentation de l'outil (jamais un paquet
    deviné sur son nom), sinon on renvoie vers l'installeur Linux de Vigie.
    """
    texte = CATALOGUE[nom]["installation"]
    from . import recettes
    if (systeme or sys.platform) != "darwin" and recettes.pour(nom, "linux"):
        # Outils que la doc fait rater sous Ubuntu (« sudo apt install eyewitness »
        # n'existe pas) : l'installeur Linux a une recette pour eux.
        return "installeur Linux de Vigie (bash installer-linux.command)"
    if (systeme or sys.platform) == "darwin" or not texte.startswith("brew "):
        return texte
    from . import installeur
    doc = installeur._install_documentee({"nom": nom, "lien": CATALOGUE[nom]["depot"]})
    motifs = {libelle.split()[0]: motif for libelle, motif, _ in installeur.DOCUMENTEES}
    for genre, modele in _AFFICHAGE:
        trouve = motifs[genre].search(doc)
        if trouve and not trouve.group(1).startswith("-"):
            return modele.format(trouve.group(1))
    return "installeur Linux de Vigie (bash installer-linux.command)"


def executer(nom, arguments, delai=300, dossier=None, entree=None, partiel=False):
    """Lance un outil du catalogue et renvoie ce qu'il affiche.

    Les arguments sont passés en liste, jamais via un shell : une valeur saisie
    par l'utilisateur ne peut pas devenir une commande.
    """
    options = {"partiel": True} if partiel else {}
    return executer_detail(nom, arguments, delai, dossier, entree, **options).stdout


def executer_detail(nom, arguments, delai=300, dossier=None, entree=None, partiel=False):
    """Comme executer(), mais renvoie tout : code de retour, sortie, messages d'erreur.

    entree : texte envoyé à l'outil (une liste de noms, pour dnsx). Sans entree, le
    clavier est coupé : un outil qui pose une question ne bloque pas le diagnostic.
    partiel : si l'outil dépasse son délai, on garde ce qu'il a déjà affiché (code de
    retour None) au lieu de tout perdre. Sherlock, par exemple, écrit chaque compte
    trouvé au fil de l'eau : 4 minutes de recherche valent mieux que rien.
    """
    outil = CATALOGUE[nom]
    chemin = trouver(outil["commande"])
    if not chemin:
        raise ControleImpossible(
            f"l'outil {nom} n'est pas installé ({astuce_installation(nom)})")
    environnement = dict(os.environ, PATH=chemin_recherche())
    try:
        return subprocess.run([chemin] + list(arguments), capture_output=True, text=True,
                              timeout=delai, cwd=dossier, env=environnement,
                              errors="replace", input=entree,
                              stdin=None if entree is not None else subprocess.DEVNULL)
    except subprocess.TimeoutExpired as depassement:
        if not partiel:
            raise ControleImpossible(f"l'outil {nom} n'a pas répondu en {delai} secondes")
        return subprocess.CompletedProcess([chemin] + list(arguments), None,
                                           _texte(depassement.stdout), _texte(depassement.stderr))


def _texte(contenu):
    if isinstance(contenu, bytes):
        return contenu.decode("utf-8", errors="replace")
    return contenu or ""


def pourquoi(resultat):
    """Pourquoi un outil n'a rien donné, en français : l'explication d'un message connu
    (vigie/erreurs.py), sinon la dernière ligne de l'outil telle quelle."""
    from . import erreurs
    texte = (resultat.stderr or "") + "\n" + (resultat.stdout or "")
    explications = erreurs.expliquer(texte, maximum=1)
    if explications:
        return explications[0]
    lignes = [l.strip() for l in texte.splitlines() if l.strip()]
    if lignes:
        return "message de l'outil : " + lignes[-1][:160]
    return f"l'outil s'est arrêté sans rien dire (code {resultat.returncode})"


def etat():
    """Pour la commande « vigie outils » : ce qui est prévu, installé, branché."""
    return [{
        "nom": nom,
        "role": outil["role"],
        "installe": disponible(nom),
        "branche": outil["adaptateur"] is not None,
        "actif": outil["actif"],
        "attaque": outil.get("attaque", False),
        "licence": outil["licence"],
        "installation": astuce_installation(nom),
    } for nom, outil in CATALOGUE.items()]
