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
        "licence": "Apache-2.0", "actif": False, "adaptateur": None,
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
    # Lot 2 (21/11/2026). dnsrecon et dnsx : rien de plus que mail/checkdmarc sur
    # pavillon-noir.tech, gardés pour le banc. Exiv2 : doublon d'ExifTool.
    "dnsrecon": {
        "role": "Fiche DNS complète du domaine (2e avis)",
        "commande": "dnsrecon",
        "installation": "pipx install --python python3.13 dnsrecon (cassé sous 3.14)",
        "depot": "https://github.com/darkoperator/dnsrecon",
        "licence": "GPL-2.0", "actif": False, "adaptateur": None,
    },
    "dnsx": {
        "role": "Réponses DNS des adresses de la société (alias oubliés)",
        "commande": "dnsx", "installation": "brew install dnsx",
        "depot": "https://github.com/projectdiscovery/dnsx",
        "licence": "MIT", "actif": False, "adaptateur": None,
    },
    # Comme Sherlock, plus complet (68 comptes « vigie » sur 200 sites le 21/11/2026, la
    # plupart d'homonymes). Pseudos du dirigeant + accord écrit uniquement. Banc seulement.
    "maigret": {
        "role": "Comptes publics ouverts sous un pseudo (2e avis)",
        "commande": "maigret", "installation": "pipx install --python python3.14 maigret",
        "depot": "https://github.com/soxoj/maigret",
        "licence": "MIT", "actif": False, "adaptateur": None,
    },
    # Lot 3 (21/11/2026) : Lighthouse sur TOUTES les pages. pavillon-noir.tech : 31 pages
    # en 95 s, rien de plus que Lighthouse sur l'accueil. Banc seulement (trop long).
    "unlighthouse": {
        "role": "Protections et vitesse de toutes les pages du site (2e avis)",
        "commande": "unlighthouse-ci", "installation": "npm install -g unlighthouse",
        "depot": "https://github.com/harlan-zw/unlighthouse",
        "licence": "MIT", "actif": False, "adaptateur": None,
    },
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
DOSSIERS_OUTILS = ["~/.local/bin", "~/go/bin", "/opt/homebrew/bin", "/usr/local/bin"]


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


def executer(nom, arguments, delai=300, dossier=None):
    """Lance un outil du catalogue et renvoie ce qu'il affiche.

    Les arguments sont passés en liste, jamais via un shell : une valeur saisie
    par l'utilisateur ne peut pas devenir une commande.
    """
    outil = CATALOGUE[nom]
    chemin = trouver(outil["commande"])
    if not chemin:
        raise ControleImpossible(
            f"l'outil {nom} n'est pas installé ({outil['installation']})")
    environnement = dict(os.environ, PATH=chemin_recherche())
    try:
        resultat = subprocess.run([chemin] + list(arguments), capture_output=True, text=True,
                                  timeout=delai, cwd=dossier, env=environnement,
                                  errors="replace")
    except subprocess.TimeoutExpired:
        raise ControleImpossible(f"l'outil {nom} n'a pas répondu en {delai} secondes")
    return resultat.stdout


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
        "installation": outil["installation"],
    } for nom, outil in CATALOGUE.items()]
