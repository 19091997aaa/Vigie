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
        "licence": "MIT", "actif": False, "adaptateur": None,
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
        "licence": "GPL-2.0", "actif": False, "adaptateur": None,
    },
    # --- Bloc Exposition : scan externe (autorisation signée) ---
    "httpx": {
        "role": "Sites qui répondent, technologie et version",
        "commande": "httpx", "installation": "brew install httpx",
        "depot": "https://github.com/projectdiscovery/httpx",
        "licence": "MIT", "actif": True, "adaptateur": None,
    },
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


def disponible(nom):
    return shutil.which(CATALOGUE[nom]["commande"]) is not None


def executer(nom, arguments, delai=300, dossier=None):
    """Lance un outil du catalogue et renvoie ce qu'il affiche.

    Les arguments sont passés en liste, jamais via un shell : une valeur saisie
    par l'utilisateur ne peut pas devenir une commande.
    """
    outil = CATALOGUE[nom]
    chemin = shutil.which(outil["commande"])
    if not chemin:
        raise ControleImpossible(
            f"l'outil {nom} n'est pas installé ({outil['installation']})")
    try:
        resultat = subprocess.run([chemin] + list(arguments), capture_output=True, text=True,
                                  timeout=delai, cwd=dossier)
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
