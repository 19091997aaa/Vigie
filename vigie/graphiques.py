"""Ouvrir un outil avec SA propre interface : sa fenêtre, sa page web ou sa console.

Demande d'Anass (26/11/2026) : beaucoup d'outils du catalogue ne se pilotent pas en
ligne de commande. Ce sont des logiciels à fenêtres (Ghidra, Burp, Autopsy…), des
services avec une page web (Wazuh, OpenVAS, Uptime Kuma, SpiderFoot…) ou des
consoles interactives (Metasploit, Shannon…). Vigie ne les « traduit » pas : il les
OUVRE, tels qu'ils sont, depuis l'onglet « Ouvrir un outil ».

Cinq genres :
  appli    : un logiciel à fenêtres -> Vigie le démarre, la fenêtre apparaît.
  web      : un service avec une page web -> Vigie le démarre s'il est arrêté, attend
             qu'il réponde, puis ouvre sa page dans le navigateur.
  console  : un outil qui se pilote au clavier -> Vigie ouvre un terminal avec l'outil.
  page     : une page web qui tourne dans le navigateur (CyberChef).
  lien     : une extension du navigateur -> Vigie ouvre sa page officielle.

Garde-fous (règles d'or) :
  - Ouvrir une interface ne vise personne : rien n'est scanné à l'ouverture. Mais les
    outils d'audit (actifs) et offensifs (GATE) ne s'ouvrent qu'après avoir coché
    « je ne vise que mon labo ou une cible couverte par une autorisation signée ».
    Chaque ouverture de ces outils est notée dans journal/ouvertures.jsonl.
  - Rien de tout ça n'entre dans un diagnostic ni dans un enchaînement automatique.
  - Vigie n'installe rien ici : il ouvre ce qui est déjà sur la machine.

Les lignes de démarrage viennent de la documentation de chaque outil. Elles sont à
confirmer sur la VM : si l'une rate, l'erreur s'affiche en français.
"""
import datetime
import glob
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import time
import urllib.parse

from . import erreurs, outils, recettes, registre


def _appli(*commandes, mac="", url_apres="", note=""):
    return {"genre": "appli", "commandes": list(commandes), "mac": mac,
            "url_apres": url_apres, "note": note}


def _console(*commandes, note="", besoin=(), intro="", script="", ia=False):
    """besoin : ce qu'il faut en plus sur la machine ("docker", "node22").
    intro : phrase affichée en français dans le terminal avant le démarrage.
    script : lignes bash qui posent les questions en français puis lancent l'outil
    ({cmd} = la commande trouvée), pour un outil qui ne démarre pas sans réglages."""
    return {"genre": "console", "commandes": list(commandes), "note": note,
            "besoin": list(besoin), "intro": intro, "script": script, "ia": ia}


def _web(url, *demarrer, attente=60, note="", ia=False):
    """ia : l'outil a besoin de la clé d'IA enregistrée dans Vigie (cles_ia.py)."""
    return {"genre": "web", "url": url, "demarrer": list(demarrer), "attente": attente,
            "note": note, "ia": ia}


def _cmd(*argv, dossier="", fichier="", avant=None):
    """Démarrer en lançant une commande (sans droits administrateur).
    dossier : dossier de travail rangé par Vigie ; fichier : le script se lance
    depuis le dossier de l'outil où se trouve ce fichier."""
    return {"moyen": "cmd", "argv": list(argv), "dossier": dossier, "fichier": fichier,
            "avant": avant or []}


def _admin(*argv):
    """Démarrer avec les droits administrateur : une fenêtre demande le mot de passe."""
    return {"moyen": "admin", "argv": list(argv)}


def _service(nom):
    return {"moyen": "service", "nom": nom}


def _docker(nom):
    return {"moyen": "docker", "nom": nom}


def _compose(nom):
    return {"moyen": "compose", "nom": nom}


# Commande « npx » d'un Node 22 ou plus (celui que Vigie pose à part, sinon celui du
# système s'il est assez récent). Résolu par _trouver().
NPX22 = "@npx22"

# Questions en français pour un outil d'IA qui lit sa clé dans l'environnement
# (OPENAI_API_KEY, ANTHROPIC_API_KEY, GEMINI_API_KEY, DEEPSEEK_API_KEY). La clé reste
# dans ce terminal seulement : rien n'est écrit sur le disque.
CLE_IA = (
    'if [ -z "$OPENAI_API_KEY$ANTHROPIC_API_KEY$GEMINI_API_KEY$DEEPSEEK_API_KEY" ]; then '
    'echo "Quel fournisseur d\'IA ?  1 = Anthropic (Claude)   2 = OpenAI (ChatGPT)   '
    '3 = Google (Gemini)   4 = DeepSeek"; read -r -p "Tape 1, 2, 3 ou 4 : " choix; '
    'case "$choix" in 2) var=OPENAI_API_KEY;; 3) var=GEMINI_API_KEY;; '
    '4) var=DEEPSEEK_API_KEY;; *) var=ANTHROPIC_API_KEY;; esac; '
    'read -r -s -p "Colle ta clé d\'IA (elle ne s\'affiche pas) puis Entrée : " cle; echo; '
    'export "$var=$cle"; echo "Clé prise pour cette fois (elle n\'est pas enregistrée)."; '
    'echo; fi; ')

# Clé = nom exact du registre (docs_outils.json). Un test vérifie que chaque clé existe.
INTERFACES = {
    # --- Logiciels à fenêtres ------------------------------------------------
    "Ghidra": _appli(["ghidraRun"], ["ghidra"], mac="Ghidra",
                     note="La fenêtre met souvent 20 à 30 secondes à apparaître."),
    "Autopsy": _appli(["autopsy"], mac="Autopsy",
                      url_apres="http://127.0.0.1:9999/autopsy",
                      note="Sous Ubuntu, la version du paquet s'ouvre dans le navigateur."),
    "Wireshark": _appli(["wireshark"], mac="Wireshark"),
    "VeraCrypt": _appli(["veracrypt"], mac="VeraCrypt"),
    "Burp Suite Community": _appli(["burpsuite"], ["BurpSuiteCommunity"],
                                   ["/opt/BurpSuiteCommunity/BurpSuiteCommunity"],
                                   ["~/BurpSuiteCommunity/BurpSuiteCommunity"],
                                   mac="Burp Suite Community Edition"),
    "OWASP ZAP": _appli(["zaproxy"], ["zap.sh"], ["/opt/zaproxy/zap.sh"], ["owasp-zap"],
                        mac="ZAP"),
    "Angry IP Scanner": _appli(["ipscan"], mac="Angry IP Scanner"),
    "KeePassXC": _appli(["keepassxc"], mac="KeePassXC"),
    # --- Services avec une page web -----------------------------------------
    "SpiderFoot": _web("http://127.0.0.1:5001",
                       _cmd("spiderfoot", "-l", "127.0.0.1:5001"),
                       _cmd("sf.py", "-l", "127.0.0.1:5001"),
                       _cmd("python3", "sf.py", "-l", "127.0.0.1:5001", fichier="sf.py")),
    "ArchiveBox": _web("http://127.0.0.1:8000",
                       _cmd("archivebox", "server", "127.0.0.1:8000", dossier="archivebox",
                            avant=[["archivebox", "init"]])),
    "Datashare": _web("http://127.0.0.1:8080", _cmd("datashare"), attente=90),
    "Web-Check": _web("http://127.0.0.1:3000", _docker("web-check"), _compose("web-check")),
    "Flowsint": _web("http://127.0.0.1:5173", _compose("flowsint"), attente=120),
    "OpenVAS (Greenbone Community)": _web(
        "https://127.0.0.1:9392", _admin("gvm-start"), _service("gsad"), attente=180,
        note="Le navigateur prévient d'un certificat « non sûr » : c'est normal en local."),
    "ntopng (Community)": _web("http://127.0.0.1:3000", _service("ntopng")),
    "Gophish": _web("https://127.0.0.1:3333", _cmd("gophish", fichier="config.json"),
                    note="Au premier démarrage, Gophish donne un mot de passe de départ "
                         "(affiché ici s'il est trouvé)."),
    "Pi-hole": _web("http://127.0.0.1/admin", _service("pihole-FTL")),
    "AdGuard Home": _web("http://127.0.0.1:3000", _service("AdGuardHome")),
    "Wazuh": _web("https://127.0.0.1", _service("wazuh-dashboard"), _compose("wazuh-docker"),
                  _compose("wazuh"), attente=180),
    "Uptime Kuma": _web("http://127.0.0.1:3001", _docker("uptime-kuma"),
                        _cmd("node", "server/server.js", fichier="server/server.js")),
    "MISP": _web("https://127.0.0.1", _compose("misp-docker"), _compose("misp"), attente=180),
    "Velociraptor": _web("https://127.0.0.1:8889",
                         _cmd("velociraptor", "gui", dossier="velociraptor")),
    "Arkime": _web("http://127.0.0.1:8005", _service("arkimeviewer")),
    "BloodHound": _web("http://127.0.0.1:8080", _compose("bloodhound"),
                       _docker("bloodhound"), attente=120),
    "ROADtools": _web("http://127.0.0.1:5000",
                      _cmd("roadrecon", "gui", dossier="roadtools"),
                      note="Il montre ce qui a été récolté avant (roadrecon gather)."),
    # mitmproxy 11 et plus protège sa page par un jeton (« ?token=… ») écrit au
    # démarrage : sans lui, la page refuse d'afficher (28/11/2026 sur la VM). Vigie le lit
    # dans le journal (JETON) ; mitmweb n'ouvre plus d'onglet de son côté.
    "mitmproxy": _web("http://127.0.0.1:8081",
                      _cmd("mitmweb", "--web-host", "127.0.0.1",
                           "--set", "web_open_browser=false"),
                      note="Le proxy écoute sur 127.0.0.1:8080 : règle ce proxy dans le "
                           "navigateur ou l'appareil à observer."),
    "OWASP Nettacker": _web("https://127.0.0.1:5000",
                            _cmd("nettacker", "--start-api"),
                            _cmd("python3", "nettacker.py", "--start-api",
                                 fichier="nettacker.py"),
                            note="La clé d'accès à la page s'affiche au démarrage."),
    "MITRE Caldera": _web("http://127.0.0.1:8888", _compose("caldera"),
                          _cmd("python3", "server.py", "--insecure", fichier="server.py"),
                          attente=120),
    "Infection Monkey": _web("https://127.0.0.1:5000", _docker("monkey-island"),
                             _compose("monkey"), attente=120),
    "PentAGI": _web("https://127.0.0.1:8443", _compose("pentagi"), attente=180, ia=True,
                    note="Il lui faut une clé d'IA (fichier .env de PentAGI)."),
    "ARTEX": _web("http://127.0.0.1:8787", _compose("artex"), attente=300, ia=True,
                  note="Attaquant IA AUTONOME : un planificateur enchaîne de vrais outils "
                       "offensifs tout seul. À ouvrir UNIQUEMENT sur ton labo ou une cible à "
                       "toi (coche obligatoire), jamais sur la cible d'autrui. Il lui faut "
                       "Docker, PostgreSQL (fournis par sa compose) et une clé d'IA "
                       "(ANTHROPIC_API_KEY ou OPENAI_API_KEY, dans le .env ou sa page). "
                       "Le jeton de configuration s'affiche dans les journaux au 1er démarrage."),
    "RedAmon": _web("http://127.0.0.1:3000", _compose("redamon"), attente=180, ia=True,
                    note="Il lui faut une clé d'IA, réglée dans sa page « Settings »."),
    "Bettercap": _web("http://127.0.0.1", _admin("bettercap", "-caplet", "http-ui")),
    # --- Consoles (l'outil se pilote au clavier) ----------------------------
    "osquery": _console(["osqueryi"]),
    "radare2": _console(["r2", "-"]),
    "Recon-ng": _console(["recon-ng"]),
    "Metasploit Framework": _console(["msfconsole"]),
    # Shannon n'est pas installé par Vigie (offensif) : il passe par « npx », qui le
    # télécharge au 1er lancement. Il lui faut Node 22 ou plus (celui de Vigie s'il est
    # là) et Docker. Le 28/11/2026, avec le Node d'Ubuntu, le terminal restait vide.
    "Shannon": _console(["shannon"], [NPX22, "--yes", "@keygraph/shannon@latest"], ia=True,
                        besoin=["docker", "node22"],
                        intro="Shannon démarre. Au 1er lancement, il se télécharge "
                              "(1 à 3 minutes sans rien afficher) : patiente. Il pose ensuite "
                              "ses questions à l'écran, en anglais (clé d'IA, cible, dossier du "
                              "code source).",
                        note="Son lanceur pose les questions à l'écran (clé d'IA, cible). "
                             "Il lui faut Docker, Node 22 et une clé d'IA. Il lit le CODE "
                             "SOURCE de l'appli testée : seulement TON appli."),
    # PentestGPT s'arrêtait en anglais « No LLM provider is configured » (28/11/2026) :
    # le terminal demande d'abord, en français, quel fournisseur et quelle clé.
    "PentestGPT": _console(["pentestgpt"], ia=True,
                           intro="PentestGPT : assistant d'IA pour les tests d'intrusion. "
                                 "Il lui faut une clé d'IA (payante, chez le fournisseur).",
                           script=CLE_IA + "{cmd}",
                           note="Il lui faut une clé d'IA : le terminal te la demande au "
                                "démarrage (elle n'est pas enregistrée). Seulement sur TES "
                                "cibles."),
    # Strix ne démarre pas sans cible ni clé d'IA (28/11/2026) : le terminal pose les
    # questions en français, puis lance « strix --target ». Bac à sable Docker.
    "Strix": _console(["strix"], ia=True, besoin=["docker"],
                      intro="Strix : agents d'IA qui testent TON site ou TON code. "
                            "Réponds aux questions ci-dessous.",
                      script=(
                          'if [ -z "$LLM_API_KEY" ]; then read -r -s -p "Ta clé d\'IA '
                          '(elle ne s\'affiche pas pendant que tu la colles) : " LLM_API_KEY; '
                          'echo; export LLM_API_KEY; fi; '
                          'if [ -z "$STRIX_LLM" ]; then read -r -p "Modèle d\'IA, '
                          'par exemple openai/gpt-5 ou anthropic/<nom du modèle> : " '
                          'STRIX_LLM; export STRIX_LLM; fi; '
                          'read -r -p "Cible : TON site (https://…) ou le dossier de TON '
                          'code : " cible; {cmd} --target "$cible"'),
                      note="Il lui faut Docker et une clé d'IA. Le terminal te demande la "
                           "clé, le modèle et la cible. Seulement TON site ou TON code."),
    # --- Dans le navigateur --------------------------------------------------
    "CyberChef": {"genre": "page", "url": "https://gchq.github.io/CyberChef/",
                  "fichiers": ["cyberchef/CyberChef*.html", "CyberChef/CyberChef*.html",
                               "cyberchef/*.html"],
                  "note": "Tout se passe dans le navigateur : rien n'est envoyé ailleurs."},
    "InVID-WeVerify": {"genre": "lien",
                       "url": "https://github.com/AFP-Medialab/verification-plugin",
                       "note": "C'est une extension du navigateur : sa page explique comment "
                               "l'ajouter."},
}

GENRES = {"appli": "Logiciel à fenêtres", "web": "Page web du service",
          "console": "Console (au clavier)", "page": "Dans le navigateur",
          "lien": "Extension du navigateur"}

# Familles qui demandent de cocher l'engagement avant d'ouvrir.
SOUS_ENGAGEMENT = {"audit", "gate"}

JOURNAL = "journal"


class Refus(Exception):
    """L'outil ne peut pas s'ouvrir : la raison est en français."""


# ---------------------------------------------------------------------------
# Le registre
_REGISTRE = None


def _fiche(nom):
    global _REGISTRE
    if _REGISTRE is None:
        _REGISTRE = {o["nom"]: o for o in registre.charger()}
    return _REGISTRE.get(nom)


def famille(nom):
    return (_fiche(nom) or {}).get("famille", "")


def demande_engagement(nom):
    return famille(nom) in SOUS_ENGAGEMENT


def systeme():
    return platform.system()


# ---------------------------------------------------------------------------
# Regarder la machine (sans rien lancer)
def _hote_port(url):
    morceaux = urllib.parse.urlsplit(url)
    port = morceaux.port or (443 if morceaux.scheme == "https" else 80)
    return morceaux.hostname or "127.0.0.1", port


def repond(url, delai=0.5):
    """Le service écoute-t-il à cette adresse ? (on ouvre une connexion, rien de plus)"""
    hote, port = _hote_port(url)
    try:
        with socket.create_connection((hote, port), timeout=delai):
            return True
    except OSError:
        return False


def _trouver(argv0):
    if argv0 == NPX22:
        return npx22()
    argv0 = os.path.expanduser(argv0)
    if os.path.isabs(argv0):
        return argv0 if os.access(argv0, os.X_OK) else None
    return outils.trouver(argv0)


def npx22():
    """Le « npx » d'un Node 22 ou plus, ou None."""
    for racine in _dossiers_outils()[:3]:
        npx = os.path.join(racine, f"node{recettes.NODE_MINIMUM}", "bin", "npx")
        if os.access(npx, os.X_OK):
            return npx
    npx = outils.trouver("npx")
    node = outils.trouver("node")
    if npx and node and recettes.version_node(node) >= recettes.NODE_MINIMUM:
        return npx
    return None


# ---------------------------------------------------------------------------
# Docker : beaucoup de services (ARTEX, Web-Check, Wazuh…) tournent en conteneurs.
# Le 28/11/2026, ARTEX apparaissait « pas installé » sur la VM sans dire pourquoi :
# Vigie dit maintenant précisément ce qui manque.
DOCKER_MESSAGES = {
    "absent": "Docker n'est pas installé sur cette machine. Relance l'installeur de Vigie : "
              "il pose Docker, puis redémarre la machine.",
    "arrete": "Docker est installé mais arrêté. Redémarre la machine (Docker démarre avec "
              "elle), puis réessaie.",
    "droits": "Docker est installé, mais ton compte n'a pas encore le droit de s'en servir. "
              "Relance l'installeur de Vigie (il te donne ce droit), puis redémarre la "
              "machine.",
}

_CACHE_ETAT_DOCKER = {"quand": 0.0, "etat": ""}


def _dans_groupe_docker():
    """Le compte est-il inscrit dans le groupe docker (même si la session ne le sait pas
    encore, avant de se reconnecter) ?"""
    try:
        import grp
        import pwd
        utilisateur = pwd.getpwuid(os.getuid()).pw_name
        return utilisateur in grp.getgrnam("docker").gr_mem
    except (ImportError, KeyError, OSError):
        return False


def docker_etat():
    """"ok", "sg" (droit donné, session pas encore rafraîchie : on passe par « sg »),
    "absent", "arrete" ou "droits"."""
    if time.time() - _CACHE_ETAT_DOCKER["quand"] < 15 and _CACHE_ETAT_DOCKER["etat"]:
        return _CACHE_ETAT_DOCKER["etat"]
    if not outils.trouver("docker"):
        etat_ = "absent"
    else:
        code, sortie = _executer(["docker", "info", "--format", "{{.ServerVersion}}"], 8)
        bas = sortie.lower()
        if code == 0:
            etat_ = "ok"
        elif "permission denied" in bas:
            etat_ = "sg" if _dans_groupe_docker() and shutil.which("sg") else "droits"
        else:
            etat_ = "arrete"
        if etat_ == "sg":
            code, _ = _executer(["sg", "docker", "-c", "docker info"], 8)
            etat_ = "sg" if code == 0 else "arrete"
    _CACHE_ETAT_DOCKER.update(quand=time.time(), etat=etat_)
    return etat_


def docker_pret():
    return docker_etat() in ("ok", "sg")


def _avec_docker(argv):
    """La ligne à lancer pour une commande docker (via « sg docker » si besoin)."""
    if argv and argv[0] == "docker" and docker_etat() == "sg":
        return ["sg", "docker", "-c", " ".join(_citer(a) for a in argv)]
    return argv


def _dossiers_outils():
    racine = recettes.dossiers()[0]
    return [racine, "/opt/vigie-outils", os.path.expanduser("~/vigie-outils"),
            os.path.expanduser("~")]


def dossier_outil(nom, fichier):
    """Le dossier de l'outil qui contient ce fichier (pour les outils copiés depuis
    leur dépôt : SpiderFoot, Caldera…). None s'il n'est pas trouvé."""
    for racine in _dossiers_outils():
        for sous in (nom, nom.lower(), nom.capitalize()):
            chemin = os.path.join(racine, sous)
            if os.path.isfile(os.path.join(chemin, fichier)):
                return chemin
    return None


_COMPOSE = ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")


def dossier_compose(nom):
    for racine in _dossiers_outils():
        for sous in (nom, nom.lower()):
            chemin = os.path.join(racine, sous)
            if any(os.path.isfile(os.path.join(chemin, f)) for f in _COMPOSE):
                return chemin
    return None


def _executer(argv, delai=8, dossier=None):
    try:
        fini = subprocess.run(argv, capture_output=True, text=True, timeout=delai,
                              cwd=dossier, env=_environnement())
        return fini.returncode, (fini.stdout or "") + (fini.stderr or "")
    except (OSError, subprocess.SubprocessError) as erreur:
        return 1, str(erreur)


_CACHE_DOCKER = {"quand": 0.0, "noms": set()}


def conteneurs():
    """Les noms des conteneurs Docker de la machine (vide sans Docker)."""
    if time.time() - _CACHE_DOCKER["quand"] < 15:
        return _CACHE_DOCKER["noms"]
    noms = set()
    if outils.trouver("docker") and docker_pret():
        code, sortie = _executer(_avec_docker(["docker", "ps", "-a", "--format",
                                               "{{.Names}}"]), 6)
        if code == 0:
            noms = {ligne.strip() for ligne in sortie.splitlines() if ligne.strip()}
    _CACHE_DOCKER.update(quand=time.time(), noms=noms)
    return noms


def service_existe(nom):
    if not shutil.which("systemctl"):
        return False
    code, sortie = _executer(["systemctl", "list-unit-files", f"{nom}.service",
                              "--no-legend", "--no-pager"], 5)
    return code == 0 and nom.lower() in sortie.lower()


def moyen_disponible(moyen):
    """Ce moyen de démarrer existe-t-il sur cette machine ?"""
    genre = moyen["moyen"]
    if genre in ("cmd", "admin"):
        if not _trouver(moyen["argv"][0]):
            return False
        if moyen.get("fichier") and moyen["argv"][0] in _INTERPRETES:
            return bool(dossier_outil(moyen.get("_outil", ""), moyen["fichier"]))
        return True
    if genre == "service":
        return service_existe(moyen["nom"])
    if genre == "docker":
        return moyen["nom"] in conteneurs()
    if genre == "compose":
        return docker_pret() and bool(dossier_compose(moyen["nom"]))
    return False


def manques(nom):
    """Ce qui manque, précisément et en français, pour ouvrir cet outil ici (vide si rien).
    Exemple : ARTEX = dossier bien copié, mais Docker absent."""
    fiche = INTERFACES[nom]
    raisons = []
    if fiche["genre"] == "console":
        besoin = fiche.get("besoin", [])
        if "docker" in besoin and not docker_pret():
            raisons.append(DOCKER_MESSAGES[docker_etat()])
        if "node22" in besoin and not npx22() and not _trouver(
                fiche["commandes"][0][0]):
            raisons.append("Il lui faut Node 22 ou plus. Relance l'installeur de Vigie : il "
                           "pose Node 22 à part (pour sitespeed.io), Shannon s'en servira.")
        return raisons
    if fiche["genre"] != "web":
        return raisons
    moyens = fiche.get("demarrer", [])
    if any(moyen_disponible(dict(m, _outil=_dossier_nom(nom))) for m in moyens):
        return raisons
    conteneurs_ = [m for m in moyens if m["moyen"] in ("docker", "compose")]
    if conteneurs_ and len(conteneurs_) == len(moyens) and not docker_pret():
        raisons.append(DOCKER_MESSAGES[docker_etat()])
    composes = [m for m in moyens if m["moyen"] == "compose"]
    if composes and not any(dossier_compose(m["nom"]) for m in composes):
        if recettes.RECETTES.get(nom.lower()):
            raisons.append(f"Le dossier de {nom} n'est pas encore sur la machine : relance "
                           "l'installeur de Vigie, il le copie.")
    return raisons


# Un script lancé par un interprète : il faut trouver le dossier de l'outil.
_INTERPRETES = ("python3", "node")


def _moyens(nom):
    """Les moyens de démarrer déclarés, avec le nom de l'outil (pour chercher son dossier)."""
    moyens = [dict(m, _outil=_dossier_nom(nom)) for m in INTERFACES[nom].get("demarrer", [])]
    lanceur = lanceur_a_la_main(nom)
    if lanceur and not any(m["moyen"] == "cmd" and _trouver(m["argv"][0]) == lanceur
                           for m in moyens):
        moyens.append({"moyen": "cmd", "argv": [lanceur], "_outil": _dossier_nom(nom)})
    return moyens


def pistes(nom):
    """Ce que Vigie a cherché sur la machine, en français (pour les outils absents)."""
    fiche = INTERFACES[nom]
    commandes = [a[0] for a in fiche.get("commandes", [])]
    services, conteneurs_, dossiers = [], [], []
    for m in fiche.get("demarrer", []):
        if m["moyen"] in ("cmd", "admin") and m["argv"][0] not in _INTERPRETES:
            commandes.append(m["argv"][0])
        elif m["moyen"] in ("cmd", "admin"):
            dossiers.append(f"{_dossier_nom(nom)}/{m['fichier']}")
        elif m["moyen"] == "service":
            services.append(m["nom"])
        elif m["moyen"] == "docker":
            conteneurs_.append(m["nom"])
        elif m["moyen"] == "compose":
            dossiers.append(f"{m['nom']}/docker-compose.yml")
    for binaire in _binaires_connus(nom):
        if binaire not in commandes:
            commandes.append(binaire)
    morceaux = []
    if commandes:
        morceaux.append("la commande " + " ou ".join(dict.fromkeys(os.path.basename(c)
                                                                   for c in commandes)))
    if services:
        morceaux.append("le service " + " ou ".join(services))
    if conteneurs_:
        morceaux.append("le conteneur Docker " + " ou ".join(conteneurs_))
    if dossiers:
        morceaux.append("le dossier " + " ou ".join(dossiers))
    return morceaux


def _dossier_nom(nom):
    """« OWASP Nettacker » -> « nettacker », « MITRE Caldera » -> « caldera »…"""
    mots = re.sub(r"\(.*?\)", "", nom).split()
    return (mots[-1] if mots else nom).lower()


def commande_dispo(nom):
    """Pour une appli ou une console : la première commande qui existe ici (ou None)."""
    for argv in INTERFACES[nom].get("commandes", []):
        if _trouver(argv[0]):
            return argv
    # Outil posé à la main ou installé sous un autre nom : la commande que Vigie connaît
    # pour lui (presence.py, rapport d'installation, « Je l'ai installé à la main »).
    for binaire in _binaires_connus(nom):
        if _trouver(binaire):
            return [binaire]
    return None


def _binaires_connus(nom):
    from . import presence
    try:
        return presence.binaires_possibles(nom, presence.rapport_installation())
    except Exception:  # un rapport d'installation abîmé ne doit pas casser l'onglet
        return []


def lanceur_a_la_main(nom):
    """Le lanceur écrit par « Je l'ai installé à la main » pour cet outil, ou None."""
    from . import a_la_main
    for binaire in _binaires_connus(nom):
        chemin = _trouver(binaire)
        if not chemin:
            continue
        try:
            with open(chemin, encoding="utf-8", errors="replace") as fichier:
                if a_la_main.MARQUE in fichier.read(2000):
                    return chemin
        except OSError:
            continue
    return None


def _appli_mac(nom):
    appli = INTERFACES[nom].get("mac")
    if not appli or systeme() != "Darwin":
        return None
    code, _ = _executer(["open", "-Ra", appli], 5)
    return appli if code == 0 else None


def fichier_local(nom):
    for racine in _dossiers_outils()[:3]:
        for motif in INTERFACES[nom].get("fichiers", []):
            trouves = sorted(glob.glob(os.path.join(racine, motif)))
            if trouves:
                return trouves[-1]
    return None


def etat(nom):
    """{"present": True/False, "en_marche": True/False/None} sans rien lancer."""
    fiche = INTERFACES[nom]
    genre = fiche["genre"]
    if genre == "console":
        return {"present": bool(commande_dispo(nom)) and not manques(nom),
                "en_marche": None}
    if genre == "appli":
        return {"present": bool(commande_dispo(nom) or _appli_mac(nom)), "en_marche": None}
    if genre == "web":
        en_marche = repond(fiche["url"])
        present = en_marche or any(moyen_disponible(m) for m in _moyens(nom))
        return {"present": present, "en_marche": en_marche}
    if genre == "page":
        return {"present": True, "en_marche": None}
    return {"present": True, "en_marche": None}


# ---------------------------------------------------------------------------
# Ouvrir
def _environnement(nom=""):
    """L'environnement des programmes lancés. Un outil d'IA reçoit en plus la clé d'IA
    enregistrée dans Vigie (cles_ia.py) ; les autres outils, jamais."""
    env = dict(os.environ)
    env["PATH"] = outils.chemin_recherche()
    if INTERFACES.get(nom, {}).get("ia"):
        from . import cles_ia
        env.update(cles_ia.environnement())
    return env


def _dossier_vigie(sous):
    chemin = os.path.join(os.path.expanduser("~/.local/share/vigie"), sous)
    os.makedirs(chemin, exist_ok=True)
    return chemin


def journal_fichier(nom):
    slug = re.sub(r"[^a-z0-9]+", "-", nom.lower()).strip("-") or "outil"
    return os.path.join(_dossier_vigie("journaux-interfaces"), f"{slug}.log")


def _ecran_disponible():
    if systeme() != "Linux":
        return True
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


SANS_CLE_IA = ("{nom} a besoin de ta clé d'IA. Entre-la une seule fois en haut de "
               "« Ouvrir un outil », partie « Ta clé d'IA » : Vigie la garde et la donne "
               "à tous les outils d'IA.")

SANS_ECRAN = ("Vigie a été démarré sans écran (par exemple à distance, par SSH) : la "
              "fenêtre de l'outil ne peut pas s'afficher. Démarre Vigie depuis le bureau "
              "de la machine (double-clic), puis réessaie.")


def _detacher(argv, titre):
    """Démarre un programme qui continue de tourner après la réponse de Vigie."""
    return _detacher_journal(argv, open(journal_fichier(titre), "ab"), nom=titre)


def _detacher_journal(argv, journal, dossier=None, nom=""):
    try:
        return subprocess.Popen(argv, cwd=dossier or None, stdin=subprocess.DEVNULL,
                                stdout=journal, stderr=subprocess.STDOUT,
                                start_new_session=True, env=_environnement(nom))
    except OSError as erreur:
        raise Refus(f"Le programme n'a pas pu démarrer : {erreur}.") from erreur
    finally:
        journal.close()


def _lire(chemin, taille=6000):
    try:
        with open(chemin, "rb") as fichier:
            fichier.seek(0, os.SEEK_END)
            fichier.seek(max(0, fichier.tell() - taille))
            return fichier.read().decode("utf-8", "replace")
    except OSError:
        return ""


def _echec(nom, sortie):
    raisons = erreurs.expliquer(sortie)
    texte = f"{nom} s'est arrêté tout de suite."
    if raisons:
        texte += " " + " ".join(raisons)
    else:
        texte += " Le message de l'outil est dans « Détail technique »."
    return texte


def _surveiller(processus, nom, chemin_journal, secondes=4):
    """Attend quelques secondes : si le programme s'arrête en erreur, on le dit."""
    fin = time.time() + secondes
    while time.time() < fin:
        code = processus.poll()
        if code is not None:
            if code != 0:
                raise Refus(_echec(nom, _lire(chemin_journal)))
            return
        time.sleep(0.3)


def _ouvrir_terminal(argv, titre, intro="", chemin_en_plus="", script=""):
    """Ouvre une fenêtre de terminal qui lance argv et reste ouverte à la fin.
    intro : phrase en français affichée d'abord ; chemin_en_plus : dossier mis en tête
    du PATH (le Node 22 de Vigie pour « npx ») ; script : questions puis lancement."""
    ligne = " ".join(_citer(a) for a in argv)
    if script:
        ligne = script.replace("{cmd}", ligne)
    if chemin_en_plus:
        ligne = f'export PATH={_citer(chemin_en_plus)}:"$PATH"; {ligne}'
    if intro:
        ligne = f"echo {_citer(intro)}; echo; {ligne}"
    garde = f"{ligne}; echo; read -r -p 'Appuie sur Entrée pour fermer cette fenêtre.' _"
    if systeme() == "Darwin":
        script = ligne.replace("\\", "\\\\").replace('"', '\\"')
        return ["osascript", "-e", f'tell application "Terminal" to do script "{script}"',
                "-e", 'tell application "Terminal" to activate']
    for terminal in (["gnome-terminal", f"--title={titre}", "--", "bash", "-c", garde],
                     ["konsole", "-e", "bash", "-c", garde],
                     ["xfce4-terminal", "-x", "bash", "-c", garde],
                     ["x-terminal-emulator", "-e", "bash", "-c", garde],
                     ["xterm", "-T", titre, "-e", "bash", "-c", garde]):
        if shutil.which(terminal[0]):
            return terminal
    return None


def _citer(mot):
    return mot if re.fullmatch(r"[A-Za-z0-9_@%+=:,./-]+", mot) else "'" + mot.replace(
        "'", "'\\''") + "'"


def noter_ouverture(nom, journal=JOURNAL):
    os.makedirs(journal, exist_ok=True)
    ligne = {"quand": datetime.datetime.now().isoformat(timespec="seconds"),
             "outil": nom, "famille": famille(nom), "action": "ouverture de l'interface",
             "engagement": "labo ou cible couverte par une autorisation signée"}
    with open(os.path.join(journal, "ouvertures.jsonl"), "a", encoding="utf-8") as fichier:
        fichier.write(json.dumps(ligne, ensure_ascii=False) + "\n")


def verifier(nom, engagement=False):
    """Lève Refus si l'outil ne peut pas être ouvert depuis cet onglet."""
    if nom not in INTERFACES:
        raise Refus("Cet outil n'a pas d'interface à ouvrir depuis Vigie.")
    if demande_engagement(nom) and not engagement:
        raise Refus(f"{nom} est un outil d'audit ou offensif. Coche d'abord la case : tu ne "
                    "vises que ton labo ou une cible couverte par une autorisation signée.")
    if INTERFACES[nom].get("ia"):
        from . import cles_ia
        if not cles_ia.lire():
            raise Refus(SANS_CLE_IA.format(nom=nom))


def ouvrir(nom, suivre=lambda texte: None, engagement=False, journal=JOURNAL):
    """Ouvre l'outil. Renvoie {"message", "url" (ou ""), "detail"}. Lève Refus sinon.
    suivre(texte) reçoit l'avancement en français (pour la page qui se met à jour)."""
    verifier(nom, engagement)
    if demande_engagement(nom):
        noter_ouverture(nom, journal)
    fiche = INTERFACES[nom]
    genre = fiche["genre"]
    if genre == "lien":
        return {"message": f"Page officielle de {nom}.", "url": fiche["url"], "detail": ""}
    if genre == "page":
        local = fichier_local(nom)
        if local and _ecran_disponible():
            ouvreur = "open" if systeme() == "Darwin" else "xdg-open"
            if shutil.which(ouvreur):
                _detacher([ouvreur, local], nom)
                return {"message": f"{nom} s'ouvre dans le navigateur de la machine "
                                   "(copie locale).", "url": "", "detail": local}
        return {"message": f"{nom} s'ouvre dans le navigateur (page officielle).",
                "url": fiche["url"], "detail": ""}
    if genre == "appli":
        return _ouvrir_appli(nom, fiche, suivre)
    if genre == "console":
        return _ouvrir_console(nom, fiche)
    return _ouvrir_web(nom, fiche, suivre)


def _ouvrir_appli(nom, fiche, suivre):
    appli_mac = _appli_mac(nom)
    argv = commande_dispo(nom)
    if not argv and not appli_mac:
        raise Refus(f"{nom} n'est pas installé sur cette machine (aucune de ses commandes "
                    "n'a été trouvée).")
    if not _ecran_disponible():
        raise Refus(SANS_ECRAN)
    if appli_mac:
        argv = ["open", "-a", appli_mac]
    suivre(f"Démarrage de {nom}…")
    chemin = journal_fichier(nom)
    processus = _detacher_journal(argv, open(chemin, "ab"))
    _surveiller(processus, nom, chemin)
    url = ""
    if fiche.get("url_apres"):
        for _ in range(16):
            if repond(fiche["url_apres"]):
                url = fiche["url_apres"]
                break
            time.sleep(0.5)
    message = (f"{nom} est ouvert dans le navigateur." if url else
               f"{nom} s'ouvre dans sa propre fenêtre, sur l'écran de la machine.")
    return {"message": message, "url": url, "detail": " ".join(argv)}


def _ouvrir_console(nom, fiche):
    argv = commande_dispo(nom)
    if not argv:
        raise Refus(f"{nom} n'est pas installé sur cette machine (aucune de ses commandes "
                    "n'a été trouvée).")
    manque = manques(nom)
    if manque:
        raise Refus(f"{nom} ne peut pas démarrer ici : " + " ".join(manque))
    if not _ecran_disponible():
        raise Refus(SANS_ECRAN)
    chemin = _trouver(argv[0])
    en_plus = os.path.dirname(chemin) if argv[0] == NPX22 else ""
    script = fiche.get("script", "")
    if fiche.get("ia"):
        # Le terminal ne reçoit pas toujours l'environnement de Vigie : il relit la clé.
        from . import cles_ia
        script = (f"set -a; . {_citer(cles_ia.fichier())} 2>/dev/null; set +a; "
                  + (script or "{cmd}"))
    terminal = _ouvrir_terminal([chemin] + argv[1:], f"Vigie - {nom}",
                                fiche.get("intro", ""), en_plus, script)
    if not terminal:
        raise Refus("Aucun terminal trouvé sur cette machine pour ouvrir la console.")
    _detacher(terminal, nom)
    return {"message": f"{nom} s'ouvre dans une fenêtre de terminal, sur l'écran de la "
                       "machine. On le pilote au clavier.", "url": "",
            "detail": " ".join(argv)}


def _demarrer(nom, moyen, suivre):
    """Lance un moyen de démarrage. Renvoie le chemin de son journal."""
    genre = moyen["moyen"]
    chemin = journal_fichier(nom)
    if genre == "cmd":
        dossier = None
        if moyen.get("fichier"):
            dossier = dossier_outil(moyen["_outil"], moyen["fichier"])
            if not dossier and moyen["argv"][0] not in _INTERPRETES:
                # Le programme lit ses réglages à côté de lui (Gophish : config.json).
                dossier = os.path.dirname(os.path.realpath(_trouver(moyen["argv"][0])))
        elif moyen.get("dossier"):
            dossier = _dossier_vigie(moyen["dossier"])
            if moyen.get("avant") and not os.listdir(dossier):
                suivre("Préparation (première fois seulement)…")
                for argv in moyen["avant"]:
                    _executer(argv, 300, dossier)
        suivre(f"Démarrage : {' '.join(moyen['argv'])}")
        processus = _detacher_journal(moyen["argv"], open(chemin, "ab"), dossier, nom)
        _surveiller(processus, nom, chemin, 3)
    elif genre == "admin":
        if not shutil.which("pkexec") and systeme() == "Linux":
            raise Refus(f"{nom} doit démarrer en administrateur, et la fenêtre de mot de "
                        "passe (pkexec) manque sur cette machine.")
        suivre("Une fenêtre va demander ton mot de passe (droits administrateur).")
        processus = _detacher_journal(["pkexec", _trouver(moyen["argv"][0])]
                                      + moyen["argv"][1:], open(chemin, "ab"))
        _surveiller(processus, nom, chemin, 2)
    elif genre == "service":
        suivre(f"Démarrage du service {moyen['nom']} : une fenêtre va demander ton mot "
               "de passe.")
        code, sortie = _executer(["pkexec", "systemctl", "start", moyen["nom"]], 120)
        if code != 0:
            raise Refus(f"Le service {moyen['nom']} n'a pas démarré. "
                        + " ".join(erreurs.expliquer(sortie)))
    elif genre == "docker":
        suivre(f"Démarrage du conteneur {moyen['nom']}…")
        code, sortie = _executer(_avec_docker(["docker", "start", moyen["nom"]]), 120)
        if code != 0:
            raise Refus(f"Le conteneur {moyen['nom']} n'a pas démarré. "
                        + " ".join(erreurs.expliquer(sortie)))
    elif genre == "compose":
        dossier = dossier_compose(moyen["nom"])
        manque_place = place_docker_insuffisante(nom, dossier)
        if manque_place:
            raise Refus(manque_place)
        cree = preparer_env(dossier)
        if cree:
            suivre(cree)
        suivre("Démarrage des conteneurs Docker. La première fois, Docker télécharge et "
               "construit l'outil : 10 à 30 minutes, laisse cette page ouverte…")
        try:
            fini = subprocess.run(_avec_docker(["docker", "compose", "up", "-d"]),
                                  cwd=dossier, capture_output=True, text=True, timeout=2400,
                                  env=_environnement(nom))
        except (OSError, subprocess.SubprocessError) as erreur:
            raise Refus(f"Docker n'a pas pu démarrer {nom} : {erreur}.") from erreur
        if fini.returncode != 0:
            raise Refus(f"Docker n'a pas pu démarrer {nom}. "
                        + " ".join(erreurs.expliquer(fini.stdout + fini.stderr)))
    return chemin


# Place à prévoir avant un « docker compose up » (1re fois : téléchargement et
# construction des images). Le 28/11/2026, le disque de la VM s'est rempli : on vérifie
# AVANT, au lieu de laisser Docker échouer à mi-chemin.
PLACE_DOCKER_MO = {"ARTEX": 6000, "PentAGI": 8000, "RedAmon": 8000, "MISP": 6000,
                   "Wazuh": 8000, "BloodHound": 4000, "Flowsint": 4000}
PLACE_DOCKER_DEFAUT_MO = 3000


def _dossier_docker():
    code, sortie = _executer(_avec_docker(["docker", "info", "--format",
                                           "{{.DockerRootDir}}"]), 8)
    chemin = sortie.strip().splitlines()[-1] if code == 0 and sortie.strip() else ""
    return chemin if chemin.startswith("/") else "/var/lib/docker"


def _libre_mo(chemin):
    while chemin and not os.path.exists(chemin):
        chemin = os.path.dirname(chemin)
    try:
        return shutil.disk_usage(chemin or "/").free // (1024 * 1024)
    except OSError:
        return None


def place_docker_insuffisante(nom, dossier):
    """La raison en français s'il manque de la place pour démarrer cet outil Docker la
    première fois (images pas encore là), sinon ""."""
    besoin = PLACE_DOCKER_MO.get(nom, PLACE_DOCKER_DEFAUT_MO)
    if dossier:   # déjà construit une fois : le redémarrer ne prend presque rien
        code, sortie = _executer(_avec_docker(["docker", "compose", "images", "-q"]), 20,
                                 dossier)
        if code == 0 and sortie.strip():
            return ""
    for chemin, quoi in ((_dossier_docker(), "le disque de Docker"),
                         (dossier, "le disque des outils")):
        libre = _libre_mo(chemin)
        if libre is not None and libre < besoin:
            return (f"Pas assez de place pour démarrer {nom} : il faut environ "
                    f"{round(besoin / 1000)} Go sur {quoi}, il en reste "
                    f"{round(libre / 1000, 1)} Go. Double-clique sur « liberer-place.command » "
                    "(dans le dossier de Vigie), puis réessaie.")
    return ""


# Lignes d'un .env d'exemple dont la valeur est à remplacer par un vrai mot de passe.
_A_REMPLACER = re.compile(r"^([A-Z0-9_]*(?:PASSWORD|SECRET)[A-Z0-9_]*)=(change-?me[^\n]*)$",
                          re.M | re.I)


def preparer_env(dossier):
    """Un outil Docker Compose qui attend un fichier .env (ARTEX : « Please set
    POSTGRES_PASSWORD in .env ») : Vigie le crée depuis le .env.example du dépôt, avec des
    mots de passe tirés au hasard. Ne touche jamais un .env existant. Renvoie la phrase
    d'avancement, ou "" s'il n'y avait rien à faire."""
    if not dossier:
        return ""
    cible = os.path.join(dossier, ".env")
    exemple = os.path.join(dossier, ".env.example")
    if os.path.exists(cible) or not os.path.isfile(exemple):
        return ""
    import secrets
    with open(exemple, encoding="utf-8", errors="replace") as fichier:
        texte = fichier.read()
    texte = _A_REMPLACER.sub(lambda m: f"{m.group(1)}={secrets.token_urlsafe(24)}", texte)
    with open(cible, "w", encoding="utf-8") as fichier:
        fichier.write(texte)
    os.chmod(cible, 0o600)
    return "Réglages de départ créés (fichier .env, mots de passe tirés au hasard)."


# Page protégée par un jeton écrit au démarrage (mitmproxy 11 et plus).
JETON = re.compile(r"(https?://[^\s/]+/\?token=[A-Za-z0-9_-]+)")


def _url_avec_jeton(url, chemin):
    """L'adresse avec son jeton si l'outil en a écrit un dans son journal (le dernier)."""
    hote, port = _hote_port(url)
    for trouve in reversed(JETON.findall(_lire(chemin, 20000))):
        if _hote_port(trouve) == (hote, port):
            return trouve
    return url


MOT_DE_PASSE = re.compile(r"password\s+([A-Za-z0-9]{6,64})\b", re.I)


def _ouvrir_web(nom, fiche, suivre):
    url = fiche["url"]
    if repond(url):
        return {"message": f"{nom} tourne déjà : sa page s'ouvre.",
                "url": _url_avec_jeton(url, journal_fichier(nom)), "detail": ""}
    moyens = [m for m in _moyens(nom) if moyen_disponible(m)]
    if not moyens:
        manque = manques(nom)
        if manque:
            raise Refus(f"{nom} ne peut pas démarrer ici : " + " ".join(manque))
        raise Refus(f"{nom} ne tourne pas, et Vigie ne trouve pas comment le démarrer sur "
                    "cette machine (ni commande, ni service, ni conteneur Docker). "
                    "Il n'est sans doute pas installé ici.")
    if any(m["moyen"] in ("admin", "service") for m in moyens[:1]) and not _ecran_disponible():
        raise Refus(SANS_ECRAN)
    chemin = _demarrer(nom, moyens[0], suivre)
    suivre(f"On attend que {nom} réponde (jusqu'à {fiche['attente']} s)…")
    fin = time.time() + fiche["attente"]
    while time.time() < fin:
        if repond(url):
            trouve = MOT_DE_PASSE.search(_lire(chemin)) if nom == "Gophish" else None
            if trouve:   # on reste sur la page de Vigie pour qu'Anass le note
                return {"message": f"{nom} est prêt. Note son mot de passe de départ "
                                   f"(utilisateur admin) : {trouve.group(1)}",
                        "url": url, "detail": "", "garder": True}
            time.sleep(0.5)  # le jeton s'écrit juste après l'ouverture du port
            return {"message": f"{nom} est prêt : sa page s'ouvre.",
                    "url": _url_avec_jeton(url, chemin), "detail": ""}
        time.sleep(1)
    raise Refus(f"{nom} a été démarré mais ne répond pas encore sur {url}. Il est peut-être "
                "encore en train de se lancer : réessaie dans une minute. "
                + " ".join(erreurs.expliquer(_lire(chemin))))


def liste():
    """Les outils de l'onglet, rangés par famille puis par nom."""
    ordre = {"diag": 0, "secu": 1, "audit": 2, "gate": 3}
    return sorted(INTERFACES, key=lambda n: (ordre.get(famille(n), 9), n.lower()))
