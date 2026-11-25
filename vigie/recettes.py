"""Installations « à part » : les outils que la méthode générale rate sous Ubuntu.

La méthode générale (vigie/installeur.py) lit la ligne d'installation écrite dans la
documentation de l'outil. Le premier diagnostic complet sur la VM Ubuntu d'Anass
(24/11/2026) a montré six cas où cette ligne ne marche pas sous Ubuntu 24.04 :

  dnstwist     la doc dit « pipx install dnstwist » : c'est la version SANS module DNS.
               dnstwist s'arrête alors en 0 seconde dès qu'on lui donne des résolveurs.
               -> pipx, puis on lui ajoute dnspython (pipx inject).
  EyeWitness   « sudo apt install eyewitness » : n'existe que sur Kali, pas Ubuntu.
               -> copie du dépôt + environnement Python à part + petit lanceur.
  Metagoofil   pareil (Kali seulement). -> même méthode.
  PhoneInfoga  « go install » échoue (il lui manque son interface web précompilée) et la
               doc propose un script téléchargé à exécuter (interdit ici).
               -> le programme officiel publié sur la page GitHub de l'outil, vérifié
               par son empreinte (fichier de sommes publié au même endroit).
  uncover      écarté comme « payant » : faux, l'outil est libre ; ce sont certaines
               sources (Shodan, Censys) qui demandent une clé. -> go install, documenté.
  sitespeed.io et Unlighthouse
               demandent Node 22, Ubuntu 24.04 fournit Node 18.
               -> si le Node de la machine est trop vieux, Vigie pose un Node 22 À PART
               (site officiel nodejs.org, empreinte vérifiée), sans toucher au système.

Ajouts du 25/11/2026 (installation complète sur la VM Ubuntu, Python 3.14) :
  Gitleaks, Stratus Red Team   « go install » avec le vrai nom de module (/v8, /v2/cmd/…).
  TruffleHog, Trivy, Grype, Syft
               « brew » seulement : sous Linux, le programme officiel GitHub, empreinte
               vérifiée (le numéro de version est lu sur la page « Releases »).
  XSStrike, SSRFmap, jwt_tool, Responder, Zircolite, DPAT
               de simples scripts Python que pipx refuse -> dépôt + Python à part.
  ROADtools    la doc nomme la bibliothèque (roadlib) -> roadrecon et roadtx du dépôt.
  SecLists     des listes de mots, pas un programme -> copie du dépôt.
  npm          tous les outils npm passent par installer_npm() : Node 22, dossier de
               Vigie, aucun droit administrateur (avant : EACCES sur tous).
  MANUELS      les outils à poser à la main (serveurs, Windows, Kali, Kubernetes…),
               avec la raison en français, au lieu d'une erreur anglaise trompeuse.

Toujours la même règle : jamais un paquet deviné sur son nom. Chaque recette nomme le
dépôt exact de l'outil, ou le site officiel, et vérifie les empreintes publiées.
"""
import hashlib
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import urllib.request

# Les outils libres que le catalogue range à tort parmi les « payants » (clé API).
GRATUITS_MALGRE_CLE = {"uncover"}


def dossiers():
    """(dossier où Vigie range les outils à part, dossier des commandes)."""
    racine = os.environ.get("VIGIE_OUTILS_RACINE") or os.path.expanduser(
        "~/.local/share/vigie-outils")
    commandes = os.environ.get("PIPX_BIN_DIR") or os.path.expanduser("~/.local/bin")
    return racine, commandes


def _lancer(commande, delai=900, env=None, dossier=None):
    """(réussi, dernière ligne d'erreur, sortie complète)."""
    programme = shutil.which(commande[0], path=(env or os.environ).get("PATH"))
    if not programme:
        return False, f"{commande[0]} absent", ""
    try:
        fini = subprocess.run([programme] + commande[1:], capture_output=True, text=True,
                              timeout=delai, errors="replace", env=env, cwd=dossier,
                              stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return False, f"dépassement de {delai} s", ""
    sortie = (fini.stdout or "") + "\n" + (fini.stderr or "")
    if fini.returncode == 0:
        return True, "", sortie
    lignes = (fini.stderr or fini.stdout or "").strip().splitlines()
    return False, (lignes[-1][:140] if lignes else f"code {fini.returncode}"), sortie


def ecrire_lanceur(chemin, lignes):
    """Petit script qui lance l'outil avec SON Python ou SON Node (jamais ceux du système)."""
    os.makedirs(os.path.dirname(chemin), exist_ok=True)
    with open(chemin, "w", encoding="utf-8") as fichier:
        fichier.write("#!/bin/sh\n# Écrit par l'installeur de Vigie.\n" + "\n".join(lignes) + "\n")
    os.chmod(chemin, os.stat(chemin).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _telecharger(url, destination, delai=300):
    requete = urllib.request.Request(url, headers={"User-Agent": "Vigie-installeur"})
    with urllib.request.urlopen(requete, timeout=delai) as reponse, \
            open(destination, "wb") as fichier:
        shutil.copyfileobj(reponse, fichier)


def _empreinte(chemin):
    calcul = hashlib.sha256()
    with open(chemin, "rb") as fichier:
        for morceau in iter(lambda: fichier.read(1 << 20), b""):
            calcul.update(morceau)
    return calcul.hexdigest()


def lire_sommes(texte):
    """Fichier de sommes « empreinte  nom » -> {nom: empreinte}."""
    sommes = {}
    for ligne in (texte or "").splitlines():
        morceaux = ligne.split()
        if len(morceaux) == 2 and re.fullmatch(r"[0-9a-f]{64}", morceaux[0]):
            sommes[morceaux[1].lstrip("*")] = morceaux[0]
    return sommes


def _extraire_un(archive, membre_voulu, destination):
    """Sort UN fichier d'une archive, sans jamais écrire en dehors de la destination."""
    with tarfile.open(archive) as tar:
        for membre in tar.getmembers():
            if membre.isfile() and os.path.basename(membre.name) == membre_voulu:
                source = tar.extractfile(membre)
                with open(destination, "wb") as fichier:
                    shutil.copyfileobj(source, fichier)
                os.chmod(destination, 0o755)
                return True
    return False


def _extraire_tout(archive, destination):
    """Déballe une archive dans destination en retirant son dossier de tête."""
    os.makedirs(destination, exist_ok=True)
    racine = os.path.realpath(destination)
    with tarfile.open(archive) as tar:
        for membre in tar.getmembers():
            morceaux = membre.name.split("/", 1)
            if len(morceaux) < 2 or not morceaux[1]:
                continue
            cible = os.path.realpath(os.path.join(destination, morceaux[1]))
            if not cible.startswith(racine + os.sep):
                continue  # chemin piégé (« ../ ») : ignoré
            if membre.issym() or membre.islnk():
                lien = os.path.realpath(os.path.join(os.path.dirname(cible), membre.linkname))
                if not lien.startswith(racine + os.sep):
                    continue
            membre.name = morceaux[1]
            # filtre « data » (Python 3.12+) : en plus de nos propres garde-fous.
            options = {"filter": "data"} if hasattr(tarfile, "data_filter") else {}
            tar.extract(membre, destination, **options)


def _architecture():
    machine = platform.machine().lower()
    return {"x86_64": "x64", "amd64": "x64", "aarch64": "arm64", "arm64": "arm64"}.get(machine)


# ---------------------------------------------------------------------------
# Les recettes. Chacune renvoie (réussi, message, commandes à essayer pour la vérifier).

def pipx_avec_module(paquet, module):
    def recette():
        _lancer(["pipx", "install", paquet])  # déjà là : pipx le dit, on continue
        reussi, message, _ = _lancer(["pipx", "inject", paquet, module])
        return reussi, (message or ""), [paquet]
    return recette


def module_manquant(paquet, module):
    """Vrai si l'outil installé PAR PIPX n'a pas son module (cas de dnstwist).
    Un outil posé autrement (apt) n'est pas touché."""
    reussi, _, liste = _lancer(["pipx", "list", "--short"], delai=60)
    if not reussi or not re.search(rf"^{re.escape(paquet)}\s", liste, re.M):
        return False
    reussi, _, sortie = _lancer(["pipx", "runpip", paquet, "show", module], delai=60)
    return not reussi and "not found" in sortie.lower()


def depot_python(depot, requirements, script, commande, nom, nettoyer_pipx=None):
    """Copie du dépôt GitHub exact + environnement Python à part + lanceur.

    Pour les outils qui sont un simple script Python (XSStrike, SSRFmap, jwt_tool…) :
    pipx les refuse (« Check package spec for errors ») car ce ne sont pas des paquets.
    requirements : le fichier de dépendances, ou None pour installer le dossier
    lui-même s'il a un pyproject.toml / setup.py (sinon, aucune dépendance).
    nettoyer_pipx : un ancien paquet pipx posé de travers à retirer d'abord (DPAT).
    """
    def recette():
        racine, commandes = dossiers()
        if nettoyer_pipx:
            _lancer(["pipx", "uninstall", nettoyer_pipx], delai=120)
        dossier = os.path.join(racine, nom)
        if os.path.isdir(os.path.join(dossier, ".git")):
            reussi, message, _ = _lancer(["git", "-C", dossier, "pull", "--ff-only"])
        else:
            os.makedirs(racine, exist_ok=True)
            reussi, message, _ = _lancer(["git", "clone", "--depth", "1", depot, dossier])
        if not reussi:
            return False, "git : " + message, []
        venv = os.path.join(dossier, "vigie-venv")
        reussi, message, _ = _lancer([sys.executable, "-m", "venv", venv])
        if not reussi:
            return False, "python3 -m venv : " + message + " (paquet python3-venv ?)", []
        pip = os.path.join(venv, "bin", "pip")
        if requirements and os.path.exists(os.path.join(dossier, requirements)):
            reussi, message, _ = _lancer([pip, "install", "-r",
                                          os.path.join(dossier, requirements)])
        elif any(os.path.exists(os.path.join(dossier, f))
                 for f in ("pyproject.toml", "setup.py")):
            reussi, message, _ = _lancer([pip, "install", dossier])
            dependances = _dependances_pyproject(dossier)
            if not reussi and dependances:
                # Un dossier qui n'est pas un « paquet » (SSRFmap) : on pose juste la
                # liste de dépendances qu'il déclare lui-même.
                reussi, message, _ = _lancer([pip, "install"] + dependances)
        if not reussi:
            return False, "pip : " + message, []
        ecrire_lanceur(os.path.join(commandes, commande), [
            f'cd "{dossier}" 2>/dev/null || true',
            f'exec "{os.path.join(venv, "bin", "python")}" "{os.path.join(dossier, script)}" "$@"'])
        return True, "", [commande]
    return recette


def _dependances_pyproject(dossier):
    """La liste « dependencies » que le pyproject.toml du dépôt déclare."""
    try:
        import tomllib
        with open(os.path.join(dossier, "pyproject.toml"), "rb") as lu:
            liste = tomllib.load(lu).get("project", {}).get("dependencies", [])
    except (ImportError, OSError, ValueError):
        return []
    return [d for d in liste if isinstance(d, str) and not d.startswith("-")]


def depot_donnees(depot, nom):
    """Un dépôt qui n'est pas un programme mais des données (listes de mots : SecLists).
    Copie du dépôt exact. Renvoie None comme commandes : rien à « démarrer »."""
    def recette():
        racine, _ = dossiers()
        dossier = os.path.join(racine, nom)
        if os.path.isdir(os.path.join(dossier, ".git")):
            reussi, message, _ = _lancer(["git", "-C", dossier, "pull", "--ff-only"],
                                         delai=1800)
        else:
            os.makedirs(racine, exist_ok=True)
            reussi, message, _ = _lancer(["git", "clone", "--depth", "1", depot, dossier],
                                         delai=1800)
        return reussi, ("git : " + message if not reussi else ""), None
    return recette


def pipx_spec(*specs):
    """pipx sur une adresse exacte (ex. un sous-dossier du dépôt : ROADtools)."""
    def recette():
        poses = []
        for spec, binaire in specs:
            reussi, message, sortie = _lancer(["pipx", "install", spec])
            if not reussi and "already" not in sortie.lower():
                return False, "pipx : " + message, []
            poses.append(binaire)
        return True, "", poses
    return recette


def binaire_github(depot, archive, sommes, binaire):
    """Le programme officiel publié sur la page « Releases » du dépôt, empreinte vérifiée."""
    def recette():
        systeme = {"linux": "Linux", "darwin": "Darwin"}.get(sys.platform)
        arch = {"x64": "x86_64", "arm64": "arm64"}.get(_architecture() or "")
        if not systeme or not arch:
            return False, f"système non prévu ({sys.platform} {platform.machine()})", []
        nom_archive = archive.format(systeme=systeme, arch=arch)
        base = f"https://github.com/{depot}/releases/latest/download/"
        _, commandes = dossiers()
        with tempfile.TemporaryDirectory() as travail:
            chemin = os.path.join(travail, nom_archive)
            try:
                _telecharger(base + sommes, os.path.join(travail, "sommes.txt"))
                with open(os.path.join(travail, "sommes.txt"), encoding="utf-8") as lu:
                    attendue = lire_sommes(lu.read()).get(nom_archive)
                _telecharger(base + nom_archive, chemin)
            except OSError as erreur:
                return False, f"téléchargement impossible : {erreur}", []
            if not attendue or _empreinte(chemin) != attendue:
                return False, "empreinte du fichier téléchargé incorrecte : installation refusée", []
            os.makedirs(commandes, exist_ok=True)
            if not _extraire_un(chemin, binaire, os.path.join(commandes, binaire)):
                return False, f"{binaire} absent de l'archive", []
        return True, "", [binaire]
    return recette


def derniere_version(depot, delai=60):
    """L'étiquette de la dernière version publiée (ex. « v0.58.1 »), lue sur la page
    « Releases » du dépôt exact (GitHub redirige vers /releases/tag/<étiquette>)."""
    requete = urllib.request.Request(f"https://github.com/{depot}/releases/latest",
                                     headers={"User-Agent": "Vigie-installeur"})
    with urllib.request.urlopen(requete, timeout=delai) as reponse:
        adresse = reponse.geturl()
    trouve = re.search(r"/releases/tag/([^/?#]+)$", adresse)
    if not trouve:
        raise OSError("dernière version introuvable")
    return urllib.request.unquote(trouve.group(1))


# Les noms que les outils Go (goreleaser) donnent à leurs archives.
NOMS_SYSTEME = {"linux": {"os": "linux", "Os": "Linux", "mac": "Linux"},
                "darwin": {"os": "darwin", "Os": "Darwin", "mac": "macOS"}}
NOMS_ARCH = {"x64": {"goarch": "amd64", "bits": "64bit", "x86": "x86_64"},
             "arm64": {"goarch": "arm64", "bits": "ARM64", "x86": "arm64"}}


def binaire_versionne(depot, archive, sommes, binaire):
    """Comme binaire_github, pour les archives dont le nom porte le numéro de version
    (trivy_0.58.1_Linux-64bit.tar.gz) : on lit d'abord la dernière version publiée.
    Empreinte vérifiée avec le fichier de sommes publié au même endroit."""
    def recette():
        systeme = NOMS_SYSTEME.get("darwin" if sys.platform == "darwin" else
                                   "linux" if sys.platform.startswith("linux") else "")
        arch = NOMS_ARCH.get(_architecture() or "")
        if not systeme or not arch:
            return False, f"système non prévu ({sys.platform} {platform.machine()})", []
        try:
            etiquette = derniere_version(depot)
        except OSError as erreur:
            return False, f"page des versions injoignable : {erreur}", []
        valeurs = dict(systeme, **arch, version=etiquette.lstrip("v"))
        nom_archive, nom_sommes = archive.format(**valeurs), sommes.format(**valeurs)
        base = f"https://github.com/{depot}/releases/download/{etiquette}/"
        _, commandes = dossiers()
        with tempfile.TemporaryDirectory() as travail:
            chemin = os.path.join(travail, nom_archive)
            try:
                _telecharger(base + nom_sommes, os.path.join(travail, "sommes.txt"))
                with open(os.path.join(travail, "sommes.txt"), encoding="utf-8") as lu:
                    attendue = lire_sommes(lu.read()).get(nom_archive)
                _telecharger(base + nom_archive, chemin)
            except OSError as erreur:
                return False, f"téléchargement impossible : {erreur}", []
            if not attendue or _empreinte(chemin) != attendue:
                return False, "empreinte du fichier téléchargé incorrecte : installation refusée", []
            os.makedirs(commandes, exist_ok=True)
            if not _extraire_un(chemin, binaire, os.path.join(commandes, binaire)):
                return False, f"{binaire} absent de l'archive", []
        return True, "", [binaire]
    return recette


def go_install(module, binaire):
    def recette():
        reussi, message, _ = _lancer(["go", "install", "-v", module])
        return reussi, message, [binaire]
    return recette


NODE_MINIMUM = 22


def version_node(commande="node"):
    """Le numéro principal de la version de Node (18, 22…), ou 0 s'il est absent."""
    programme = shutil.which(commande)
    if not programme:
        return 0
    try:
        sortie = subprocess.run([programme, "--version"], capture_output=True, text=True,
                                timeout=20).stdout
    except (OSError, subprocess.TimeoutExpired):
        return 0
    trouve = re.match(r"v?(\d+)", sortie.strip())
    return int(trouve.group(1)) if trouve else 0


# Deux outils Node installés en même temps posaient Node 22 au même endroit en même
# temps (sitespeed.io et Unlighthouse, 25/11/2026) : l'un effaçait l'autre. Un seul à la fois.
VERROU_NODE = threading.Lock()


def node_a_part():
    """Pose Node 22 dans le dossier de Vigie (site officiel, empreinte vérifiée).
    Renvoie (dossier bin de ce Node, message d'erreur)."""
    with VERROU_NODE:
        return _node_a_part()


def _node_a_part():
    racine, _ = dossiers()
    dossier = os.path.join(racine, f"node{NODE_MINIMUM}")
    node = os.path.join(dossier, "bin", "node")
    if os.path.exists(node) and version_node(node) >= NODE_MINIMUM:
        return os.path.join(dossier, "bin"), ""
    arch = _architecture()
    systeme = {"linux": "linux", "darwin": "darwin"}.get(sys.platform)
    if not arch or not systeme:
        return None, f"système non prévu ({sys.platform} {platform.machine()})"
    base = f"https://nodejs.org/dist/latest-v{NODE_MINIMUM}.x/"
    with tempfile.TemporaryDirectory() as travail:
        try:
            _telecharger(base + "SHASUMS256.txt", os.path.join(travail, "sommes.txt"))
            with open(os.path.join(travail, "sommes.txt"), encoding="utf-8") as lu:
                sommes = lire_sommes(lu.read())
            nom = next((n for n in sorted(sommes)
                        if re.fullmatch(rf"node-v{NODE_MINIMUM}\.[\d.]+-{systeme}-{arch}\.tar\.gz", n)),
                       None)
            if not nom:
                return None, "archive de Node introuvable sur nodejs.org"
            chemin = os.path.join(travail, nom)
            _telecharger(base + nom, chemin)
        except OSError as erreur:
            return None, f"téléchargement de Node impossible : {erreur}"
        if _empreinte(chemin) != sommes[nom]:
            return None, "empreinte de Node incorrecte : installation refusée"
        if os.path.isdir(dossier):
            shutil.rmtree(dossier)
        _extraire_tout(chemin, dossier)
    return os.path.join(dossier, "bin"), ""


def commandes_npm(prefixe, paquet):
    """Les commandes qu'un paquet npm déclare (champ « bin » de son package.json)."""
    import json
    fiche = os.path.join(prefixe, "lib", "node_modules", paquet, "package.json")
    try:
        with open(fiche, encoding="utf-8") as lu:
            declare = json.load(lu).get("bin")
    except (OSError, ValueError):
        return []
    if isinstance(declare, str):
        return [paquet.split("/")[-1]]
    return sorted(declare) if isinstance(declare, dict) else []


def erreur_npm(sortie):
    """La ligne utile d'un échec npm. La dernière ligne (« npm ERR! … debug-0.log »)
    ne disait rien : on garde le code d'erreur et sa phrase d'explication."""
    lignes = [l.strip() for l in (sortie or "").splitlines() if l.strip()]
    utiles = [l for l in lignes if re.search(r"npm (?:ERR!|error) (?:code|errno|syscall|"
                                            r"path|notsup|engine|404|403)", l)]
    if not utiles:
        utiles = [l for l in lignes if re.match(r"npm (?:ERR!|error)", l)
                  and "debug-0.log" not in l and "complete log" not in l]
    return " ; ".join(utiles[:3])[:220]


def installer_npm(paquet, binaires=None):
    """npm install -g d'un paquet DOCUMENTÉ, sans jamais toucher au système :
      - avec un Node assez récent (celui de la machine s'il suffit, sinon Node 22 à part) ;
      - dans le dossier de Vigie (--prefix) : avant, npm visait /usr/lib et échouait
        faute de droits administrateur (EACCES) — c'est ce qui faisait rater TOUS les
        outils npm (Lighthouse, Pa11y, Retire.js, promptfoo…) ;
      - un petit lanceur par commande, qui utilise CE Node.
    Renvoie (réussi, message, commandes posées)."""
    if version_node() >= NODE_MINIMUM:
        bin_node = os.path.dirname(shutil.which("node"))
    else:
        bin_node, message = node_a_part()
        if not bin_node:
            return False, message, []
    racine, commandes = dossiers()
    prefixe = os.path.join(racine, "node-outils")
    npm = os.path.join(bin_node, "npm")
    if not os.path.exists(npm):
        npm = shutil.which("npm") or "npm"
    env = dict(os.environ, PATH=bin_node + os.pathsep + os.environ.get("PATH", ""),
               npm_config_cache=os.path.join(racine, "cache", "npm"),
               npm_config_update_notifier="false", npm_config_fund="false")
    reussi, message, sortie = _lancer([npm, "install", "-g", "--prefix", prefixe, paquet],
                                      env=env)
    if not reussi:
        return False, "npm : " + (erreur_npm(sortie) or message), []
    # La commande qui porte le nom du paquet d'abord (lighthouse avant chrome-debug).
    poses = sorted(binaires or commandes_npm(prefixe, paquet),
                   key=lambda b: b != paquet.split("/")[-1])
    for binaire in poses:
        ecrire_lanceur(os.path.join(commandes, binaire), [
            f'PATH="{bin_node}:$PATH"', "export PATH",
            f'exec "{os.path.join(prefixe, "bin", binaire)}" "$@"'])
    return True, "", poses


def npm_moderne(paquet, binaires):
    """Recette : npm avec un Node assez récent (voir installer_npm)."""
    def recette():
        return installer_npm(paquet, binaires)
    return recette


# nom (minuscules, comme dans le catalogue) -> (libellé, recette, systèmes concernés)
TOUS = ("linux", "darwin")
OFFICIEL = "programme officiel GitHub, empreinte vérifiée (recette Vigie)"
SCRIPT = "dépôt GitHub + Python à part (recette Vigie)"
RECETTES = {
    "dnstwist": ("pipx + module DNS (recette Vigie)", pipx_avec_module("dnstwist", "dnspython"),
                 TOUS),
    "eyewitness": ("dépôt GitHub + Python à part (recette Vigie)",
                   depot_python("https://github.com/RedSiege/EyeWitness",
                                "setup/requirements.txt", "Python/EyeWitness.py",
                                "eyewitness", "EyeWitness"), TOUS),
    "metagoofil": ("dépôt GitHub + Python à part (recette Vigie)",
                   depot_python("https://github.com/opsdisk/metagoofil", "requirements.txt",
                                "metagoofil.py", "metagoofil", "metagoofil"), TOUS),
    "phoneinfoga": ("programme officiel GitHub, empreinte vérifiée (recette Vigie)",
                    binaire_github("sundowndev/phoneinfoga",
                                   "phoneinfoga_{systeme}_{arch}.tar.gz",
                                   "phoneinfoga_checksums.txt", "phoneinfoga"), ("linux",)),
    "uncover": ("go (documenté)",
                go_install("github.com/projectdiscovery/uncover/cmd/uncover@latest", "uncover"),
                TOUS),
    "sitespeed.io": ("npm avec Node 22 (recette Vigie)",
                     npm_moderne("sitespeed.io", ["sitespeed.io"]), TOUS),
    "unlighthouse": ("npm avec Node 22 (recette Vigie)",
                     npm_moderne("unlighthouse", ["unlighthouse", "unlighthouse-ci"]), TOUS),
    # --- Ajoutés le 25/11/2026 après l'installation complète sur la VM Ubuntu. ---
    # « go install » visait le mauvais nom de module (le vrai porte /v8, /v2…).
    "gitleaks": ("go (module exact, recette Vigie)",
                 go_install("github.com/zricethezav/gitleaks/v8@latest", "gitleaks"), TOUS),
    "stratus red team": ("go (documenté)",
                         go_install("github.com/datadog/stratus-red-team/v2/cmd/stratus@latest",
                                    "stratus"), TOUS),
    # Sous Mac : brew. Sous Linux : le programme officiel publié sur GitHub, vérifié.
    "trufflehog": (OFFICIEL, binaire_versionne(
        "trufflesecurity/trufflehog", "trufflehog_{version}_{os}_{goarch}.tar.gz",
        "trufflehog_{version}_checksums.txt", "trufflehog"), ("linux",)),
    "trivy": (OFFICIEL, binaire_versionne(
        "aquasecurity/trivy", "trivy_{version}_{mac}-{bits}.tar.gz",
        "trivy_{version}_checksums.txt", "trivy"), ("linux",)),
    "grype": (OFFICIEL, binaire_versionne(
        "anchore/grype", "grype_{version}_{os}_{goarch}.tar.gz",
        "grype_{version}_checksums.txt", "grype"), ("linux",)),
    "syft": (OFFICIEL, binaire_versionne(
        "anchore/syft", "syft_{version}_{os}_{goarch}.tar.gz",
        "syft_{version}_checksums.txt", "syft"), ("linux",)),
    # De simples scripts Python (pas des paquets) : pipx les refuse.
    "xsstrike": (SCRIPT, depot_python("https://github.com/s0md3v/XSStrike", "requirements.txt",
                                      "xsstrike.py", "xsstrike", "XSStrike"), TOUS),
    "ssrfmap": (SCRIPT, depot_python("https://github.com/swisskyrepo/SSRFmap", None,
                                     "ssrfmap.py", "ssrfmap", "SSRFmap"), TOUS),
    "jwt_tool": (SCRIPT, depot_python("https://github.com/ticarpi/jwt_tool", "requirements.txt",
                                      "jwt_tool.py", "jwt_tool", "jwt_tool"), TOUS),
    "responder": (SCRIPT, depot_python("https://github.com/lgandx/Responder", "requirements.txt",
                                       "Responder.py", "responder", "Responder"), TOUS),
    "zircolite": (SCRIPT, depot_python("https://github.com/wagga40/Zircolite", None,
                                       "zircolite.py", "zircolite", "Zircolite"), TOUS),
    # pipx posait DPAT avec pour seules commandes « test » et « tests » (= pytest) !
    "dpat": (SCRIPT, depot_python("https://github.com/clr2of8/DPAT", "requirements.txt",
                                  "dpat.py", "dpat", "DPAT", nettoyer_pipx="dpat"), TOUS),
    # La doc disait « pip install roadlib » : c'est la bibliothèque, sans commande.
    "roadtools": ("pipx depuis le dépôt exact (recette Vigie)", pipx_spec(
        ("git+https://github.com/dirkjanm/ROADtools#subdirectory=roadrecon", "roadrecon"),
        ("git+https://github.com/dirkjanm/ROADtools#subdirectory=roadtx", "roadtx")), TOUS),
    # Des listes de mots (pour ffuf, Gobuster…), pas un programme. « apt » : Kali seulement.
    "seclists": ("copie du dépôt GitHub (recette Vigie)",
                 depot_donnees("https://github.com/danielmiessler/SecLists", "SecLists"), TOUS),
}


# Les outils que Vigie ne doit PAS essayer d'installer tout seul, avec la raison en
# français. Avant, il tentait « go install » ou « pipx » sur leur dépôt et affichait une
# erreur anglaise trompeuse. Ce ne sont pas des pannes : ils se posent à la main.
# nom (minuscules) -> (raison, systèmes concernés)
KALI = "paquet présent seulement dans Kali Linux, pas dans Ubuntu"
MANUELS = {
    "geo-sleuth": ("c'est une « compétence » pour assistant IA, pas un programme à installer",
                   TOUS),
    "xingrin": ("plateforme web à installer avec Docker (un serveur), pas un programme", TOUS),
    "arl-next": ("plateforme web à installer avec Docker (un serveur), pas un programme", TOUS),
    "mitre caldera": ("serveur à installer avec Docker ou à la main (voir sa doc)", TOUS),
    "grr rapid response": ("serveur + agents à poser sur les postes surveillés", TOUS),
    "velociraptor": ("serveur + agents ; programme à télécharger sur sa page officielle", TOUS),
    "crowdsec": ("service de protection qui tourne en permanence : il s'installe sur la "
                 "machine à protéger (chez le client), avec son dépôt officiel", TOUS),
    "coraza waf": ("bibliothèque pour serveur web (Caddy, Nginx), pas un programme seul", TOUS),
    "hardentools": ("outil pour Windows uniquement", TOUS),
    "artex": ("le dépôt d'origine a été supprimé : aucune source sûre", TOUS),
    "xalgorix": ("se compile à la main (Go + Node.js) : pas de méthode automatique sûre", TOUS),
    "adalanche": ("programme à télécharger sur sa page officielle (Releases)", TOUS),
    "dorkagent": ("demande des clés d'accès payantes (Serper + IA) : à poser à la main", TOUS),
    "sparrow-wifi": ("application graphique qui demande une carte Wi-Fi et les droits "
                     "administrateur", TOUS),
    "peass-ng (winpeas/linpeas)": ("scripts à déposer sur la machine auditée : ils se "
                                   "téléchargent sur leur page officielle, rien à installer ici",
                                   ("linux",)),
    "metasploit framework": (KALI + " ; ailleurs, son installeur officiel est un script à "
                             "exécuter, ce que Vigie refuse", ("linux",)),
    "owasp zap": (KALI + " ; ailleurs, installeur officiel (Java) sur zaproxy.org", ("linux",)),
    "airgeddon": (KALI + " ; ailleurs, il se lance depuis son dépôt en administrateur",
                  ("linux",)),
    "kismet": (KALI + " ; ailleurs, dépôt officiel sur kismetwireless.net", ("linux",)),
    "veracrypt": ("pas dans Ubuntu : paquet à télécharger sur veracrypt.fr", ("linux",)),
    "rustscan": ("sous Linux : paquet à télécharger sur sa page officielle ; Nmap (installé) "
                 "fait le même travail", ("linux",)),
    "feroxbuster": ("sous Linux : programme à télécharger sur sa page officielle ; ffuf et "
                    "Gobuster (installés) font le même travail", ("linux",)),
    "kubescape": ("ne sert que pour Kubernetes (rare chez une TPE) : à poser à la main si "
                  "besoin", ("linux",)),
    "kube-bench": ("ne sert que pour Kubernetes (rare chez une TPE) : à poser à la main si "
                   "besoin", ("linux",)),
    "owasp dependency-check": ("programme Java à télécharger (zip) sur sa page officielle",
                               ("linux",)),
}


def manuel(nom, systeme=None):
    """La raison pour laquelle cet outil se pose à la main sur ce système, sinon None."""
    fiche = MANUELS.get((nom or "").strip().lower())
    if not fiche:
        return None
    raison, systemes = fiche
    systeme = systeme or ("darwin" if sys.platform == "darwin" else
                          "linux" if sys.platform.startswith("linux") else sys.platform)
    return raison if systeme in systemes else None


def pour(nom, systeme=None):
    """(libellé, recette) prévue pour cet outil sur ce système, sinon None."""
    fiche = RECETTES.get((nom or "").strip().lower())
    if not fiche:
        return None
    libelle, recette, systemes = fiche
    systeme = systeme or ("darwin" if sys.platform == "darwin" else
                          "linux" if sys.platform.startswith("linux") else sys.platform)
    return (libelle, recette) if systeme in systemes else None


def a_reparer():
    """Les outils déjà « prêts » d'après le bilan, mais installés de travers. Une reprise
    de l'installeur les refait (aujourd'hui : dnstwist sans son module DNS)."""
    reparer = []
    if shutil.which("pipx") and module_manquant("dnstwist", "dnspython"):
        reparer.append("dnstwist")
    return reparer
