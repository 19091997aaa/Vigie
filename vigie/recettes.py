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
import contextlib
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
import time
import urllib.request

# Les outils libres que le catalogue range à tort parmi les « payants » (clé API).
GRATUITS_MALGRE_CLE = {"uncover"}


def dossiers():
    """(dossier où Vigie range les outils à part, dossier des commandes)."""
    racine = os.environ.get("VIGIE_OUTILS_RACINE") or os.path.expanduser(
        "~/.local/share/vigie-outils")
    commandes = os.environ.get("PIPX_BIN_DIR") or os.path.expanduser("~/.local/bin")
    return racine, commandes


# ---------------------------------------------------------------------------
# Mémoire. Le 26/11/2026, sur la VM Ubuntu, le système a TUÉ l'installeur (signal 9,
# « mémoire presque pleine ») vers l'outil 108 : six installations de front, dont
# plusieurs compilations Python et Go, chacune pouvant prendre 1 Go ou plus.
# Désormais : les compilations (pip, pipx, go) passent une par une, attendent qu'il y
# ait assez de mémoire libre, et le nombre d'installations de front suit la mémoire.

MEMOIRE_MINI_MO = 1000      # mémoire libre voulue avant de lancer une compilation
MO_PAR_INSTALLATION = 1500  # ce qu'on compte pour une installation menée de front
PARALLELE_MAX = 4

_LOURDS = threading.BoundedSemaphore(1)
_COMPILEURS = {"go", "pipx", "pip", "pip3"}


def memoire_libre_mo():
    """La mémoire encore disponible, en Mo (None si on ne sait pas la lire)."""
    try:
        with open("/proc/meminfo", encoding="utf-8") as lu:
            for ligne in lu:
                if ligne.startswith("MemAvailable:"):
                    return int(ligne.split()[1]) // 1024
    except (OSError, ValueError, IndexError):
        pass
    if sys.platform == "darwin":  # Mac : la mémoire totale, dont on compte la moitié
        try:
            total = subprocess.run(["sysctl", "-n", "hw.memsize"], capture_output=True,
                                   text=True, timeout=10).stdout
            return int(total.strip()) // (2 * 1024 * 1024)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            pass
    return None


def parallele_auto(memoire_mo=None):
    """Combien d'installations mener de front, d'après la mémoire libre.
    2,5 Go libres -> 1 ; 4 Go -> 2 ; 6 Go et plus -> 4 (jamais plus)."""
    memoire_mo = memoire_libre_mo() if memoire_mo is None else memoire_mo
    if memoire_mo is None:
        return 2
    return max(1, min(PARALLELE_MAX, memoire_mo // MO_PAR_INSTALLATION))


def regler_compilations(nombre=0):
    """Combien de compilations (pip, pipx, go) peuvent tourner en même temps.
    0 = auto : 1 seule sous 8 Go de mémoire libre, 2 au-delà."""
    global _LOURDS
    nombre = int(nombre or 0)
    if nombre <= 0:
        libre = memoire_libre_mo()
        nombre = 2 if libre is not None and libre >= 8000 else 1
    _LOURDS = threading.BoundedSemaphore(nombre)
    return nombre


def limiter_compilations():
    """Chaque compilation reste sobre : Go et make sur 2 cœurs au plus, au lieu de
    tous (chaque cœur occupé = un compilateur de plus en mémoire). Ne remplace pas un
    réglage déjà fait par la personne."""
    os.environ.setdefault("GOFLAGS", "-p=2")
    os.environ.setdefault("MAKEFLAGS", "-j2")
    os.environ.setdefault("CMAKE_BUILD_PARALLEL_LEVEL", "2")
    os.environ.setdefault("MAX_JOBS", "2")


def est_compilation(commande):
    """pip, pipx et go compilent souvent (surtout avec un Python très récent) :
    ce sont eux qui remplissent la mémoire. apt, npm et les téléchargements, non."""
    return bool(commande) and os.path.basename(commande[0]) in _COMPILEURS


def attendre_memoire(minimum_mo=MEMOIRE_MINI_MO, attente_max=300, pause=5):
    """Attend (5 min au plus) qu'il y ait assez de mémoire libre. Renvoie le temps attendu."""
    attendu = 0
    while attendu < attente_max:
        libre = memoire_libre_mo()
        if libre is None or libre >= minimum_mo:
            break
        time.sleep(pause)
        attendu += pause
    return attendu


# ---------------------------------------------------------------------------
# Place disque. Le 26/11/2026, Stratus Red Team a raté sur « no space left on device »
# dans /opt/vigie-outils/tmp : les restes de compilation (go-build…, pip-…) d'une
# installation coupée, le cache de Go et celui de pip remplissaient le disque des
# outils (garak et Nebula pèsent ~6 Go chacun, à cause de la bibliothèque d'IA torch).

PLACE_MINI_MO = 6000   # en dessous, on fait le ménage avant de compiler
# Les dossiers provisoires des compilateurs (go, pip) : jamais ceux d'un autre programme.
_RESTES = re.compile(r"^(?:go-build|go-link|pip-)", re.I)
_ACTIFS = 0                       # compilations en cours
_VERROU_PLACE = threading.Lock()  # personne ne démarre pendant le ménage


def place_libre_mo(chemin=None):
    """La place libre (Mo) sur le disque des outils (ou de chemin)."""
    chemin = chemin or os.environ.get("TMPDIR") or dossiers()[0]
    while chemin and not os.path.exists(chemin):
        chemin = os.path.dirname(chemin)
    try:
        return shutil.disk_usage(chemin or "/").free // (1024 * 1024)
    except OSError:
        return None


def _vider(dossier, garder=None):
    """Supprime le contenu d'un dossier (pas le dossier lui-même). garder(nom) dit quoi
    supprimer ; sans garder, tout part. Renvoie les Mo libérés."""
    if not dossier or not os.path.isdir(dossier):
        return 0
    avant = place_libre_mo(dossier) or 0
    for nom in os.listdir(dossier):
        if garder and not garder(nom):
            continue
        chemin = os.path.join(dossier, nom)
        if os.path.isdir(chemin) and not os.path.islink(chemin):
            shutil.rmtree(chemin, ignore_errors=True)
        else:
            try:
                os.remove(chemin)
            except OSError:
                pass
    return max(0, (place_libre_mo(dossier) or 0) - avant)


def _a_vigie(variable):
    """Le dossier de la variable (TMPDIR, GOCACHE…) seulement s'il est DANS le dossier
    des outils de Vigie (/opt/vigie-outils) : jamais le /tmp ou un cache du système."""
    dossier = os.environ.get(variable, "")
    racine = os.environ.get("VIGIE_OUTILS_RACINE", "")
    if racine and dossier and os.path.realpath(dossier).startswith(
            os.path.realpath(racine) + os.sep):
        return dossier
    return ""


def nettoyer_restes():
    """Au DÉBUT d'une installation (rien ne tourne encore) : les restes d'une installation
    coupée (mémoire pleine, coupure) dans le dossier temporaire de Vigie. Renvoie les Mo
    libérés."""
    return _vider(_a_vigie("TMPDIR"))


def faire_de_la_place():
    """Libère de la place SANS toucher aux outils installés : restes de compilation,
    caches de Go, de pip et de uv. Seulement quand aucune compilation ne tourne (voir
    chantier). Renvoie les Mo libérés."""
    libere = _vider(_a_vigie("TMPDIR"), garder=lambda nom: bool(_RESTES.match(nom)))
    for variable in ("GOCACHE", "PIP_CACHE_DIR", "UV_CACHE_DIR"):
        libere += _vider(_a_vigie(variable))
    return libere


def apres_go():
    """Après une compilation Go : ses dossiers provisoires et son cache de compilation
    (des centaines de Mo par outil, inutiles une fois le programme posé)."""
    libere = _vider(_a_vigie("TMPDIR"), garder=lambda nom: nom.startswith(("go-build",
                                                                           "go-link")))
    return libere + _vider(_a_vigie("GOCACHE"))


@contextlib.contextmanager
def chantier(commande):
    """Une compilation à la fois (ou le nombre réglé), seulement avec assez de mémoire
    libre et assez de place disque. Les autres commandes passent sans attendre.

    Le ménage (caches, restes) ne se fait que quand AUCUNE autre compilation ne tourne :
    vider le cache de Go sous les pieds d'une compilation la ferait rater."""
    global _ACTIFS
    if not est_compilation(commande):
        yield
        return
    with _LOURDS:
        attendre_memoire()
        with _VERROU_PLACE:
            if _ACTIFS == 0:
                libre = place_libre_mo()
                if libre is not None and libre < PLACE_MINI_MO:
                    faire_de_la_place()
            _ACTIFS += 1
        try:
            yield
        finally:
            with _VERROU_PLACE:
                _ACTIFS -= 1
                if _ACTIFS == 0 and os.path.basename(commande[0]) == "go":
                    apres_go()


def _lancer(commande, delai=900, env=None, dossier=None):
    """(réussi, dernière ligne d'erreur, sortie complète)."""
    programme = shutil.which(commande[0], path=(env or os.environ).get("PATH"))
    if not programme:
        return False, f"{commande[0]} absent", ""
    try:
        with chantier(commande):
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


def _extraire_tout(archive, destination, retirer_tete=True):
    """Déballe une archive dans destination en retirant son dossier de tête
    (retirer_tete=False : archive sans dossier de tête, comme celle de PowerShell)."""
    os.makedirs(destination, exist_ok=True)
    racine = os.path.realpath(destination)
    with tarfile.open(archive) as tar:
        for membre in tar.getmembers():
            nom = membre.name[2:] if membre.name.startswith("./") else membre.name
            morceaux = nom.split("/", 1) if retirer_tete else ["", nom]
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


def depot_python(depot, requirements, script, commande, nom, nettoyer_pipx=None,
                 python=None):
    """Copie du dépôt GitHub exact + environnement Python à part + lanceur.

    Pour les outils qui sont un simple script Python (XSStrike, SSRFmap, jwt_tool…) :
    pipx les refuse (« Check package spec for errors ») car ce ne sont pas des paquets.
    requirements : le fichier de dépendances, ou None pour installer le dossier
    lui-même s'il a un pyproject.toml / setup.py (sinon, aucune dépendance).
    nettoyer_pipx : un ancien paquet pipx posé de travers à retirer d'abord (DPAT).
    python : une version (« 3.12 ») quand les dépendances ne s'installent pas sur le
    Python de la machine : Vigie pose alors ce Python à part (python_a_part).
    """
    def recette():
        racine, commandes = dossiers()
        if nettoyer_pipx:
            _lancer(["pipx", "uninstall", nettoyer_pipx], delai=120)
        interprete = sys.executable
        if python:
            interprete, erreur = python_a_part(python)
            if not interprete:
                return False, erreur, []
        dossier = os.path.join(racine, nom)
        if os.path.isdir(os.path.join(dossier, ".git")):
            reussi, message, _ = _lancer(["git", "-C", dossier, "pull", "--ff-only"])
        else:
            os.makedirs(racine, exist_ok=True)
            reussi, message, _ = _lancer(["git", "clone", "--depth", "1", depot, dossier])
        if not reussi:
            return False, "git : " + message, []
        venv = os.path.join(dossier, "vigie-venv")
        reussi, message, _ = _lancer([interprete, "-m", "venv", venv])
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


# Python « à part » pour les outils dont les dépendances ne s'installent pas encore sur
# le Python très récent de la VM (3.14) : SpiderFoot exige lxml < 5, sans version pour
# 3.14 (26/11/2026). Source officielle : python-build-standalone (le même projet que
# pipx --fetch-missing-python), empreinte vérifiée avec son fichier SHA256SUMS.
PBS = "https://raw.githubusercontent.com/astral-sh/python-build-standalone/latest-release/" \
      "latest-release.json"
VERROU_PYTHON = threading.Lock()


def _triplet():
    machine = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64",
               "arm64": "aarch64"}.get(platform.machine().lower())
    systeme = {"linux": "unknown-linux-gnu", "darwin": "apple-darwin"}.get(sys.platform)
    return f"{machine}-{systeme}" if machine and systeme else None


def python_a_part(version="3.12"):
    """Pose un Python officiel (python-build-standalone) dans le dossier de Vigie.
    Renvoie (chemin du programme python3, message d'erreur)."""
    with VERROU_PYTHON:
        return _python_a_part(version)


def _python_a_part(version):
    racine, _ = dossiers()
    dossier = os.path.join(racine, f"python{version}")
    python = os.path.join(dossier, "bin", "python3")
    if os.access(python, os.X_OK):
        return python, ""
    triplet = _triplet()
    if not triplet:
        return None, f"système non prévu ({sys.platform} {platform.machine()})"
    import json
    with tempfile.TemporaryDirectory() as travail:
        try:
            _telecharger(PBS, os.path.join(travail, "derniere.json"), delai=60)
            with open(os.path.join(travail, "derniere.json"), encoding="utf-8") as lu:
                infos = json.load(lu)
            prefixe, etiquette = infos["asset_url_prefix"], infos["tag"]
            _telecharger(prefixe + "/SHA256SUMS", os.path.join(travail, "sommes.txt"))
            with open(os.path.join(travail, "sommes.txt"), encoding="utf-8") as lu:
                sommes = lire_sommes(lu.read())
            motif = (rf"cpython-{re.escape(version)}\.\d+\+{re.escape(etiquette)}-"
                     rf"{re.escape(triplet)}-install_only\.tar\.gz")
            nom = next((n for n in sorted(sommes) if re.fullmatch(motif, n)), None)
            if not nom:
                return None, f"Python {version} introuvable dans la publication officielle"
            chemin = os.path.join(travail, nom)
            _telecharger(prefixe + "/" + nom, chemin)
        except (OSError, ValueError, KeyError) as erreur:
            return None, f"téléchargement de Python {version} impossible : {erreur}"
        if _empreinte(chemin) != sommes[nom]:
            return None, f"empreinte de Python {version} incorrecte : installation refusée"
        if os.path.isdir(dossier):
            shutil.rmtree(dossier)
        _extraire_tout(chemin, dossier)
    if not os.access(python, os.X_OK):
        return None, f"Python {version} déballé mais introuvable ({python})"
    return python, ""


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
    commande = [npm, "install", "-g", "--prefix", prefixe, paquet]
    reussi, message, sortie = _lancer(commande, env=env)
    if not reussi and re.search(r"\bENOTEMPTY\b|\bEEXIST\b", sortie or ""):
        # Le reste d'une installation coupée (promptfoo, 26/11/2026) bloque npm : on
        # retire ce paquet-là seulement (et ses dossiers provisoires), puis on réessaie.
        modules = os.path.join(prefixe, "lib", "node_modules")
        cible = os.path.join(modules, *re.sub(r"(?<=.)@[^/]*$", "", paquet).split("/"))
        provisoires = os.path.dirname(cible)
        if os.path.isdir(provisoires):
            for nom in os.listdir(provisoires):
                if nom.startswith("." + os.path.basename(cible) + "-"):
                    shutil.rmtree(os.path.join(provisoires, nom), ignore_errors=True)
        shutil.rmtree(cible, ignore_errors=True)
        reussi, message, sortie = _lancer(commande, env=env)
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


# ---------------------------------------------------------------------------
# Ajouts du 26/11/2026 (tri des 84 outils « à poser à la main ») : trois outils utiles
# à Vigie avaient en fait une source officielle vérifiable.

def lire_texte(chemin):
    """Lit un petit fichier texte, qu'il soit en UTF-8 ou en UTF-16 (le fichier
    d'empreintes de PowerShell est en UTF-16 : lu en UTF-8, il paraissait vide)."""
    with open(chemin, "rb") as lu:
        brut = lu.read()
    if brut.startswith((b"\xff\xfe", b"\xfe\xff")):
        return brut.decode("utf-16", errors="replace")
    return brut.decode("utf-8-sig", errors="replace")


def nuclei_modeles():
    """Nuclei Templates : les « modèles » de tests de Nuclei (des données, pas un
    programme). Méthode documentée : « nuclei -update-templates » ; si Nuclei n'est pas
    (encore) là, copie du dépôt exact. Rien à « démarrer »."""
    def recette():
        from . import outils
        env = dict(os.environ, PATH=outils.chemin_recherche())
        if shutil.which("nuclei", path=env["PATH"]):
            reussi, message, _ = _lancer(["nuclei", "-update-templates"], delai=1800, env=env)
            if reussi:
                return True, "", None
        return depot_donnees("https://github.com/projectdiscovery/nuclei-templates",
                             "nuclei-templates")()
    return recette


VERROU_PWSH = threading.Lock()
DEPOT_PWSH = "PowerShell/PowerShell"


def powershell_a_part():
    """PowerShell 7 posé dans le dossier de Vigie : programme officiel publié par
    Microsoft sur GitHub, empreinte vérifiée avec son fichier hashes.sha256.
    Rien n'est touché dans le système (pas de dépôt apt ajouté).
    Renvoie (chemin de pwsh, message d'erreur)."""
    with VERROU_PWSH:
        return _powershell_a_part()


def _powershell_a_part():
    from . import outils
    deja = shutil.which("pwsh", path=outils.chemin_recherche())
    if deja:
        return deja, ""
    racine, commandes = dossiers()
    dossier = os.path.join(racine, "powershell")
    pwsh = os.path.join(dossier, "pwsh")
    if os.path.exists(pwsh):
        return pwsh, ""
    arch = _architecture()
    systeme = {"linux": "linux", "darwin": "osx"}.get(
        "darwin" if sys.platform == "darwin" else
        "linux" if sys.platform.startswith("linux") else "")
    if not arch or not systeme:
        return None, f"système non prévu ({sys.platform} {platform.machine()})"
    base = f"https://github.com/{DEPOT_PWSH}/releases/latest/download/"
    with tempfile.TemporaryDirectory() as travail:
        try:
            _telecharger(base + "hashes.sha256", os.path.join(travail, "sommes.txt"))
            sommes = lire_sommes(lire_texte(os.path.join(travail, "sommes.txt")).lower())
            nom = next((n for n in sorted(sommes) if re.fullmatch(
                rf"powershell-[\d.]+-{systeme}-{arch}\.tar\.gz", n)), None)
            if not nom:
                return None, "archive de PowerShell introuvable sur sa page officielle"
            chemin = os.path.join(travail, nom)
            _telecharger(base + nom, chemin)
        except OSError as erreur:
            return None, f"téléchargement de PowerShell impossible : {erreur}"
        if _empreinte(chemin) != sommes[nom]:
            return None, "empreinte de PowerShell incorrecte : installation refusée"
        if os.path.isdir(dossier):
            shutil.rmtree(dossier)
        _extraire_tout(chemin, dossier, retirer_tete=False)
    if not os.path.exists(pwsh):
        return None, "pwsh absent de l'archive de PowerShell"
    os.chmod(pwsh, os.stat(pwsh).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    ecrire_lanceur(os.path.join(commandes, "pwsh"), [f'exec "{pwsh}" "$@"'])
    return pwsh, ""


def module_powershell(module, commande_ps, commande):
    """Un module PowerShell (Maester, Monkey365) : PowerShell 7 à part, puis la ligne de
    la documentation de l'outil, « Install-Module -Name <module> -Scope CurrentUser »,
    depuis la PowerShell Gallery (le magasin officiel de Microsoft). Aucun droit
    administrateur. Un lanceur au nom de l'outil charge le module ; sans argument, il
    affiche l'aide (c'est ce que l'installeur vérifie)."""
    def recette():
        pwsh, message = powershell_a_part()
        if not pwsh:
            return False, message, []
        reussi, message, _ = _lancer([pwsh, "-NoLogo", "-NoProfile", "-NonInteractive",
                                      "-Command",
                                      f"Install-Module -Name {module} -Repository PSGallery "
                                      "-Scope CurrentUser -Force -AllowClobber "
                                      "-ErrorAction Stop"], delai=1800)
        if not reussi:
            return False, "PowerShell Gallery : " + message, []
        _, commandes = dossiers()
        charger = f"Import-Module {module} -ErrorAction Stop"
        ecrire_lanceur(os.path.join(commandes, commande), [
            'case "$1" in ""|-h|--help)',
            f'  exec "{pwsh}" -NoLogo -NoProfile -Command "{charger}; Get-Help {commande_ps}" ;;',
            "esac",
            f'exec "{pwsh}" -NoLogo -NoProfile -Command "{charger}; {commande_ps} $*"'])
        return True, "", [commande]
    return recette


ZAP_VERSIONS = "https://raw.githubusercontent.com/zaproxy/zap-admin/master/ZapVersions.xml"
ZAP_SOURCE = "https://github.com/zaproxy/zaproxy/releases/download/"


def version_java():
    """Le numéro principal de Java (17, 21…), ou 0 s'il est absent."""
    programme = shutil.which("java")
    if not programme:
        return 0
    try:
        fini = subprocess.run([programme, "-version"], capture_output=True, text=True,
                              timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return 0
    trouve = re.search(r'version "(\d+)', (fini.stderr or "") + (fini.stdout or ""))
    return int(trouve.group(1)) if trouve else 0


def lire_zap_versions(texte):
    """(adresse, empreinte) de l'archive Linux de ZAP, lues dans ZapVersions.xml : le
    fichier que ZAP lui-même lit pour se mettre à jour. L'adresse doit pointer vers la
    page « Releases » du dépôt exact de ZAP, sinon on refuse."""
    import xml.etree.ElementTree as ET
    try:
        linux = ET.fromstring(texte).find("core/linux")
    except ET.ParseError:
        return None, None
    if linux is None:
        return None, None
    adresse = (linux.findtext("url") or "").strip()
    empreinte = (linux.findtext("hash") or "").strip().lower()
    if empreinte.startswith("sha-256:"):
        empreinte = empreinte[len("sha-256:"):]
    if not adresse.startswith(ZAP_SOURCE) or not re.fullmatch(r"[0-9a-f]{64}", empreinte):
        return None, None
    return adresse, empreinte


def zap_officiel():
    """OWASP ZAP sous Linux : l'archive officielle (GitHub du projet), empreinte vérifiée
    avec le fichier de versions de ZAP. Il lui faut Java 17 ou plus : s'il manque, on pose
    celui d'Ubuntu (apt, « default-jre-headless »)."""
    def recette():
        if version_java() < 17:
            from . import installeur
            apt = next(c for l, _, c in installeur.DOCUMENTEES if l.startswith("apt"))
            reussi, message, _ = installeur._lancer(apt + ["default-jre-headless"])
            if not reussi or version_java() < 17:
                return False, "Java 17 ou plus manquant : " + (message or "apt a échoué"), []
        racine, commandes = dossiers()
        dossier = os.path.join(racine, "ZAP")
        with tempfile.TemporaryDirectory() as travail:
            try:
                _telecharger(ZAP_VERSIONS, os.path.join(travail, "versions.xml"))
                adresse, attendue = lire_zap_versions(
                    lire_texte(os.path.join(travail, "versions.xml")))
                if not adresse:
                    return False, "fichier de versions de ZAP illisible", []
                chemin = os.path.join(travail, "zap.tar.gz")
                _telecharger(adresse, chemin, delai=1800)
            except OSError as erreur:
                return False, f"téléchargement impossible : {erreur}", []
            if _empreinte(chemin) != attendue:
                return False, "empreinte du fichier téléchargé incorrecte : installation refusée", []
            if os.path.isdir(dossier):
                shutil.rmtree(dossier)
            _extraire_tout(chemin, dossier)
        if not os.path.exists(os.path.join(dossier, "zap.sh")):
            return False, "zap.sh absent de l'archive", []
        ecrire_lanceur(os.path.join(commandes, "zaproxy"),
                       [f'exec "{os.path.join(dossier, "zap.sh")}" "$@"'])
        return True, "", ["zaproxy"]
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
    # SpiderFoot (26/11/2026) : la doc proposait « pipx install spiderfoot-ng », un fork
    # tiers (9 versions publiées en un jour, autre dépôt) -> retiré. Le dépôt officiel n'est
    # pas un paquet, et ses dépendances (lxml < 5) ne s'installent pas sur Python 3.14 :
    # dépôt officiel + Python 3.12 à part. Lanceur « spiderfoot » = python sf.py.
    "spiderfoot": ("dépôt officiel + Python 3.12 à part (recette Vigie)",
                   depot_python("https://github.com/smicallef/spiderfoot", "requirements.txt",
                                "sf.py", "spiderfoot", "SpiderFoot",
                                nettoyer_pipx="spiderfoot-ng", python="3.12"), TOUS),
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
    # --- Ajoutés le 26/11/2026 (tri des outils « à poser à la main »). ---
    # Les modèles de tests de Nuclei : sans eux, Nuclei (audit sur autorisation) ne teste rien.
    "nuclei templates": ("modèles Nuclei (documenté, recette Vigie)", nuclei_modeles(), TOUS),
    # Audit Microsoft 365 du client (avec son accord et SON compte) : la plupart des TPE,
    # dont les cabinets comptables, sont sur Microsoft 365. Marchent sous Linux avec
    # PowerShell 7.
    "maester": ("PowerShell 7 officiel + PowerShell Gallery (recette Vigie)",
                module_powershell("Maester", "Invoke-Maester", "maester"), TOUS),
    "monkey365": ("PowerShell 7 officiel + PowerShell Gallery (recette Vigie)",
                  module_powershell("monkey365", "Invoke-Monkey365", "monkey365"), TOUS),
    # Test des sites web pendant un audit signé. Le paquet « zaproxy » n'existe que sur Kali.
    "owasp zap": ("programme officiel ZAP, empreinte vérifiée (recette Vigie)",
                  zap_officiel(), ("linux",)),
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

# --- Tri du 26/11/2026 : les 84 outils « à poser à la main » de la 1re installation
# complète sur la VM Ubuntu (8 Go). Avant, la plupart disaient seulement « pas de
# méthode automatique sûre ». Chacun a maintenant sa vraie raison, et ceux qui n'ont
# rien à faire sur la machine de Vigie sont comptés à part (PAS_ICI) : ce n'est ni une
# panne ni un travail à faire.
CHEZ_CLIENT = ("protection à installer chez le client pendant la sécurisation, pas sur la "
               "machine de Vigie")
SUR_WINDOWS = "outil PowerShell pour Windows : il se lance sur un PC Windows, pas ici"
INUTILE = "pas utile pour Vigie pour l'instant"
OFFENSIF = "outil d'attaque (famille GATE) : pas dans Vigie tant que le labo n'existe pas"
GROS_SERVEUR = ("gros serveur (plusieurs Go de mémoire) : trop lourd pour la VM, à poser "
                "plus tard sur un serveur loué")

# Utiles, mais à poser à la main (ils restent comptés « à poser à la main »).
MANUELS.update({
    "openvas (greenbone community)": (
        GROS_SERVEUR + " ; utile pour l'audit sur autorisation (conteneurs Greenbone "
        "Community)", TOUS),
    "wazuh": (GROS_SERVEUR + " ; utile pour une offre de surveillance des postes", TOUS),
    "burp suite community": ("application à télécharger sur portswigger.net, puis à "
                             "brancher dans « Je l'ai installé à la main »", TOUS),
    "scubagear": (SUR_WINDOWS + " ; utile pour l'audit Microsoft 365 (Maester et "
                  "Monkey365 font le même travail ici)", TOUS),
    "hardeningkitty": (SUR_WINDOWS + " ; utile pendant la sécurisation des postes du "
                       "client", TOUS),
    "bloodhound": ("serveur avec Docker ; seulement pour un client qui a un Active "
                   "Directory (rare chez une TPE)", TOUS),
})

_PAS_ICI = {
    # Diag gratuit : des applis, extensions ou plateformes ; Vigie fait déjà le travail.
    "datashare": "appli de recherche dans des documents : " + INUTILE,
    "invid-weverify": "extension de navigateur (vérification d'images) : " + INUTILE,
    "web-check": "site à héberger qui refait les contrôles que Vigie fait déjà",
    "flowsint": "appli d'enquête à la main avec ses propres serveurs : " + INUTILE,
    "reconftw": "gros script qui réinstalle des dizaines d'outils que Vigie a déjà posés",
    "zmap": "scan d'internet entier : " + INUTILE,
    "angry ip scanner": "application graphique ; Nmap (installé) fait le même travail",
    # Audit interne : des scripts à déposer sur la machine auditée.
    "privesccheck": "script à déposer sur le poste Windows audité, rien à installer ici",
    "linux-smart-enumeration": "script à déposer sur le serveur Linux audité, rien à "
                               "installer ici",
    "complianceascode": "durcissement de serveurs Linux (rare chez une TPE) : " + INUTILE,
    # Cloud Azure et Windows : rare chez une TPE, ou offensif.
    "microburst": "audit Azure (rare chez une TPE) : " + INUTILE,
    "microsoft365dsc": "gestion de configuration Microsoft 365 pour grandes entreprises : "
                       + INUTILE,
    "aadinternals": OFFENSIF,
    "azurehound": "audit Azure (rare chez une TPE) : " + INUTILE,
    "psrule for azure": "audit Azure (rare chez une TPE) : " + INUTILE,
    "locksmith": "Active Directory (rare chez une TPE) : " + INUTILE,
    "group3r": "Active Directory (rare chez une TPE) : " + INUTILE,
    "exploit-db (searchsploit)": OFFENSIF,
    # Wi-Fi : carte spéciale, outils d'attaque.
    "hcxtools": OFFENSIF + " (Wi-Fi, carte spéciale)",
    "hcxdumptool": OFFENSIF + " (Wi-Fi, carte spéciale)",
    # Analyse poussée (rétro-ingénierie, enquête après incident).
    "ghidra": "rétro-ingénierie de programmes : " + INUTILE,
    "cyberchef": "s'utilise en ligne (gchq.github.io/CyberChef), rien à installer",
    "autopsy": "enquête sur un disque après incident : " + INUTILE,
    "outils zimmerman": "enquête Windows après incident : " + INUTILE,
    "chainsaw": "lecture des journaux Windows après incident : " + INUTILE,
    "hayabusa": "lecture des journaux Windows après incident : " + INUTILE,
    # Surveillance et protections : se posent chez le client.
    "ntopng (community)": CHEZ_CLIENT,
    "zeek": CHEZ_CLIENT,
    "arkime": CHEZ_CLIENT,
    "uptime kuma": CHEZ_CLIENT,
    "vaultwarden": CHEZ_CLIENT,
    "pi-hole": CHEZ_CLIENT,
    "osquery": CHEZ_CLIENT,
    "falco": CHEZ_CLIENT,
    "pfsense ce": CHEZ_CLIENT + " (c'est un pare-feu complet)",
    "opnsense": CHEZ_CLIENT + " (c'est un pare-feu complet)",
    "devsec hardening": CHEZ_CLIENT,
    "harden-windows-security": CHEZ_CLIENT + " (Windows)",
    "snort 3": CHEZ_CLIENT,
    "owasp crs": CHEZ_CLIENT + " (règles pour le serveur web)",
    "caddy waf": CHEZ_CLIENT + " (pare-feu du serveur web)",
    "sysmon-modular": CHEZ_CLIENT + " (Windows)",
    "misp": "plateforme de partage de menaces pour grandes équipes : " + INUTILE,
    # Simulation d'attaque et IA offensive.
    "atomic red team": OFFENSIF,
    "infection monkey": OFFENSIF,
    "shannon": OFFENSIF,
    "deepaudit": OFFENSIF,
    "decepticon": OFFENSIF,
    "redamon": OFFENSIF,
    "open-kritt": OFFENSIF,
    "burp ai agent": OFFENSIF,
}
MANUELS.update({nom: (raison, TOUS) for nom, raison in _PAS_ICI.items()})

# Déjà dans MANUELS plus haut, mais rien à faire sur la machine de Vigie non plus.
PAS_ICI = set(_PAS_ICI) | {
    "geo-sleuth", "xingrin", "arl-next", "mitre caldera", "grr rapid response",
    "velociraptor", "crowdsec", "coraza waf", "hardentools", "artex", "xalgorix",
    "adalanche", "dorkagent", "sparrow-wifi", "peass-ng (winpeas/linpeas)",
    "metasploit framework", "airgeddon", "kismet", "veracrypt", "rustscan", "feroxbuster",
    "kubescape", "kube-bench", "owasp dependency-check"}


def pas_ici(nom):
    """Vrai pour un outil qu'il n'y a pas lieu d'installer sur la machine de Vigie
    (chez le client, Windows, offensif, doublon ou inutile pour une TPE)."""
    return (nom or "").strip().lower() in PAS_ICI


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
