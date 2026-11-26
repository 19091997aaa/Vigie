"""Installation en masse des outils du catalogue, par catégorie.

Pour chaque outil, on essaie d'abord les commandes écrites dans sa propre
documentation (docs_outils.json), puis son dépôt GitHub exact, et on note celle
qui marche. On ne devine JAMAIS un paquet à partir de son nom (voir methodes()).

    python3 -m vigie installer --categorie "OSINT : pseudos, e-mails, images, métadonnées"
    python3 -m vigie installer --tous --a-blanc

Rien n'est installé en dehors des gestionnaires standards (Homebrew, pipx, go,
npm). Aucun script distant n'est exécuté.
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading

CATALOGUE = os.path.join(os.path.dirname(__file__), "catalogue_outils.json")
DEPOT = re.compile(r"github\.com/([^/]+)/([^/#?]+)")


def charger(chemin=CATALOGUE):
    with open(chemin, encoding="utf-8") as fichier:
        return json.load(fichier)


def preparer_dest(dossier):
    """Pose pipx/go/npm sur un dossier précis (ex. /opt/vigie-outils) sans que la
    personne touche aux variables d'environnement.

    Renvoie le dossier des exécutables (pour l'afficher). Les sous-processus
    d'installation lisent os.environ, donc on règle tout ici une fois pour toutes.
    """
    dossier = os.path.abspath(os.path.expanduser(dossier))
    bin_dir = os.path.join(dossier, "bin")
    go_dir = os.path.join(dossier, "go")
    cache = os.path.join(dossier, "cache")
    tmp = os.path.join(dossier, "tmp")
    for d in (bin_dir, go_dir, cache, tmp, os.path.join(dossier, "pipx")):
        os.makedirs(d, exist_ok=True)
    os.environ["PIPX_HOME"] = os.path.join(dossier, "pipx")
    os.environ["PIPX_BIN_DIR"] = bin_dir
    os.environ["GOPATH"] = go_dir
    os.environ["GOBIN"] = bin_dir
    # Les CACHES vont aussi sur le disque, sinon ils remplissent / (le cache de
    # compilation Go peut peser plusieurs Go) : c'est ce qui a saturé le système.
    os.environ["GOMODCACHE"] = os.path.join(go_dir, "pkg", "mod")
    os.environ["GOCACHE"] = os.path.join(cache, "go-build")
    os.environ["PIP_CACHE_DIR"] = os.path.join(cache, "pip")
    os.environ["UV_CACHE_DIR"] = os.path.join(cache, "uv")  # si pipx passe par uv
    os.environ["TMPDIR"] = tmp
    os.environ["PATH"] = bin_dir + os.pathsep + os.environ.get("PATH", "")
    # Les outils installés « à part » (vigie/recettes.py : EyeWitness, Node 22…) aussi.
    os.environ["VIGIE_OUTILS_RACINE"] = dossier
    return bin_dir


def categories(outils):
    """Les catégories et le nombre d'outils dans chacune."""
    compte = {}
    for outil in outils:
        compte[outil["categorie"]] = compte.get(outil["categorie"], 0) + 1
    return compte


def depot(lien):
    """https://github.com/owner/repo -> ('owner', 'repo'), sinon None."""
    trouve = DEPOT.search(lien or "")
    return (trouve.group(1), trouve.group(2).removesuffix(".git")) if trouve else None


# apt ne sait faire qu'une installation à la fois (verrou de dpkg). Le 25/11/2026, six
# installations lancées de front sur la VM Ubuntu se sont bloquées entre elles : CeWL,
# Wireshark, tcpdump, The Sleuth Kit, YARA, Patator et Sparrow-WiFi ont échoué sur
# « Impossible d'obtenir le verrou de dpkg ». Les autres méthodes (pipx, go, npm)
# continuent en parallèle ; apt, lui, passe UN PAR UN.
VERROU_APT = threading.Lock()

# Les lignes qui disent vraiment ce qui ne va pas (la dernière ligne est souvent
# « voir le journal complet », ce qui n'aide personne).
LIGNE_UTILE = re.compile(
    r"^(?:E:|error:|ERROR:|npm (?:ERR!|error) code|fatal:|go: |Cannot determine|"
    r"No apps associated|Unable to|Impossible)|is not|not found|requires|No matching", re.I)


def ligne_utile(texte):
    """La ligne d'erreur la plus parlante d'une sortie, sinon la dernière."""
    lignes = [l.strip() for l in (texte or "").strip().splitlines() if l.strip()]
    for ligne in lignes:
        if LIGNE_UTILE.search(ligne) and "debug-0.log" not in ligne:
            return ligne[:160]
    return lignes[-1][:160] if lignes else ""


def _lancer(commande, delai=600):
    """Lance une commande d'installation. Renvoie (réussi, message court, sortie).

    Aucune question ne peut bloquer l'installation : l'entrée est fermée (stdin) et apt
    tourne en mode « sans question » (Wireshark demandait qui a le droit de capturer,
    et attendait une réponse que personne ne voyait)."""
    programme = shutil.which(commande[0])
    if not programme:
        return False, f"{commande[0]} absent", ""
    from . import recettes
    # apt : un à la fois. pip/pipx/go : une compilation à la fois, avec assez de mémoire.
    verrou = VERROU_APT if "apt-get" in commande else recettes.chantier(commande)
    try:
        with verrou:
            fini = subprocess.run([programme] + commande[1:], capture_output=True,
                                  text=True, timeout=delai, errors="replace",
                                  stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return False, f"dépassement de {delai} s", ""
    sortie = (fini.stdout or "") + "\n" + (fini.stderr or "")
    if fini.returncode == 0:
        return True, "", sortie
    message = ligne_utile(fini.stderr) or ligne_utile(fini.stdout)
    return False, (message or f"code {fini.returncode}"), sortie


# pipx annonce les binaires posés sous « These apps are now globally available ».
APPS_PIPX = re.compile(r"^\s*-\s+(\S+)\s*$", re.M)


def binaires_poses(libelle, sortie, proprietaire, nom, commande=None):
    """Quels exécutables l'installation a réellement posés. L'outil le dit lui-même."""
    if libelle.startswith("pipx"):
        apps = APPS_PIPX.findall(sortie or "")
        if apps:
            return apps
    if libelle.startswith("go"):
        # go install pose le dernier segment du module : .../v2/cmd/subfinder@latest -> subfinder
        module = (commande or [""])[-1].split("@")[0]
        segments = [s for s in module.split("/") if s and s != "..."
                    and not re.fullmatch(r"v\d+", s)]
        return [segments[-1]] if len(segments) > 3 else [nom]
    if libelle.startswith("apt") and commande:
        # Le paquet apt (dernier argument) sert souvent de nom d'exécutable.
        return [commande[-1], nom.lower(), nom]
    return [nom.lower(), nom]


def _env_essai():
    """L'environnement d'un essai de démarrage. Une appli à fenêtres (Nebula, en Qt)
    s'ouvre « hors écran » : rien ne surgit pendant l'installation, et l'essai ne dépend
    pas de l'écran de la session."""
    return dict(os.environ, QT_QPA_PLATFORM="offscreen")


def repond(binaire, delai=60):
    """L'exécutable démarre-t-il vraiment ? Un paquet installé peut rester une coquille vide.

    Un outil qui tourne encore au bout du délai a DÉMARRÉ (garak ou Nebula chargent une
    IA avant d'afficher leur aide) : avant, Vigie le croyait en panne."""
    chemin = shutil.which(binaire)
    if not chemin:
        return False
    for arguments in (["--help"], ["-h"], []):
        try:
            # Lancé depuis le dossier temporaire : certains outils (Nettacker) créent
            # des fichiers là où on les lance, ils ne doivent pas salir le dossier Vigie.
            fini = subprocess.run([chemin] + arguments, capture_output=True,
                                  text=True, timeout=delai, errors="replace",
                                  stdin=subprocess.DEVNULL, cwd=tempfile.gettempdir(),
                                  env=_env_essai())
        except subprocess.TimeoutExpired:
            return True
        except OSError:
            continue
        # Beaucoup d'outils renvoient un code non nul sur --help : ce qui compte,
        # c'est qu'ils aient écrit quelque chose au lieu de planter au démarrage.
        if len(((fini.stdout or "") + (fini.stderr or "")).strip()) > 40 \
                and not _PLANTAGE.search(fini.stderr or ""):
            return True
    return False


# Un programme Python qui plante au démarrage écrit une longue trace (> 40 caractères) :
# ce n'est pas une aide, c'est une panne.
_PLANTAGE = re.compile(r"^Traceback \(most recent call last\)|^\w*(?:Import|ModuleNotFound)"
                       r"Error:", re.M)


# Un programme arrêté net ne dit rien : c'est le signal reçu qui explique.
_SIGNAUX = {9: "arrêté net par le système (mémoire pleine ?)",
            4: "refusé par le processeur (programme prévu pour un processeur plus récent)",
            11: "plantage (erreur de mémoire)", 6: "s'est arrêté tout seul (abandon)"}


def erreur_demarrage(binaires):
    """Pourquoi l'outil ne démarre pas : la dernière ligne de son message d'erreur
    (ex. « No module named 'pkg_resources' »), pour l'écrire dans le compte rendu.

    Jamais vide quand on sait quelque chose : le 26/11/2026, auto-archiver, Nebula et
    garak étaient « installés mais ne démarrent pas » sans aucune raison, parce que leur
    commande n'existait pas (reste d'une installation coupée) et que Vigie se taisait."""
    introuvables, muet = [], ""
    for binaire in binaires:
        chemin = shutil.which(binaire)
        if not chemin:
            introuvables.append(binaire)
            continue
        try:
            fini = subprocess.run([chemin, "--help"], capture_output=True, text=True,
                                  timeout=60, errors="replace", stdin=subprocess.DEVNULL,
                                  cwd=tempfile.gettempdir(), env=_env_essai())
        except subprocess.TimeoutExpired:
            muet = muet or f"{binaire} ne répond pas en 60 s"
            continue
        except OSError as erreur:
            muet = muet or f"{binaire} ne se lance pas ({erreur.strerror or erreur})"
            continue
        lignes = [l.strip() for l in (fini.stderr or fini.stdout or "").splitlines()
                  if l.strip()]
        if lignes:
            return lignes[-1][:160]
        if fini.returncode < 0:
            muet = muet or f"{binaire} : " + _SIGNAUX.get(
                -fini.returncode, f"arrêté par le système (signal {-fini.returncode})")
        else:
            muet = muet or f"{binaire} s'arrête sans aucun message (code {fini.returncode})"
    if muet:
        return muet
    if introuvables:
        return "aucune commande trouvée (" + ", ".join(introuvables[:3]) + ")"
    return ""


DOCS = os.path.join(os.path.dirname(__file__), "docs_outils.json")
# Un nom de paquet : lettres, chiffres, - _ . et d'éventuelles options entre crochets.
# Jamais un morceau d'adresse : « pip install git+https://…/impacket » donnait le paquet
# « git » (un paquet PyPI sans rapport !). Le nom doit finir là, pas sur « + : / ».
PAQUET = r"([A-Za-z0-9][A-Za-z0-9._-]*(?:\[[A-Za-z0-9,_-]+\])?)(?![A-Za-z0-9._+:/\[-])"
DOCUMENTEES = [
    ("brew (documenté)", re.compile(r"\bbrew install\s+" + PAQUET), ["brew", "install"]),
    ("pipx (documenté)", re.compile(r"\bpip[x3]? install\s+(?:--upgrade\s+|-U\s+)?" + PAQUET),
     ["pipx", "install"]),
    ("go (documenté)", re.compile(r"\bgo install\s+(?:-v\s+)?(github\.com/\S+@\S+)"), ["go", "install"]),
    ("npm (documenté)", re.compile(r"\bnpm (?:install|i) -g\s+" + PAQUET), ["npm", "install", "-g"]),
    # Linux (Debian/Ubuntu/Kali) : le paquet est celui écrit dans la doc de l'outil,
    # jamais deviné. -y pour ne pas bloquer sur une question.
    # DPkg::Lock::Timeout : apt ATTEND le verrou (jusqu'à 5 min) au lieu d'échouer
    # tout de suite si une mise à jour automatique l'occupe. C'est ce qui faisait
    # rater nmap, tcpdump, clamav… alors qu'ils sont bien dans les dépôts Ubuntu.
    # DEBIAN_FRONTEND=noninteractive + confdef/confold : aucune question à l'écran.
    ("apt (documenté)", re.compile(r"\bapt(?:-get)? install\s+" + PAQUET),
     ["sudo", "env", "DEBIAN_FRONTEND=noninteractive", "apt-get",
      "-o", "DPkg::Lock::Timeout=600", "-o", "Dpkg::Options::=--force-confdef",
      "-o", "Dpkg::Options::=--force-confold", "install", "-y"]),
]


def _install_documentee(outil, chemin=DOCS):
    """La ligne « install » relevée dans le dépôt de l'outil (docs_outils.json)."""
    try:
        docs = charger(chemin)
    except (OSError, ValueError):
        return ""
    lien = (outil.get("lien") or "").rstrip("/").lower()
    for fiche in docs:
        if fiche.get("nom") == outil.get("nom") or (
                lien and (fiche.get("lien") or "").rstrip("/").lower() == lien):
            return fiche.get("install") or ""
    return ""


def methodes(outil, install=None):
    """Les commandes à essayer pour cet outil.

    JAMAIS un paquet choisi sur son seul nom. Le 21/11/2026, l'ancienne méthode
    (« npm install -g <nom du dépôt> ») a posé 63 programmes sans rapport sur le Mac
    d'Anass : un téléchargeur de sous-titres à la place de Subfinder, etc. N'importe qui
    peut publier un paquet sous le nom d'un outil connu. On n'essaie donc que :
      1. les commandes écrites dans la documentation de l'outil (docs_outils.json) ;
      2. le dépôt GitHub de l'outil lui-même (pipx ou go, depuis son adresse exacte).
    """
    couple = depot(outil.get("lien", ""))
    if not couple:
        return []
    proprietaire, nom = couple
    texte = _install_documentee(outil) if install is None else install
    essais, vus = [], set()
    for libelle, motif, debut in DOCUMENTEES:
        for paquet in motif.findall(texte):
            commande = debut + [paquet]
            if paquet.startswith("-") or tuple(commande) in vus:
                continue
            vus.add(tuple(commande))
            essais.append((libelle, commande))
    # Repli sur le dépôt exact, SEULEMENT dans le langage de l'outil. Avant, Vigie
    # essayait pipx ET go sur tous les dépôts : sur un outil Docker, Node ou Rust, ça
    # ne pouvait que rater, avec des messages d'erreur trompeurs. Sans aucune
    # documentation, on ne connaît pas le langage : on essaie les deux.
    python, go = _langages(texte)
    if python:
        essais.append(("pipx (dépôt)",
                       ["pipx", "install", f"git+https://github.com/{proprietaire}/{nom}"]))
    if go:
        essais.append(("go (dépôt)", ["go", "install", f"github.com/{proprietaire}/{nom}@latest"]))
    return essais


_PYTHON = re.compile(r"\bpip[x3]?\b|python|\buv\b|setup\.py|pyproject|requirements", re.I)
_GO = re.compile(r"\bgo (?:install|build|get)\b|golang|\(go\)|\bGo\b")


def _langages(install):
    """(python ?, go ?) d'après la ligne d'installation documentée de l'outil."""
    if not (install or "").strip():
        return True, True
    return bool(_PYTHON.search(install)), bool(_GO.search(install))


def _compte(outil, installe=False, repond_=False, binaire="", methode="", raison="",
           manuel=False):
    compte = {"nom": outil["nom"], "installe": installe, "repond": repond_,
              "binaire": binaire, "methode": methode, "raison": raison}
    if manuel:
        compte["manuel"] = True  # pas une panne : l'outil se pose à la main
    return compte


def _premier_qui_repond(binaires):
    for binaire in binaires:
        if repond(binaire):
            return binaire
    return ""


def _par_recette(outil, a_blanc):
    """Les outils que la doc fait rater sous Ubuntu ont une recette à eux
    (vigie/recettes.py). Renvoie un compte rendu, ou None pour passer à la suite."""
    from . import presence, recettes
    trouvee = recettes.pour(outil["nom"])
    if not trouvee:
        return None
    libelle, recette = trouvee
    if a_blanc:
        return _compte(outil, methode=libelle, raison="à blanc : " + libelle)
    try:
        reussi, message, binaires = recette()
    except Exception as erreur:  # une recette qui plante laisse sa chance à la doc
        reussi, message, binaires = False, f"erreur : {erreur}", []
    if not reussi:
        return _compte(outil, raison=f"{libelle} : {message}")
    if binaires is None:  # des données (SecLists) : rien à démarrer, c'est prêt
        return _compte(outil, True, True, methode=libelle)
    candidats = binaires + [b for b in presence.binaires_possibles(outil["nom"])
                            if b not in binaires]
    binaire = _premier_qui_repond(candidats)
    if binaire:
        return _compte(outil, True, True, binaire, libelle)
    pourquoi = erreur_demarrage(candidats)
    return _compte(outil, True, methode=libelle,
                   raison="installé mais ne démarre pas" + (f" : {pourquoi}" if pourquoi else ""))


def installer_un(outil, a_blanc=False):
    """Essaie les méthodes l'une après l'autre, puis vérifie que l'outil démarre vraiment.
    Une recette Vigie (vigie/recettes.py) passe en premier quand l'outil en a une ;
    un outil qui se pose à la main (serveur, Windows, Kali…) n'est même pas essayé."""
    from . import recettes
    raison = recettes.manuel(outil["nom"])
    if raison or (not a_blanc and not methodes(outil) and not recettes.pour(outil["nom"])):
        # Un outil qui se pose à la main est peut-être DÉJÀ là (posé par Anass, ou
        # branché depuis l'interface) : on le reconnaît au lieu de noter « échec ».
        deja = "" if a_blanc else _deja_pose(outil)
        if deja:
            return _compte(outil, True, True, deja, "installé à la main")
    if raison:
        return _compte(outil, raison="à installer à la main : " + raison, manuel=True)
    recette = _par_recette(outil, a_blanc)
    if recette and (recette["installe"] or a_blanc):
        return recette
    # Quand une recette existe, c'est elle la méthode exacte : si elle rate, on ne
    # retombe pas sur un « go install <dépôt>@latest » deviné, qui ne peut que rater
    # avec une erreur trompeuse (Stratus Red Team, 26/11/2026). La doc reste essayée.
    resultat = _installer_par_doc(outil, a_blanc, devines=not recette)
    if recette and not resultat["installe"]:
        resultat["raison"] = " | ".join(r for r in (recette["raison"], resultat["raison"])
                                        if r)[:300]
        resultat.pop("manuel", None)
    return resultat


def _deja_pose(outil):
    """La commande de l'outil s'il est déjà sur la machine, sinon ""."""
    from . import a_la_main
    try:
        return a_la_main.deja_la(outil["nom"])
    except Exception:  # registre illisible, etc. : on continue comme avant
        return ""


# Python de secours. La VM d'Anass a Python 3.14 (très récent) : beaucoup d'outils ne
# s'y installent pas encore, ou s'installent mais plantent au démarrage. pipx sait
# alors utiliser un Python 3.12 à lui (--fetch-missing-python : il le télécharge depuis
# le projet officiel python-build-standalone, sans toucher au Python du système).
PYTHON_SECOURS = "3.12"
_PIPX_SECOURS = ["--python", PYTHON_SECOURS, "--fetch-missing-python"]
_NOM_PIPX = re.compile(r"installed package (\S+)")
# Un dossier de l'outil existe déjà (installation précédente, ou RESTE d'une installation
# coupée) : pipx répond « déjà installé », sans rien faire, avec le code 0.
_DEJA_PIPX = re.compile(r"'([^']+)'(?:\s+\([^)]*\))?\s+(?:already\s+seems\s+to\s+be|is"
                        r"\s+already)\s+installed", re.I)
# garak ou Nebula : ~6 Go à télécharger et décompresser (la bibliothèque d'IA torch).
DELAI_PYTHON = 1800


def _pipx_secours(commande):
    """La même commande pipx, avec le Python de secours."""
    return commande[:2] + _PIPX_SECOURS + commande[2:]


def _venv_pipx(commande, sortie):
    """Le nom sous lequel pipx a rangé l'outil (pour le désinstaller ou le lister)."""
    for motif in (_NOM_PIPX, _DEJA_PIPX):
        trouve = motif.search(sortie or "")
        if trouve:
            return trouve.group(1)
    return re.sub(r"\[.*\]$", "", commande[-1])  # le paquet de la doc, sans ses options


def _apps_pipx(venv):
    """Les commandes d'un outil que pipx a déjà rangé (pipx list --json)."""
    programme = shutil.which("pipx")
    if not programme:
        return []
    try:
        fini = subprocess.run([programme, "list", "--json"], capture_output=True, text=True,
                              timeout=120, errors="replace", stdin=subprocess.DEVNULL)
        donnees = json.loads(fini.stdout or "{}")
        paquet = donnees.get("venvs", {}).get(venv, {}).get("metadata", {}).get(
            "main_package", {})
        return [a for a in paquet.get("apps", []) if isinstance(a, str)]
    except (subprocess.TimeoutExpired, OSError, ValueError, AttributeError):
        return []


def _reinstaller_pipx(commande, sortie):
    """Réinstalle l'outil avec le Python de secours.

    pipx IGNORE --python quand on lui passe --force (vérifié : « pipx ignores --python
    when you pass --force ») : avant le 26/11/2026, la « réparation avec Python 3.12 »
    réinstallait en fait avec le même Python, et l'outil restait en panne. On retire donc
    d'abord ce que pipx a posé (l'outil ne démarre pas de toute façon), puis on réinstalle."""
    _lancer(["pipx", "uninstall", _venv_pipx(commande, sortie)], delai=300)
    return _lancer(_pipx_secours(commande), delai=DELAI_PYTHON)


def _installer_npm(commande):
    """npm passe par la méthode de vigie/recettes.py : Node assez récent, dossier de
    Vigie, aucun droit administrateur."""
    from . import recettes
    return recettes.installer_npm(commande[-1])


def _reparer_pipx(libelle, commande, sortie, candidats):
    """Un outil Python installé qui ne démarre pas. Deux réparations connues :
      1. « No module named 'pkg_resources' » (Impacket, ScoutSuite…) : il manque
         setuptools, que les Python récents ne mettent plus d'office -> on l'ajoute ;
      2. sinon, on le réinstalle avec le Python de secours (3.12).
    Renvoie (binaire qui répond ou "", libellé, message d'erreur au démarrage,
    toujours installé ?)."""
    pourquoi = erreur_demarrage(candidats)
    if "pkg_resources" in pourquoi:
        _lancer(["pipx", "inject", _venv_pipx(commande, sortie), "setuptools<81"])
        binaire = _premier_qui_repond(candidats)
        if binaire:
            return binaire, libelle + " + setuptools", "", True
        pourquoi = erreur_demarrage(candidats) or pourquoi
    reussi, message, sortie2 = _reinstaller_pipx(commande, sortie)
    if not reussi:
        # L'ancienne installation (en panne) a été retirée : l'outil n'est plus là.
        return "", libelle, "; ".join(r for r in (
            pourquoi, f"réinstallation avec Python {PYTHON_SECOURS} ratée : {message}") if r), \
            False
    libelle = f"{libelle} avec Python {PYTHON_SECOURS}"
    candidats = binaires_poses("pipx", sortie2, "", "") + candidats
    binaire = _premier_qui_repond(candidats)
    if binaire:
        return binaire, libelle, "", True
    return "", libelle, erreur_demarrage(candidats) or pourquoi, True


def _installer_par_doc(outil, a_blanc=False, devines=True):
    essais = methodes(outil)
    if not devines:
        essais = [(l, c) for l, c in essais if "(dépôt)" not in l]
        if not essais:
            return _compte(outil, raison="")
    if not essais:
        raison = ("pas de dépôt" if not depot(outil.get("lien", "")) else
                  "pas de méthode automatique sûre (s'installe à la main, voir sa doc)")
        return _compte(outil, raison=raison, manuel=True)
    if a_blanc:
        return _compte(outil, methode=essais[0][0],
                       raison="à blanc : " + " ".join(essais[0][1]))
    proprietaire, depot_nom = depot(outil.get("lien", ""))
    raisons = []
    from . import presence
    for libelle, commande in essais:
        poses = None
        if libelle.startswith("npm"):
            reussi, message, poses = _installer_npm(commande)
            sortie = ""
        elif libelle.startswith("pipx"):
            reussi, message, sortie = _lancer(commande, delai=DELAI_PYTHON)
        else:
            reussi, message, sortie = _lancer(commande)
        if not reussi and libelle.startswith("pipx") and "No apps associated" not in sortie \
                and " absent" not in message:
            # Échec sous le Python de la machine : on retente avec le Python de secours.
            reussi2, message2, sortie2 = _lancer(_pipx_secours(commande), delai=DELAI_PYTHON)
            if reussi2:
                reussi, sortie = True, sortie2
                libelle = f"{libelle} avec Python {PYTHON_SECOURS}"
            else:
                message = message2 or message
        if not reussi:
            if "No apps associated" in sortie:
                message = "c'est une bibliothèque Python, pas un programme (aucune commande)"
            raisons.append(f"{libelle} : {message}")
            continue
        # Installé n'est pas prêt : on lance l'exécutable pour le vérifier. Le nom du
        # paquet n'est pas toujours celui de la commande (clamav -> clamscan, sleuthkit
        # -> fls, fail2ban -> fail2ban-client) : on essaie aussi les commandes connues
        # de l'outil, sinon il passe à tort pour « installé mais ne démarre pas ».
        candidats = list(poses) if poses else binaires_poses(
            libelle, sortie, proprietaire, depot_nom, commande)
        if libelle.startswith("pipx") and _DEJA_PIPX.search(sortie or ""):
            # « Déjà installé » : pipx ne redit pas ses commandes, on les lui demande.
            candidats = _apps_pipx(_venv_pipx(commande, sortie)) + candidats
        candidats += [b for b in presence.binaires_possibles(outil["nom"])
                      if b not in candidats]
        binaire = _premier_qui_repond(candidats)
        if binaire:
            return _compte(outil, True, True, binaire, libelle)
        pourquoi, toujours = "", True
        if libelle.startswith("pipx"):
            binaire, libelle, pourquoi, toujours = _reparer_pipx(libelle, commande, sortie,
                                                                 candidats)
            if binaire:
                return _compte(outil, True, True, binaire, libelle)
        else:
            pourquoi = erreur_demarrage(candidats)
        if not toujours:
            return _compte(outil, methode=libelle, raison=f"{libelle} : {pourquoi}"[:300])
        return _compte(outil, True, methode=libelle,
                       raison="installé mais ne démarre pas"
                              + (f" : {pourquoi}" if pourquoi else ""))
    # Seulement « brew absent » (Mac) et « paquet introuvable » (Kali) : ce n'est pas
    # une panne, l'outil n'existe simplement pas tout prêt pour Ubuntu.
    manuel = all(re.search(r"brew absent|Impossible de trouver le paquet|Unable to locate "
                           r"package|has no installation candidate", r) for r in raisons)
    return _compte(outil, raison=" | ".join(raisons)[:300], manuel=manuel)


def installer(outils, a_blanc=False, journal=print, parallele=1, apres_chaque=None):
    """Installe une liste d'outils et renvoie le compte rendu de chacun.

    Installer, c'est surtout attendre un téléchargement : à la file, la machine
    ne fait rien la plupart du temps. En lançant plusieurs installations de front,
    on divise l'attente d'autant. Le premier outil passe seul, pour laisser pipx
    préparer son environnement partagé sans que huit processus se marchent dessus.

    parallele : un nombre, ou 0 / None = « auto » (d'après la mémoire libre).
    Les compilations (pip, pipx, go), elles, passent une par une quoi qu'il arrive
    (voir recettes.chantier) : ce sont elles qui ont rempli la mémoire de la VM.
    apres_chaque(comptes_rendus) est appelé après chaque outil : le compte rendu est
    écrit au fur et à mesure, un arrêt brutal ne fait plus tout perdre.
    """
    from . import recettes
    if not parallele:
        parallele = recettes.parallele_auto()
    recettes.limiter_compilations()
    if not a_blanc:
        # Les restes d'une installation coupée (mémoire pleine…) dans le dossier
        # temporaire de Vigie : rien ne tourne encore, on peut tout retirer.
        libere = recettes.nettoyer_restes()
        if libere >= 100:
            journal(f"  ({libere} Mo libérés : restes d'une installation précédente)")
    comptes_rendus = []

    def noter(resultat):
        comptes_rendus.append(resultat)
        if apres_chaque:
            try:
                apres_chaque(list(comptes_rendus))
            except OSError:
                pass  # disque plein, etc. : l'installation continue

    if parallele <= 1 or len(outils) < 2 or a_blanc:
        for numero, outil in enumerate(outils, 1):
            journal(f"[{numero}/{len(outils)}] {outil['nom']}…")
            resultat = installer_un(outil, a_blanc)
            etat = "ok" if resultat["installe"] else "échec"
            journal(f"    {etat} {resultat['methode']} {resultat['raison']}".rstrip())
            noter(resultat)
        return comptes_rendus

    import concurrent.futures
    total = len(outils)
    journal(f"[1/{total}] {outils[0]['nom']}… (seul, le temps que pipx se prépare)")
    premier = installer_un(outils[0], a_blanc)
    journal(f"    {'ok' if premier['installe'] else 'échec'} {premier['methode']}".rstrip())
    noter(premier)
    faits = 1
    with concurrent.futures.ThreadPoolExecutor(max_workers=parallele) as equipe:
        en_cours = {equipe.submit(installer_un, outil, a_blanc): outil
                    for outil in outils[1:]}
        journal(f"  ({len(en_cours)} outils restants, {parallele} à la fois, "
                "compilations une par une)")
        for fini in concurrent.futures.as_completed(en_cours):
            resultat = fini.result()
            faits += 1
            etat = "ok   " if resultat["installe"] else "échec"
            journal(f"[{faits}/{total}] {etat} {resultat['nom']} "
                    f"{resultat['methode']} {resultat['raison']}".rstrip())
            noter(resultat)
    return comptes_rendus


def resume(comptes_rendus):
    """Trois états, pas deux : installé ne veut pas dire utilisable."""
    reussis = [c for c in comptes_rendus if c["installe"]]
    prets = [c for c in reussis if c.get("repond")]
    # .get : un compte rendu repris d'un ancien rapport peut ne pas porter « methode ».
    a_la_main = [c for c in comptes_rendus if not c["installe"] and c.get("manuel")]
    # Parmi eux, ceux qui n'ont rien à faire sur cette machine (chez le client, Windows,
    # offensif, doublon) : ni une panne, ni un travail à faire (tri du 26/11/2026).
    from . import recettes
    pas_ici = [c for c in a_la_main if recettes.pas_ici(c.get("nom"))]
    return {"total": len(comptes_rendus), "installes": len(reussis),
            "prets": len(prets),
            "coquilles": len(reussis) - len(prets),
            "echecs": len(comptes_rendus) - len(reussis),
            # Parmi les échecs : ceux qui se posent à la main (serveurs, Windows, Kali…)
            # et les vraies pannes, à regarder.
            "a_la_main": len(a_la_main),
            "pas_ici": len(pas_ici),
            "a_poser": len(a_la_main) - len(pas_ici),
            "vrais_echecs": len(comptes_rendus) - len(reussis) - len(a_la_main),
            "par_methode": {m: sum(1 for c in reussis if c.get("methode", "") == m)
                            for m in sorted({c.get("methode", "") for c in reussis})}}
