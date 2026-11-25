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
import contextlib
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
    verrou = VERROU_APT if "apt-get" in commande else contextlib.nullcontext()
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
                                  stdin=subprocess.DEVNULL, cwd=tempfile.gettempdir())
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


def erreur_demarrage(binaires):
    """Pourquoi l'outil ne démarre pas : la dernière ligne de son message d'erreur
    (ex. « No module named 'pkg_resources' »), pour l'écrire dans le compte rendu."""
    for binaire in binaires:
        chemin = shutil.which(binaire)
        if not chemin:
            continue
        try:
            fini = subprocess.run([chemin, "--help"], capture_output=True, text=True,
                                  timeout=60, errors="replace", stdin=subprocess.DEVNULL,
                                  cwd=tempfile.gettempdir())
        except (subprocess.TimeoutExpired, OSError):
            continue
        lignes = [l.strip() for l in (fini.stderr or fini.stdout or "").splitlines()
                  if l.strip()]
        if lignes:
            return lignes[-1][:160]
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
    if raison:
        return _compte(outil, raison="à installer à la main : " + raison, manuel=True)
    recette = _par_recette(outil, a_blanc)
    if recette and (recette["installe"] or a_blanc):
        return recette
    resultat = _installer_par_doc(outil, a_blanc)
    if recette and not resultat["installe"]:
        resultat["raison"] = (recette["raison"] + " | " + resultat["raison"])[:300]
        resultat.pop("manuel", None)
    return resultat


# Python de secours. La VM d'Anass a Python 3.14 (très récent) : beaucoup d'outils ne
# s'y installent pas encore, ou s'installent mais plantent au démarrage. pipx sait
# alors utiliser un Python 3.12 à lui (--fetch-missing-python : il le télécharge depuis
# le projet officiel python-build-standalone, sans toucher au Python du système).
PYTHON_SECOURS = "3.12"
_PIPX_SECOURS = ["--python", PYTHON_SECOURS, "--fetch-missing-python"]
_NOM_PIPX = re.compile(r"installed package (\S+)")


def _pipx_secours(commande, forcer=False):
    """La même commande pipx, avec le Python de secours."""
    return commande[:2] + (["--force"] if forcer else []) + _PIPX_SECOURS + commande[2:]


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
    Renvoie (binaire qui répond ou "", libellé, message d'erreur au démarrage)."""
    pourquoi = erreur_demarrage(candidats)
    nom = _NOM_PIPX.search(sortie or "")
    if "pkg_resources" in pourquoi and nom:
        _lancer(["pipx", "inject", nom.group(1), "setuptools<81"])
        binaire = _premier_qui_repond(candidats)
        if binaire:
            return binaire, libelle + " + setuptools", ""
        pourquoi = erreur_demarrage(candidats) or pourquoi
    reussi, _, sortie2 = _lancer(_pipx_secours(commande, forcer=True))
    if reussi:
        candidats = binaires_poses("pipx", sortie2, "", "") + candidats
        binaire = _premier_qui_repond(candidats)
        if binaire:
            return binaire, f"{libelle} avec Python {PYTHON_SECOURS}", ""
        pourquoi = erreur_demarrage(candidats) or pourquoi
    return "", libelle, pourquoi


def _installer_par_doc(outil, a_blanc=False):
    essais = methodes(outil)
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
        else:
            reussi, message, sortie = _lancer(commande)
        if not reussi and libelle.startswith("pipx") and "No apps associated" not in sortie \
                and " absent" not in message:
            # Échec sous le Python de la machine : on retente avec le Python de secours.
            reussi2, message2, sortie2 = _lancer(_pipx_secours(commande))
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
        candidats += [b for b in presence.binaires_possibles(outil["nom"])
                      if b not in candidats]
        binaire = _premier_qui_repond(candidats)
        if binaire:
            return _compte(outil, True, True, binaire, libelle)
        pourquoi = ""
        if libelle.startswith("pipx"):
            binaire, libelle, pourquoi = _reparer_pipx(libelle, commande, sortie, candidats)
            if binaire:
                return _compte(outil, True, True, binaire, libelle)
        else:
            pourquoi = erreur_demarrage(candidats)
        return _compte(outil, True, methode=libelle,
                       raison="installé mais ne démarre pas"
                              + (f" : {pourquoi}" if pourquoi else ""))
    # Seulement « brew absent » (Mac) et « paquet introuvable » (Kali) : ce n'est pas
    # une panne, l'outil n'existe simplement pas tout prêt pour Ubuntu.
    manuel = all(re.search(r"brew absent|Impossible de trouver le paquet|Unable to locate "
                           r"package|has no installation candidate", r) for r in raisons)
    return _compte(outil, raison=" | ".join(raisons)[:300], manuel=manuel)


def installer(outils, a_blanc=False, journal=print, parallele=1):
    """Installe une liste d'outils et renvoie le compte rendu de chacun.

    Installer, c'est surtout attendre un téléchargement : à la file, la machine
    ne fait rien la plupart du temps. En lançant plusieurs installations de front,
    on divise l'attente d'autant. Le premier outil passe seul, pour laisser pipx
    préparer son environnement partagé sans que huit processus se marchent dessus.
    """
    if parallele <= 1 or len(outils) < 2 or a_blanc:
        comptes_rendus = []
        for numero, outil in enumerate(outils, 1):
            journal(f"[{numero}/{len(outils)}] {outil['nom']}…")
            resultat = installer_un(outil, a_blanc)
            etat = "ok" if resultat["installe"] else "échec"
            journal(f"    {etat} {resultat['methode']} {resultat['raison']}".rstrip())
            comptes_rendus.append(resultat)
        return comptes_rendus

    import concurrent.futures
    total = len(outils)
    journal(f"[1/{total}] {outils[0]['nom']}… (seul, le temps que pipx se prépare)")
    premier = installer_un(outils[0], a_blanc)
    journal(f"    {'ok' if premier['installe'] else 'échec'} {premier['methode']}".rstrip())
    comptes_rendus = [premier]
    faits = 1
    with concurrent.futures.ThreadPoolExecutor(max_workers=parallele) as equipe:
        en_cours = {equipe.submit(installer_un, outil, a_blanc): outil
                    for outil in outils[1:]}
        journal(f"  ({len(en_cours)} outils restants, {parallele} à la fois)")
        for fini in concurrent.futures.as_completed(en_cours):
            resultat = fini.result()
            faits += 1
            etat = "ok   " if resultat["installe"] else "échec"
            journal(f"[{faits}/{total}] {etat} {resultat['nom']} "
                    f"{resultat['methode']} {resultat['raison']}".rstrip())
            comptes_rendus.append(resultat)
    return comptes_rendus


def resume(comptes_rendus):
    """Trois états, pas deux : installé ne veut pas dire utilisable."""
    reussis = [c for c in comptes_rendus if c["installe"]]
    prets = [c for c in reussis if c.get("repond")]
    # .get : un compte rendu repris d'un ancien rapport peut ne pas porter « methode ».
    a_la_main = [c for c in comptes_rendus if not c["installe"] and c.get("manuel")]
    return {"total": len(comptes_rendus), "installes": len(reussis),
            "prets": len(prets),
            "coquilles": len(reussis) - len(prets),
            "echecs": len(comptes_rendus) - len(reussis),
            # Parmi les échecs : ceux qui se posent à la main (serveurs, Windows, Kali…)
            # et les vraies pannes, à regarder.
            "a_la_main": len(a_la_main),
            "vrais_echecs": len(comptes_rendus) - len(reussis) - len(a_la_main),
            "par_methode": {m: sum(1 for c in reussis if c.get("methode", "") == m)
                            for m in sorted({c.get("methode", "") for c in reussis})}}
