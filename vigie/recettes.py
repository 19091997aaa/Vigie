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


def depot_python(depot, requirements, script, commande, nom):
    """Copie du dépôt GitHub exact + environnement Python à part + lanceur."""
    def recette():
        racine, commandes = dossiers()
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
        reussi, message, _ = _lancer([pip, "install", "-r",
                                      os.path.join(dossier, requirements)])
        if not reussi:
            return False, "pip : " + message, []
        ecrire_lanceur(os.path.join(commandes, commande), [
            f'exec "{os.path.join(venv, "bin", "python")}" "{os.path.join(dossier, script)}" "$@"'])
        return True, "", [commande]
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


def node_a_part():
    """Pose Node 22 dans le dossier de Vigie (site officiel, empreinte vérifiée).
    Renvoie (dossier bin de ce Node, message d'erreur)."""
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


def npm_moderne(paquet, binaires):
    """npm install -g, avec un Node assez récent : celui de la machine s'il suffit,
    sinon un Node 22 posé à part (le système n'est pas touché)."""
    def recette():
        if version_node() >= NODE_MINIMUM:
            reussi, message, _ = _lancer(["npm", "install", "-g", paquet])
            return reussi, message, list(binaires)
        bin_node, message = node_a_part()
        if not bin_node:
            return False, message, []
        racine, commandes = dossiers()
        prefixe = os.path.join(racine, "node-outils")
        env = dict(os.environ, PATH=bin_node + os.pathsep + os.environ.get("PATH", ""))
        reussi, message, _ = _lancer([os.path.join(bin_node, "npm"), "install", "-g",
                                      "--prefix", prefixe, paquet], env=env)
        if not reussi:
            return False, "npm : " + message, []
        for binaire in binaires:
            ecrire_lanceur(os.path.join(commandes, binaire), [
                f'PATH="{bin_node}:$PATH"', "export PATH",
                f'exec "{os.path.join(prefixe, "bin", binaire)}" "$@"'])
        return True, "", list(binaires)
    return recette


# nom (minuscules, comme dans le catalogue) -> (libellé, recette, systèmes concernés)
TOUS = ("linux", "darwin")
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
}


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
