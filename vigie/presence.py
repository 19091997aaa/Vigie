"""Est-ce qu'un outil du catalogue est installé sur CETTE machine ?

On ne fait que regarder : rien n'est installé ni lancé ici. On cherche un exécutable
de l'outil dans les dossiers où les installeurs les posent (outils.chemin_recherche).

Le nom d'un outil n'est pas toujours celui de sa commande : ClamAV se lance avec
« clamscan », radare2 avec « r2 », The Sleuth Kit avec « fls ». On essaie donc
plusieurs pistes, de la plus sûre à la moins sûre :
  1. un exécutable noté à la main pour les suites d'outils (BINAIRE_CONNU) ;
  2. la commande déclarée par Vigie (outils.CATALOGUE, lanceur, outils manuels) ;
  3. l'exécutable que l'installation de Vigie a vérifié (~/vigie-installation.json) ;
  4. la commande écrite au début de la ligne d'usage du catalogue ;
  5. le nom du dépôt GitHub, s'il ressemble au nom de l'outil.
L'outil est « installé » si l'une de ces commandes existe sur la machine.
"""
import json
import os
import re

from . import installeur, lanceur, manuel, outils, registre

# Suites d'outils dont l'usage, dans le catalogue, est une phrase et pas une commande :
# un exécutable sûr que leur paquet pose (Debian, Ubuntu, Kali).
BINAIRE_CONNU = {"the sleuth kit": "fls"}

# Rapport écrit par l'installeur Linux (installer-linux.command).
RAPPORT = "~/vigie-installation.json"

# Ce qui lance un script plutôt qu'un outil : le mot qui suit n'est pas l'outil.
_LANCEURS = {"docker", "npx", "go", "pipx", "pip", "pip3", "npm", "bash", "sh", "java",
             "node", "ruby", "perl", "php", "git", "make", "cargo", "dotnet", "pwsh",
             "powershell", "python", "python3"}
_COMMANDE = re.compile(r"^[A-Za-z][A-Za-z0-9_.+-]{0,40}$")
# Un mot de français : la ligne d'usage est une phrase (« suite complète d'audit… »).
_PHRASE = re.compile(r"[àâäéèêëîïôöùûüç]|^[dlDL]'|^(?:de|des|du|la|le|les|un|une|et|ou|"
                     r"pour|avec|sans|sur|en|par|puis|qui|que|dans)$")
# Un vrai argument : option (-x), emplacement ({cible}, <x>, [x]), fichier, adresse…
_ARGUMENT = re.compile(r"^-|[{<\[]|[A-Za-z0-9].*[/.=:@]|[/.=:@].*[A-Za-z0-9]|^\d+$")


def binaire_usage(usage):
    """La commande à taper, lue au début de la ligne d'usage. None si c'est une phrase.

    « clamscan [options] {fichier} » -> clamscan ; « fail2ban-client » -> fail2ban-client ;
    « suite complète d'audit… », « serveur DNS filtrant… » -> None (ce sont des phrases).
    """
    premier = (usage or "").split(";")[0].split("(")[0].strip()
    jetons = [j.strip("'\"") for j in premier.split()]
    if jetons[:1] == ["sudo"]:
        jetons = jetons[1:]
    if len(jetons) > 2 and jetons[0] in ("python", "python3") and jetons[1] == "-m":
        jetons = jetons[2:]                       # « python3 -m garak » -> garak
    if not jetons:
        return None
    commande, suite = jetons[0], jetons[1:]
    if commande.lower() in _LANCEURS or not _COMMANDE.match(commande):
        return None                               # script, docker, chemin « ./… »
    if len(commande) > 3 and commande.isupper():
        return None                               # « SURTOUT via… », « ATTENTION… »
    if any(_PHRASE.search(mot) for mot in suite):
        return None
    if suite and not any(_ARGUMENT.search(mot) for mot in suite):
        return None                               # que des mots : une description
    return commande


def _ressemble(depot_nom, nom):
    """Le dépôt porte-t-il le nom de l'outil ? (« opnsense/core » : non, trop vague)"""
    a = re.sub(r"[^a-z0-9]", "", depot_nom.lower())
    b = re.sub(r"[^a-z0-9]", "", nom.lower())
    return bool(a and b) and (a in b or b in a)


def rapport_installation(chemin=RAPPORT):
    """{nom en minuscules : exécutable vérifié} d'après la dernière installation.
    Vide s'il n'y a pas encore eu d'installation sur cette machine."""
    try:
        with open(os.path.expanduser(chemin), encoding="utf-8") as fichier:
            details = json.load(fichier).get("details", [])
    except (OSError, ValueError, AttributeError):
        return {}
    return {d["nom"].lower(): d["binaire"] for d in details
            if isinstance(d, dict) and d.get("nom") and d.get("repond") and d.get("binaire")}


def echecs_installation(chemin=RAPPORT):
    """{nom en minuscules : raison} des outils dont la dernière installation a raté.
    Vide s'il n'y a pas encore eu d'installation sur cette machine."""
    try:
        with open(os.path.expanduser(chemin), encoding="utf-8") as fichier:
            details = json.load(fichier).get("details", [])
    except (OSError, ValueError, AttributeError):
        return {}
    return {d["nom"].lower(): d.get("raison") or "raison non notée" for d in details
            if isinstance(d, dict) and d.get("nom") and not d.get("repond")}


def binaires_possibles(nom, verifies=None):
    """Les commandes dont la présence prouve que l'outil est installé (sans doublon)."""
    cle = (nom or "").strip().lower()
    possibles = []

    def ajouter(binaire):
        if binaire and binaire not in possibles:
            possibles.append(binaire)

    ajouter(BINAIRE_CONNU.get(cle))
    for nom_cat, outil in outils.CATALOGUE.items():
        if nom_cat.lower() == cle:
            ajouter(outil["commande"])
    for nom_decl, decl in lanceur.LANCEMENTS.items():
        if nom_decl.lower() == cle:
            ajouter(decl["commande"])
    for nom_decl, decl in manuel.OUTILS.items():
        if nom_decl.lower() == cle:
            ajouter(decl["outil"])
    ajouter((verifies or {}).get(cle))
    fiche = _fiche(cle)
    if fiche:
        ajouter(binaire_usage(fiche.get("usage", "")))
        couple = installeur.depot(fiche.get("lien", ""))
        if couple and _ressemble(couple[1], fiche["nom"]):
            ajouter(couple[1])
            ajouter(couple[1].lower())
    return possibles


_FICHES = None


def _fiche(cle):
    global _FICHES
    if _FICHES is None:
        _FICHES = {o["nom"].lower(): o for o in registre.charger()}
    return _FICHES.get(cle)


def installe(nom, verifies=None):
    """True : une commande de l'outil existe ici. False : aucune. None : rien à chercher."""
    possibles = binaires_possibles(nom, verifies)
    if not possibles:
        return None
    return any(outils.trouver(binaire) for binaire in possibles)


def etat(verifies=None):
    """{nom du registre : True / False / None} pour tous les outils, en une passe."""
    if verifies is None:
        verifies = rapport_installation()
    return {o["nom"]: installe(o["nom"], verifies) for o in registre.charger()}
