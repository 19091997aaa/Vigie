"""Bloc Exposition - adresses annexes de la société (sous-domaines), outil externe : Subfinder.

Subfinder interroge des sources publiques (journaux des certificats, archives DNS) :
aucune question n'est posée aux machines de la société. Chaque adresse annexe est
une porte d'entrée : un ancien site de test oublié est une cible classique.

Comparé à Amass le 21/11/2026 sur pavillon-noir.tech : Subfinder en trouve 1 en
20 secondes, Amass 0 (et laisse un moteur tourner après coup). Subfinder est gardé.
"""
import json
import time

from .. import outils
from ..modeles import INFO, OK, Constat

BLOC = "Exposition"
MAXIMUM_AFFICHE = 15
# Le module technos réutilise la liste : on ne relance pas Subfinder deux fois.
DUREE_CACHE = 600
_CACHE = {}


def lire_sortie(texte, domaine):
    """Garde les sous-domaines du domaine lui-même, jamais un nom d'un tiers."""
    noms = set()
    for ligne in (texte or "").splitlines():
        ligne = ligne.strip()
        if not ligne:
            continue
        try:
            hote = json.loads(ligne).get("host", "")
        except (json.JSONDecodeError, AttributeError):
            hote = ligne
        hote = hote.strip().lower().rstrip(".").removeprefix("*.")
        if hote.endswith("." + domaine):
            noms.add(hote)
    return sorted(noms)


def trouver(domaine):
    """La liste des sous-domaines, gardée 10 minutes pour les autres modules."""
    instant, liste = _CACHE.get(domaine, (0, None))
    if liste is not None and time.time() - instant < DUREE_CACHE:
        return liste
    sortie = outils.executer(
        "subfinder", ["-d", domaine, "-silent", "-oJ", "-timeout", "20", "-max-time", "3"],
        delai=240)
    liste = lire_sortie(sortie, domaine)
    _CACHE[domaine] = (time.time(), liste)
    return liste


def analyser(cible):
    noms = trouver(cible.domaine)
    brut = {"sous_domaines": noms}
    annexes = [nom for nom in noms if nom != "www." + cible.domaine]
    if not annexes:
        return [Constat(BLOC, OK, "Aucune adresse annexe visible publiquement",
                        "En dehors du site principal, aucune autre adresse de la société "
                        "n'apparaît dans les sources publiques.", cle="sous_domaines")], brut
    liste = ", ".join(annexes[:MAXIMUM_AFFICHE])
    if len(annexes) > MAXIMUM_AFFICHE:
        liste += f" et {len(annexes) - MAXIMUM_AFFICHE} autres"
    return [Constat(
        BLOC, INFO, f"{len(annexes)} adresses annexes visibles publiquement",
        f"Adresses trouvées : {liste}. Chacune est une porte d'entrée possible : une "
        "adresse oubliée (ancien site, site de test) est souvent mal protégée.",
        "Faire la liste de ces adresses, fermer celles qui ne servent plus, et tenir "
        "les autres à jour.", cle="sous_domaines")], brut
