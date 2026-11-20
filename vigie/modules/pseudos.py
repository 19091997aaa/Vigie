"""Bloc Exposition - comptes publics du dirigeant (outil externe : Sherlock).

Donnée personnelle : ce module ne tourne que si le dirigeant a donné ses pseudos
ET son accord écrit. Jamais sur un tiers.
"""
import re
import tempfile

from .. import outils
from ..modeles import INFO, OK, Constat, ControleImpossible

BLOC = "Exposition"
PSEUDO = re.compile(r"[A-Za-z0-9._-]{2,40}")
LIGNE = re.compile(r"^\[\+\]\s*(.+?):\s*(https?://\S+)\s*$")
MAXIMUM_AFFICHE = 25


def lire_sortie(texte):
    """Extrait les comptes trouvés de ce que Sherlock affiche."""
    comptes = []
    for ligne in texte.splitlines():
        trouve = LIGNE.match(ligne.strip())
        if trouve:
            comptes.append({"site": trouve.group(1), "adresse": trouve.group(2)})
    return comptes


def analyser(cible):
    if not cible.pseudos:
        raise ControleImpossible("aucun pseudo fourni par le dirigeant")
    if not cible.accord_dirigeant:
        raise ControleImpossible(
            "accord écrit du dirigeant requis pour chercher ses comptes (--accord-dirigeant)")
    constats, brut = [], {}
    for pseudo in cible.pseudos:
        if not PSEUDO.fullmatch(pseudo):
            raise ControleImpossible(f"pseudo invalide : {pseudo}")
        with tempfile.TemporaryDirectory() as dossier:
            sortie = outils.executer(
                "sherlock", [pseudo, "--print-found", "--no-color", "--timeout", "15"],
                delai=900, dossier=dossier)
        comptes = lire_sortie(sortie)
        brut[pseudo] = comptes
        if not comptes:
            constats.append(Constat(BLOC, OK, f"Aucun compte public trouvé au pseudo « {pseudo} »",
                                    "Aucun des sites contrôlés n'affiche de compte à ce nom."))
            continue
        noms = ", ".join(c["site"] for c in comptes[:MAXIMUM_AFFICHE])
        reste = len(comptes) - MAXIMUM_AFFICHE
        if reste > 0:
            noms += f" et {reste} autres"
        constats.append(Constat(
            BLOC, INFO, f"{len(comptes)} comptes publics au pseudo « {pseudo} »",
            "Sites concernés : " + noms + ". Chaque compte oublié est une porte : mot de passe "
            "réutilisé, informations utiles à un escroc pour se faire passer pour vous. "
            "Résultat automatique, à confirmer compte par compte.",
            "Fermer les comptes inutilisés. Mot de passe unique et double authentification "
            "sur ceux que vous gardez."))
    return constats, brut
