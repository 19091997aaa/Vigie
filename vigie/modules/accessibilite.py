"""Bloc Exposition - accessibilité de la page d'accueil (outil externe : Pa11y).

Pa11y charge la page dans Chrome et la confronte au référentiel WCAG 2 niveau AA
(celui exigé par la loi européenne sur l'accessibilité pour une partie des
entreprises depuis juin 2025). Ce n'est pas de la sécurité : le constat ne compte
pas dans la note, mais il intéresse le dirigeant.
"""
import json
import os
import tempfile

from .. import outils, pdf
from ..modeles import INFO, OK, Constat, ControleImpossible

BLOC = "Exposition"


def lire_sortie(texte):
    try:
        problemes = json.loads(texte or "")
    except json.JSONDecodeError:
        raise ControleImpossible("Pa11y n'a pas renvoyé de résultat lisible")
    if not isinstance(problemes, list):
        raise ControleImpossible("Pa11y n'a pas renvoyé de résultat lisible")
    return [p for p in problemes if p.get("type") == "error"]


def analyser(cible):
    navigateur = pdf.trouver_navigateur()
    if not navigateur:
        raise ControleImpossible("aucun navigateur Chrome ou Edge pour Pa11y")
    # Pa11y lit un fichier « pa11y.json » du dossier courant comme réglages : dossier vide.
    with tempfile.TemporaryDirectory() as dossier:
        os.environ.setdefault("PUPPETEER_EXECUTABLE_PATH", navigateur)
        texte = outils.executer("pa11y", ["--reporter", "json", "--standard", "WCAG2AA",
                                          "https://" + cible.domaine + "/"],
                                delai=180, dossier=dossier)
    erreurs = lire_sortie(texte)
    brut = {"accessibilite": {"erreurs": len(erreurs)}}
    if not erreurs:
        return [Constat(BLOC, OK, "Page d'accueil accessible (WCAG 2 AA)",
                        "Aucun défaut d'accessibilité détecté automatiquement.",
                        cle="accessibilite")], brut
    return [Constat(
        BLOC, INFO, f"{len(erreurs)} défaut{'s' if len(erreurs) > 1 else ''} d'accessibilité "
                    "sur la page d'accueil",
        "Des personnes malvoyantes ou qui naviguent au clavier auront du mal à utiliser "
        "le site. Pour certaines entreprises, c'est une obligation légale depuis juin 2025.",
        "Faire corriger ces défauts par la personne qui gère le site.",
        cle="accessibilite", hors_note=True)], brut
