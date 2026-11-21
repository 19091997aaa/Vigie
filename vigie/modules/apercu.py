"""Capture d'écran de la page d'accueil, pour illustrer le rapport (outil : gowitness).

Ce n'est pas un contrôle : aucun constat, aucun point retiré. La capture montre au
dirigeant son site tel que le voit un visiteur, en tête du rapport. Elle est gardée
dans le rapport lui-même (image intégrée), qui reste un seul fichier à envoyer.

gowitness télécharge son propre navigateur s'il n'en trouve pas : Vigie lui donne
toujours le Chrome (ou Edge) déjà installé, et renonce s'il n'y en a pas.
"""
import base64
import glob
import os
import tempfile

from .. import outils, pdf
from ..modeles import ControleImpossible

TAILLE_MAXIMUM = 2_000_000


def analyser(cible):
    navigateur = pdf.trouver_navigateur()
    if not navigateur:
        raise ControleImpossible("aucun navigateur Chrome ou Edge pour la capture d'écran")
    with tempfile.TemporaryDirectory() as dossier:
        captures = os.path.join(dossier, "captures")
        outils.executer("gowitness", [
            "scan", "single", "-u", "https://" + cible.domaine, "--chrome-path", navigateur,
            "-s", captures, "--write-none", "--skip-html", "--skip-network-logs", "-q",
            "-T", "45", "--delay", "4"], delai=120, dossier=dossier)
        images = sorted(glob.glob(os.path.join(captures, "*.jpeg"))
                        + glob.glob(os.path.join(captures, "*.png")))
        if not images or os.path.getsize(images[0]) > TAILLE_MAXIMUM:
            raise ControleImpossible("gowitness n'a pas pu photographier la page d'accueil")
        with open(images[0], "rb") as image:
            contenu = base64.b64encode(image.read()).decode("ascii")
    type_image = "image/png" if images[0].endswith(".png") else "image/jpeg"
    return [], {"apercu": {"type": type_image, "image_base64": contenu}}
