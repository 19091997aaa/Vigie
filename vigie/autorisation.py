"""Le garde-fou légal de Vigie.

Un module actif (scan, recherche de failles) ne tourne que si l'autorisation
signée du client est fournie. Son empreinte est inscrite dans le rapport :
on peut prouver quel document couvrait quel diagnostic.
"""
import hashlib
import os

from .modeles import ControleImpossible


class AutorisationManquante(ControleImpossible):
    """Sans autorisation, le contrôle est refusé et listé comme non réalisé."""


def verifier(chemin):
    """Renvoie la trace de l'autorisation, ou lève AutorisationManquante."""
    if not chemin:
        raise AutorisationManquante(
            "Ce contrôle touche aux machines du client. "
            "Fournir l'autorisation signée avec --autorisation fichier.pdf")
    if not os.path.isfile(chemin):
        raise AutorisationManquante(f"Fichier d'autorisation introuvable : {chemin}")
    with open(chemin, "rb") as fichier:
        empreinte = hashlib.sha256(fichier.read()).hexdigest()
    return {"fichier": os.path.basename(chemin), "empreinte_sha256": empreinte}
