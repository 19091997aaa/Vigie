"""Bloc Conformité assureur : confronte les réponses du dirigeant aux exigences réelles
des assureurs cyber. Produit la fiche qui dit ce qui tient et ce qui expose à un refus.

Pas de scan, pas de réseau : c'est un questionnaire. Les réponses viennent du dirigeant
(cible.reponses : id de question -> True/False). Une question sans réponse est listée
comme « à vérifier », jamais comptée comme un défaut.
"""
from .. import questionnaire
from ..modeles import OK, Constat, ControleImpossible

BLOC = "Conformité assureur"


def analyser(cible):
    if not cible.reponses:
        raise ControleImpossible(
            "questionnaire assureur non rempli (fournir les réponses avec --reponses)")
    constats, a_verifier = [], []
    for question in questionnaire.QUESTIONS:
        reponse = cible.reponses.get(question["id"])
        if reponse is True:
            constats.append(Constat(
                BLOC, OK, "Conforme : " + question["question"],
                f"Exigence demandée par {question['assureurs']}, remplie.",
                cle="assureur_" + question["id"]))
        elif reponse is False:
            constats.append(Constat(
                BLOC, question["gravite_si_non"],
                "À régler : " + question["question"],
                question["pourquoi"] + f" (demandé par {question['assureurs']}.)",
                correction="Mettre en place cette mesure avant votre prochaine "
                           "déclaration d'assurance.",
                cle="assureur_" + question["id"]))
        else:
            a_verifier.append(question["question"])
    brut = {"reponses": cible.reponses, "a_verifier": a_verifier}
    if a_verifier and not constats:
        raise ControleImpossible("aucune réponse exploitable dans le questionnaire")
    return constats, brut
