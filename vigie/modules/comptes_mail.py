"""Bloc Exposition - sur quels sites l'adresse mail du dirigeant est inscrite (outil : Holehe).

Holehe demande à chaque site « cette adresse a-t-elle un compte ? » par la page
« mot de passe oublié », sans envoyer de mail à la personne. Un compte oublié avec
un vieux mot de passe est une porte d'entrée.

Donnée personnelle : seulement avec l'adresse donnée par le dirigeant ET son accord
écrit. Holehe n'interroge pas de base de fuites.
"""
import re

from .. import outils
from ..modeles import INFO, OK, Constat, ControleImpossible

BLOC = "Exposition"
MAIL = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,}")
LIGNE = re.compile(r"^\[\+\]\s+(\S+)")
MAXIMUM_AFFICHE = 25


def lire_sortie(texte):
    """Les sites où l'adresse est inscrite (lignes « [+] site » de Holehe)."""
    sites = []
    for ligne in (texte or "").splitlines():
        trouve = LIGNE.match(ligne.strip())
        if trouve and "email used" not in ligne.lower() and trouve.group(1) not in sites:
            sites.append(trouve.group(1))
    return sites


def analyser(cible):
    if not cible.emails:
        raise ControleImpossible("aucune adresse mail fournie par le dirigeant")
    if not cible.accord_dirigeant:
        raise ControleImpossible("accord écrit du dirigeant requis (--accord-dirigeant)")
    constats, brut = [], {}
    for adresse in cible.emails:
        if not MAIL.fullmatch(adresse):
            raise ControleImpossible(f"adresse mail invalide : {adresse}")
        sites = lire_sortie(outils.executer("holehe", ["--only-used", "--no-color", adresse],
                                            delai=600))
        brut[adresse] = sites
        if not sites:
            constats.append(Constat(BLOC, OK, "Aucun compte trouvé pour l'adresse du dirigeant",
                                    "Aucun des sites contrôlés n'a de compte à cette adresse."))
            continue
        noms = ", ".join(sites[:MAXIMUM_AFFICHE])
        if len(sites) > MAXIMUM_AFFICHE:
            noms += f" et {len(sites) - MAXIMUM_AFFICHE} autres"
        constats.append(Constat(
            BLOC, INFO, f"L'adresse du dirigeant a un compte sur {len(sites)} sites",
            f"Sites : {noms}. Chaque compte oublié, surtout avec un ancien mot de passe, "
            "est une porte d'entrée vers la messagerie et ce qu'elle contient.",
            "Fermer les comptes inutilisés ; mot de passe unique et double authentification "
            "sur les autres, en priorité sur la messagerie."))
    return constats, brut
