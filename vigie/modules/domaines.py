"""Bloc Exposition - noms de domaine qui imitent celui de la société (outil externe : dnstwist).

dnstwist fabrique les variantes typographiques du domaine (lettres interverties,
accents, extensions voisines) et regarde lesquelles sont enregistrées. Un domaine
imitateur enregistré sert souvent à l'hameçonnage. Lecture publique, aucun accord
technique requis.
"""
import json

from .. import outils
from ..modeles import IMPORTANT, INFO, OK, Constat, ControleImpossible

BLOC = "Exposition"
MAXIMUM_AFFICHE = 15


def lire_sortie(texte):
    """Garde les variantes réellement enregistrées (celles qui ont une adresse IP)."""
    try:
        lignes = json.loads(texte)
    except (json.JSONDecodeError, TypeError):
        raise ControleImpossible("dnstwist n'a pas renvoyé de résultat lisible")
    imitateurs = []
    for entree in lignes:
        if entree.get("fuzzer") in (None, "original", "*original"):
            continue
        if entree.get("dns_a") or entree.get("dns_ns") or entree.get("dns_mx"):
            imitateurs.append({
                "domaine": entree.get("domain", ""),
                "type": entree.get("fuzzer", ""),
                "ip": (entree.get("dns_a") or [""])[0],
                "mx": bool(entree.get("dns_mx")),
            })
    return imitateurs


def analyser(cible):
    sortie = outils.executer(
        "dnstwist", ["--format", "json", "--registered", cible.domaine], delai=600)
    imitateurs = lire_sortie(sortie)
    brut = {"imitateurs": imitateurs}
    if not imitateurs:
        return [Constat(BLOC, OK, "Aucun domaine imitateur enregistré",
                        "Aucune variante trompeuse de votre nom de domaine n'est enregistrée "
                        "aujourd'hui.", cle="domaines_imitateurs")], brut
    # Un imitateur qui peut recevoir du mail (MX) est le plus dangereux : faux mails crédibles.
    avec_mail = [i for i in imitateurs if i["mx"]]
    niveau = IMPORTANT if avec_mail else INFO
    noms = ", ".join(i["domaine"] for i in imitateurs[:MAXIMUM_AFFICHE])
    reste = len(imitateurs) - MAXIMUM_AFFICHE
    if reste > 0:
        noms += f" et {reste} autres"
    detail = (f" Dont {len(avec_mail)} capables de recevoir du courrier, donc d'envoyer "
              "de faux mails à votre nom." if avec_mail else "")
    return [Constat(
        BLOC, niveau, f"{len(imitateurs)} domaines imitent le vôtre",
        f"Variantes enregistrées : {noms}.{detail} Un escroc peut s'en servir pour piéger "
        "vos clients ou vos salariés.",
        "Surveiller ces domaines, signaler les plus proches pour fermeture, et prévenir "
        "vos équipes de vérifier l'adresse exacte.", cle="domaines_imitateurs")], brut
