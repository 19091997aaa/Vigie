"""Bloc Exposition - adresses mail de la société visibles publiquement (outil : theHarvester).

theHarvester cherche le nom de domaine dans des sources publiques (moteurs de
recherche, journaux des certificats, archives). Une adresse mail visible partout
finit dans les listes des escrocs : c'est elle qui reçoit les mails piégés.

Deux règles du diagnostic gratuit (MARCHE.md §2) :
  - theHarvester sait aussi fouiller des FUITES de données (dehashed, haveibeenpwned,
    leaklookup...). C'est interdit à froid : Vigie ne lui donne que la liste SOURCES
    ci-dessous, toutes publiques, sans fuite.
  - les adresses et les noms ne sont que COMPTÉS, jamais listés ni gardés.
"""
import json
import os
import tempfile

from .. import outils
from ..modeles import INFO, OK, Constat, ControleImpossible

BLOC = "Exposition"
SOURCES = ("crtsh", "certspotter", "hackertarget", "rapiddns", "otx", "urlscan",
           "waybackarchive", "duckduckgo", "yahoo", "mojeek", "subdomaincenter", "thc",
           "robtex")
# Jamais ces sources : elles lisent des fuites de données.
INTERDITES = ("dehashed", "haveibeenpwned", "hudsonrock", "leaklookup", "intelx",
              "leakix", "venacus")


def lire_sortie(data, domaine):
    """Compte les adresses du domaine et les personnes trouvées. Rien d'autre n'est gardé."""
    adresses = {a.strip().lower() for a in (data or {}).get("emails") or []
                if a.strip().lower().endswith("@" + domaine)}
    personnes = {str(p).strip().lower() for p in (data or {}).get("people") or [] if str(p).strip()}
    hotes = {h.split(":")[0].strip().lower() for h in (data or {}).get("hosts") or []}
    hotes = {h for h in hotes if h.endswith("." + domaine)}
    return {"adresses": len(adresses), "personnes": len(personnes), "hotes": len(hotes)}


def analyser(cible):
    assert not set(SOURCES) & set(INTERDITES)  # garde-fou : aucune source de fuite
    with tempfile.TemporaryDirectory() as dossier:
        base = os.path.join(dossier, "resultat")
        outils.executer("theHarvester", ["-d", cible.domaine, "-l", "200", "-q",
                                         "-b", ",".join(SOURCES), "-f", base],
                        delai=300, dossier=dossier)
        try:
            with open(base + ".json", encoding="utf-8") as lu:
                data = json.load(lu)
        except (OSError, json.JSONDecodeError):
            raise ControleImpossible("theHarvester n'a pas produit de résultat lisible")
    compte = lire_sortie(data, cible.domaine)
    brut = {"adresses": compte}
    if not compte["adresses"] and not compte["personnes"]:
        return [Constat(BLOC, OK, "Aucune adresse mail de la société n'est exposée",
                        "Les sources publiques consultées ne montrent ni adresse mail de la "
                        "société, ni nom de salarié.", cle="adresses_publiques")], brut
    morceaux = []
    if compte["adresses"]:
        morceaux.append(f"{compte['adresses']} adresses mail")
    if compte["personnes"]:
        morceaux.append(f"{compte['personnes']} noms de personnes")
    return [Constat(
        BLOC, INFO, "Visibles publiquement : " + " et ".join(morceaux),
        "Ces adresses et ces noms circulent sur internet : ils servent aux escrocs à viser "
        "vos salariés avec des mails piégés crédibles. Le diagnostic ne les liste pas.",
        "Préférer une adresse générique (contact@) sur le site, et former les équipes à "
        "reconnaître un mail piégé.", cle="adresses_publiques")], brut
