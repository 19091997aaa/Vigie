"""Bloc Exposition - noms de domaine qui imitent celui de la société (outil externe : dnstwist).

dnstwist fabrique les variantes typographiques du domaine (lettres interverties,
accents, extensions voisines) et regarde lesquelles sont enregistrées. Un domaine
imitateur enregistré sert souvent à l'hameçonnage. Lecture publique, aucun accord
technique requis.
"""
import json

from .. import outils, reseau
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


# Les fautes de frappe les plus courantes : quelques centaines de variantes au lieu de
# plusieurs milliers. Servent quand le DNS est trop lent pour la recherche complète.
FUZZERS_REDUITS = "addition,hyphenation,omission,plural,repetition,transposition,vowel-swap"


def arguments(domaine, resolveurs_publics=True, reduit=False):
    """dnstwist interroge des résolveurs publics, 32 questions à la fois : un nom de
    domaine un peu long donne plus de 10 000 variantes à vérifier."""
    args = ["--format", "json", "--registered", "--threads", "32"]
    if reduit:
        args += ["--fuzzers", FUZZERS_REDUITS]
    if resolveurs_publics:
        args += ["--nameservers", ",".join(reseau.SERVEURS_DNS)]
    return args + [domaine]


SANS_MODULE_DNS = "missing dnspython"
# Délais. Le contrôle entier a 15 minutes (modules/__init__.py) : les deux essais doivent
# tenir dedans, et le message doit dire la VRAIE durée. Cas réel du 26/11/2026 : 4 min
# + 9 min = coupé à 13 min, et le rapport disait « pas répondu en 540 secondes ».
DELAI_COMPLET = 240
DELAI_MACHINE = 540
DELAI_REDUIT = 300


def _essai(domaine, delai, **options):
    """Résultat de dnstwist, ou None s'il a dépassé son délai."""
    try:
        return outils.executer_detail("dnstwist", arguments(domaine, **options), delai=delai)
    except ControleImpossible:
        if not outils.disponible("dnstwist"):
            raise
        return None


def _minutes(secondes):
    return f"{secondes // 60} min" + (f" {secondes % 60} s" if secondes % 60 else "")


def lancer(domaine):
    """Lance dnstwist et renvoie (sortie JSON, note pour le rapport technique).

    Vraie cause du « 0 seconde, rien renvoyé » du 24/11/2026 : l'installeur avait posé
    dnstwist SANS son module DNS (dnspython). Dans ce cas, dnstwist refuse l'option
    --nameservers et s'arrête aussitôt (code 2, message en anglais sur la sortie
    d'erreur, rien sur la sortie normale). On le relance alors sur le DNS de la machine :
    plus lent, mais le contrôle se fait.

    Si la recherche complète dépasse son délai (le DNS répond, mais trop lentement pour
    des milliers de questions), on ne relance PAS la même recherche ailleurs : on la
    refait réduite aux fautes de frappe courantes, et le rapport le dit.

    Autre cas : avec --registered, une sortie vide veut dire qu'AUCUN nom n'a répondu,
    pas même le domaine de la société. Ce n'est pas « aucun imitateur » : c'est le DNS
    qui n'a pas répondu. On réessaie sur le DNS de la machine, puis on le dit.
    """
    resultat = _essai(domaine, DELAI_COMPLET)
    sans_module = resultat is not None and SANS_MODULE_DNS in (resultat.stderr or "").lower()
    if sans_module:
        note = "dnstwist sans module DNS : passé par le DNS de la machine"
        resultat = _essai(domaine, DELAI_MACHINE, resolveurs_publics=False)
        if resultat is None:
            raise ControleImpossible(
                f"dnstwist n'a pas fini en {_minutes(DELAI_MACHINE)} : il lui manque son module "
                "DNS (dnspython), il passe donc par le DNS de la machine, trop lent. Relancer "
                "l'installeur, qui ajoute ce module")
    elif resultat is None:
        note = ("recherche complète trop longue (plus de "
                f"{_minutes(DELAI_COMPLET)}) : refaite sur les fautes de frappe courantes")
        resultat = _essai(domaine, DELAI_REDUIT, reduit=True)
        if resultat is None:
            raise ControleImpossible(
                f"dnstwist n'a pas fini en {_minutes(DELAI_COMPLET + DELAI_REDUIT)} au total "
                f"(recherche complète {_minutes(DELAI_COMPLET)}, puis recherche réduite "
                f"{_minutes(DELAI_REDUIT)}) : les serveurs DNS répondent trop lentement à "
                "ses milliers de questions. À relancer sur une autre connexion")
    elif not (resultat.stdout or "").strip():
        note = ("aucune réponse des résolveurs publics : refaite sur les fautes de frappe "
                "courantes, par le DNS de la machine")
        resultat = _essai(domaine, DELAI_REDUIT, resolveurs_publics=False, reduit=True)
        if resultat is None:
            raise ControleImpossible(
                "dnstwist n'a eu de réponse ni des résolveurs publics, ni du DNS de la "
                f"machine en {_minutes(DELAI_COMPLET + DELAI_REDUIT)} : le pare-feu filtre "
                "sans doute ses questions DNS")
    else:
        note = ""
    if not (resultat.stdout or "").strip():
        if resultat.returncode:
            raise ControleImpossible("dnstwist s'est arrêté sans résultat — "
                                     + outils.pourquoi(resultat))
        raise ControleImpossible(
            "dnstwist n'a eu aucune réponse DNS, pas même pour le domaine de la société : "
            "le DNS de la machine ou le pare-feu bloque ses questions. À relancer quand "
            "un site s'ouvre normalement dans le navigateur.")
    return resultat.stdout, note


def analyser(cible):
    sortie, note = lancer(cible.domaine)
    imitateurs = lire_sortie(sortie)
    brut = {"imitateurs": imitateurs}
    if note:
        brut["note"] = note
    reduit = ("refaite sur les fautes de frappe courantes" in note)
    precision = (" Recherche limitée aux fautes de frappe les plus courantes : le DNS "
                 "était trop lent pour tester toutes les variantes." if reduit else "")
    if not imitateurs:
        return [Constat(BLOC, OK, "Aucun domaine imitateur enregistré",
                        "Aucune variante trompeuse de votre nom de domaine n'est enregistrée "
                        "aujourd'hui." + precision, cle="domaines_imitateurs")], brut
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
        "vos clients ou vos salariés." + precision,
        "Surveiller ces domaines, signaler les plus proches pour fermeture, et prévenir "
        "vos équipes de vérifier l'adresse exacte.", cle="domaines_imitateurs")], brut
