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


def arguments(domaine, resolveurs_publics=True):
    """dnstwist interroge des résolveurs publics, 32 questions à la fois : un nom de
    domaine un peu long donne plus de 10 000 variantes à vérifier."""
    args = ["--format", "json", "--registered", "--threads", "32"]
    if resolveurs_publics:
        args += ["--nameservers", ",".join(reseau.SERVEURS_DNS)]
    return args + [domaine]


SANS_MODULE_DNS = "missing dnspython"


def lancer(domaine):
    """Lance dnstwist et renvoie (sortie JSON, note pour le rapport technique).

    Vraie cause du « 0 seconde, rien renvoyé » du 24/11/2026 : l'installeur avait posé
    dnstwist SANS son module DNS (dnspython). Dans ce cas, dnstwist refuse l'option
    --nameservers et s'arrête aussitôt (code 2, message en anglais sur la sortie
    d'erreur, rien sur la sortie normale). On le relance alors sur le DNS de la machine :
    plus lent, mais le contrôle se fait.

    Autre cas : avec --registered, une sortie vide veut dire qu'AUCUN nom n'a répondu,
    pas même le domaine de la société. Ce n'est pas « aucun imitateur » : c'est le DNS
    qui n'a pas répondu. On réessaie sur le DNS de la machine, puis on le dit.
    """
    note = ""
    # Délais : 4 min avec les résolveurs publics (13 s d'habitude), puis 9 min par le
    # DNS de la machine. Total sous les 15 min du contrôle (modules/__init__.py).
    try:
        resultat = outils.executer_detail("dnstwist", arguments(domaine), delai=240)
    except ControleImpossible:
        if not outils.disponible("dnstwist"):
            raise
        resultat = None  # délai dépassé : les résolveurs publics ne répondent pas
    sans_module = resultat is not None and SANS_MODULE_DNS in (resultat.stderr or "").lower()
    if resultat is None or sans_module or not (resultat.stdout or "").strip():
        note = ("dnstwist sans module DNS : passé par le DNS de la machine"
                if sans_module else
                "aucune réponse des résolveurs publics : passé par le DNS de la machine")
        resultat = outils.executer_detail("dnstwist", arguments(domaine, False), delai=540)
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
