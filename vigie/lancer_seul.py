"""Lancer n'importe quel outil du catalogue, UN PAR UN, à la demande.

C'est le « mode lancer par outil » : au lieu d'enchaîner tout un bloc, on choisit un
seul outil et on le lance sur une cible. Vigie :
  1. retrouve l'outil dans le registre (registre.py) ;
  2. refuse tout de suite un outil PAYANT, ou un outil ACTIF/offensif sans autorisation
     signée (les règles d'or : un scan actif n'est jamais lancé sans accord) ;
  3. construit sa ligne de lancement (déclaration vérifiée si on en a une, sinon la
     ligne d'usage du catalogue, à confirmer au premier essai) ;
  4. lance et renvoie la sortie, traduite en français si un traducteur existe.

Rien n'est lancé via un shell : les arguments passent en liste.
"""
import re
import shlex

from . import lanceur, manuel, outils, registre

# Index du registre par nom en minuscules, construit une fois.
_PARNOM = None


def _index():
    global _PARNOM
    if _PARNOM is None:
        _PARNOM = {o["nom"].lower(): o for o in registre.charger()}
    return _PARNOM


def info(nom):
    """La fiche registre d'un outil (par son nom, insensible à la casse), ou None."""
    return _index().get((nom or "").strip().lower())


def ligne_lancement(nom, cible):
    """(commande, [arguments], vérifiée) pour lancer l'outil sur la cible.

    - vérifiée = True  : déclaration éprouvée (lanceur.LANCEMENTS ou manuel.OUTILS).
    - vérifiée = False : ligne devinée depuis l'usage du catalogue, à confirmer.
    Renvoie None si on ne sait pas construire de ligne (outil interactif / sans cible).
    """
    cle = (nom or "").strip()
    # 1. Déclaration éprouvée côté lancement en série.
    for nom_decl, decl in lanceur.LANCEMENTS.items():
        if nom_decl.lower() == cle.lower():
            return (decl["commande"],
                    [a.replace("{cible}", cible) for a in decl["arguments"]], True)
    # 2. Déclaration côté outils manuels (actifs).
    for nom_decl, decl in manuel.OUTILS.items():
        if nom_decl.lower() == cle.lower():
            return (decl["outil"],
                    [a.replace("{cible}", cible) for a in decl["arguments"]], True)
    # 3. Ligne devinée depuis l'usage du catalogue.
    fiche = info(nom)
    if fiche:
        devinee = _depuis_usage(fiche.get("usage", ""), cible)
        if devinee:
            return (*devinee, False)
    return None


def _depuis_usage(usage, cible):
    """Devine « commande + arguments » depuis la première ligne d'usage, si elle est nette.

    On ne garde que les usages de forme « commande ... {cible} ... » (ou {email}/{profil}
    /{fichier}/{numero}). Les usages interactifs ou sans emplacement de cible sont ignorés :
    mieux vaut ne rien proposer que proposer une mauvaise commande.
    """
    if not usage:
        return None
    premier = usage.split(";")[0].split("(")[0].strip()
    emplacements = ("{cible}", "{email}", "{profil}", "{fichier}", "{numero}", "{domaine}")
    if not any(e in premier for e in emplacements):
        return None
    premier = re.sub(r"\{(email|profil|fichier|numero|domaine)\}", "{cible}", premier)
    try:
        morceaux = shlex.split(premier.replace("{cible}", "\x00"))
    except ValueError:
        return None
    morceaux = [m.replace("\x00", cible) for m in morceaux]
    if len(morceaux) < 2:
        return None
    return morceaux[0], morceaux[1:]


class Refus(outils.ControleImpossible):
    """Le lancement est refusé, avec la raison en clair."""


def verifier_lancable(nom, autorisation_ok=False):
    """Lève Refus si l'outil ne peut pas être lancé seul en l'état. Sinon ne renvoie rien."""
    fiche = info(nom)
    if not fiche:
        raise Refus(f"Outil inconnu du catalogue : {nom}")
    if fiche["payant"]:
        raise Refus(f"{fiche['nom']} est payant : non installé, non lancé par Vigie.")
    if fiche["autorisation_requise"] and not autorisation_ok:
        quoi = "offensif" if fiche["attaque"] else "actif"
        raise Refus(f"{fiche['nom']} est un outil {quoi} : il faut une autorisation signée "
                    "(onglet « Outils manuels »). Il ne part jamais seul sans accord.")


def _traduire(nom, sortie):
    """Un résumé en français si un traducteur existe pour cet outil, sinon None.

    Les traducteurs fins (ports.py, audit_actif.py) lisent un FICHIER ; ici on a la
    sortie en mémoire. On se contente d'un résumé court et lisible pour les outils
    sans module dédié : le détail reste dans la sortie brute, consultable.
    """
    lignes = [l for l in (sortie or "").splitlines() if l.strip()]
    if not lignes:
        return "L'outil n'a rien renvoyé sur cette cible."
    apercu = lignes[: 12]
    reste = len(lignes) - len(apercu)
    texte = "\n".join(apercu)
    if reste > 0:
        texte += f"\n… (+{reste} autres lignes dans la sortie brute)"
    return texte


def lancer(nom, cible, delai=300):
    """Lance UN outil PASSIF sur la cible et renvoie le compte rendu (+ un résumé français).

    Refuse (Refus) un outil inconnu, payant, ou actif/offensif : ceux-là passent par
    l'onglet « Outils manuels » avec autorisation signée.
    """
    verifier_lancable(nom, autorisation_ok=False)   # passif seulement
    cible = (cible or "").strip()
    if not cible:
        raise Refus("Indique une cible (domaine, pseudo, e-mail… selon l'outil).")
    ligne = ligne_lancement(nom, cible)
    if not ligne:
        raise Refus(f"{info(nom)['nom']} : lancement à la main pour l'instant "
                    "(outil interactif ou cible non devinée). Voir l'usage du catalogue.")
    commande, arguments, verifiee = ligne
    compte = _lancer_commande(commande, arguments, delai)
    compte["outil"] = info(nom)["nom"]
    compte["verifiee"] = verifiee
    compte["traduction"] = _traduire(nom, compte.get("sortie", ""))
    return compte


def _lancer_commande(commande, arguments, delai):
    import shutil
    import subprocess
    import time
    chemin = shutil.which(commande, path=outils.chemin_recherche())
    if not chemin:
        return {"lance": False, "raison": f"{commande} n'est pas installé", "secondes": 0,
                "sortie": ""}
    depart = time.monotonic()
    try:
        fini = subprocess.run([chemin] + arguments, capture_output=True, text=True,
                              timeout=delai, errors="replace")
    except subprocess.TimeoutExpired:
        return {"lance": False, "raison": f"dépassement de {delai} s",
                "secondes": round(time.monotonic() - depart, 1), "sortie": ""}
    secondes = round(time.monotonic() - depart, 1)
    sortie = (fini.stdout or "") + ("\n" + fini.stderr if fini.returncode else "")
    return {"lance": True, "echoue": fini.returncode != 0 or not (fini.stdout or "").strip(),
            "raison": "", "secondes": secondes, "code": fini.returncode, "sortie": sortie}
