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
import os
import re
import shlex

from . import erreurs, fiches_outils, lanceur, manuel, outils, registre

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
    # 3. Ligne écrite dans la fiche en clair (fiches_outils.py), quand celle du
    #    catalogue est fausse ou absente.
    ligne_fiche = fiches_outils.fiche(cle).get("ligne")
    if ligne_fiche:
        return (ligne_fiche[0], [a.replace("{cible}", cible) for a in ligne_fiche[1:]], True)
    # 4. Ligne devinée depuis l'usage du catalogue.
    fiche = info(nom)
    if fiche:
        devinee = _depuis_usage(fiche.get("usage", ""), cible)
        if devinee:
            return (*devinee, False)
    return None


# Un jeton de la ligne d'usage qui ressemble à un exemple de cible (domaine, e-mail,
# URL, pseudo @, numéro +33…). On le remplace par la vraie cible.
_EXEMPLE_CIBLE = re.compile(
    r"^(?:'|\")?(?:"
    r"https?://\S+"                                   # une URL
    r"|\+?\d[\d ().-]{6,}"                             # un numéro de téléphone
    r"|@[A-Za-z0-9_.]+"                                # un pseudo @handle
    r"|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"  # une adresse e-mail
    r"|(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}"              # un nom de domaine
    r")(?:'|\")?$")
_PLACEHOLDERS = ("{cible}", "{email}", "{profil}", "{fichier}", "{numero}", "{domaine}",
                 "{pseudo}", "{url}", "{ip}", "{utilisateur}")


def _depuis_usage(usage, cible):
    """Devine « commande + arguments » depuis la première ligne d'usage, si elle est nette.

    Deux cas sûrs :
      1. un emplacement explicite ({cible}, {email}, {profil}…) ;
      2. un exemple de cible reconnaissable (domaine, e-mail, URL, @pseudo, numéro).
    Dans les deux cas on remplace l'emplacement / l'exemple par la vraie cible. Les
    usages interactifs ou sans cible devinable sont ignorés : mieux vaut ne rien
    proposer qu'une mauvaise commande.
    """
    if not usage:
        return None
    premier = usage.split(";")[0].split("(")[0].strip()
    a_placeholder = any(e in premier for e in _PLACEHOLDERS)
    if a_placeholder:
        premier = re.sub(r"\{[a-z]+\}", "\x00", premier)
    try:
        morceaux = shlex.split(premier)
    except ValueError:
        return None
    if len(morceaux) < 2:
        return None
    remplace = False
    sortie = []
    for jeton in morceaux:
        if "\x00" in jeton:
            sortie.append(jeton.replace("\x00", cible)); remplace = True
        elif not remplace and not a_placeholder and _EXEMPLE_CIBLE.match(jeton):
            sortie.append(cible); remplace = True
        else:
            sortie.append(jeton)
    if not remplace:
        return None
    return sortie[0], sortie[1:]


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


def fiche_claire(nom):
    """La fiche en clair (rôle, cible attendue, mode) d'un outil du registre."""
    return fiches_outils.fiche(nom, info(nom))


def preparer(nom, cible):
    """Tout ce qu'on vérifie AVANT de lancer, avec une explication en français.

    Renvoie {"cible": cible arrangée, "remarques": [...], "ligne": (commande, args,
    vérifiée)}. Lève Refus avec un texte pédagogique si l'outil ne peut pas partir :
    outil actif/payant/inconnu, outil qui ne se lance pas sur une cible (service,
    logiciel à fenêtres, Windows…), cible qui ne correspond pas, ligne inconnue.
    """
    verifier_lancable(nom, autorisation_ok=False)   # passif seulement
    vrai_nom = info(nom)["nom"]
    fiche = fiche_claire(nom)
    cible = (cible or "").strip()
    explication = fiches_outils.explication_mode(vrai_nom, fiche, cible)
    if explication:
        raise Refus(explication)
    try:
        cible, remarque = fiches_outils.adapter_cible(vrai_nom, cible, fiche)
    except fiches_outils.CibleInadaptee as erreur:
        raise Refus(str(erreur)) from None
    if not cible and fiche.get("cible") != "aucune":
        raise Refus("Indique une cible (domaine, pseudo, e-mail… selon l'outil).")
    ligne = ligne_lancement(nom, cible)
    if not ligne:
        role = fiche.get("role")
        raise Refus(f"Vigie ne sait pas encore lancer {vrai_nom} tout seul : sa "
                    "documentation ne donne pas de ligne de commande claire à appliquer "
                    "à une cible." + (f" À quoi ça sert : ça {role}." if role else "")
                    + " Il s'utilise à la main pour l'instant.")
    return {"cible": cible, "remarques": [remarque] if remarque else [], "ligne": ligne}


# Où les outils posent leurs fichiers (captures, archives, documents téléchargés),
# plutôt que dans le dossier de Vigie.
DOSSIER_TRAVAIL = "~/vigie-travail"


def lancer(nom, cible, delai=300):
    """Lance UN outil PASSIF sur la cible et renvoie le compte rendu.

    Le compte rendu contient toujours une explication en français (« explication »,
    une liste de phrases) : ce qui s'est passé, et pourquoi si ça n'a pas marché.
    Refuse (Refus) un outil inconnu, payant, actif/offensif, ou qui ne se lance pas
    sur cette cible : la raison est dite en français.
    """
    prepa = preparer(nom, cible)
    commande, arguments, verifiee = prepa["ligne"]
    vrai_nom = info(nom)["nom"]
    compte = _lancer_commande(commande, arguments, delai)
    compte["outil"] = vrai_nom
    compte["cible"] = prepa["cible"]
    compte["verifiee"] = verifiee
    compte["commande"] = " ".join([commande] + arguments)
    compte["traduction"] = _traduire(nom, compte.get("sortie", ""))
    compte["explication"] = prepa["remarques"] + expliquer(vrai_nom, compte)
    return compte


def expliquer(nom, compte):
    """Les phrases en français qui disent ce qui s'est passé pendant le lancement."""
    phrases = []
    if compte.get("absent"):
        phrases.append(f"{nom} n'est pas installé sur cet ordinateur (Vigie ne trouve pas "
                       f"la commande « {compte.get('commande_absente', '')} »).")
        raison = raison_installation(nom)
        if raison:
            phrases.append("Lors de la dernière installation, ça a raté. Voici pourquoi :")
            phrases += ["• " + texte for texte in
                        erreurs.expliquer_installation(raison)] or \
                ["• raison non reconnue (détail technique ci-dessous)."]
        phrases.append("Prochaine étape : relance l'installeur de Vigie (le fichier "
                       "« installer-… » à double-cliquer) : il ne réessaie que les outils "
                       "ratés.")
        return phrases
    if compte.get("depasse"):
        return [f"{nom} a dépassé le temps maximum ({compte.get('delai', '?')} s) et a été "
                "arrêté. La cible est peut-être très grosse ou lente, ou Internet est lent."]
    sortie = (compte.get("sortie") or "") + "\n" + (compte.get("erreurs") or "")
    if compte.get("code"):
        phrases.append(f"{nom} s'est arrêté en erreur.")
        connues = erreurs.expliquer(sortie)
        phrases += connues or ["Vigie ne reconnaît pas encore ce message d'erreur : il est "
                               "en anglais dans le détail technique ci-dessous. "
                               "Montre-le à Claude pour qu'il l'ajoute."]
        if not compte.get("verifiee"):
            phrases.append("Attention : la ligne de lancement de cet outil a été devinée par "
                           "Vigie dans sa documentation. Si l'outil dit qu'il ne comprend "
                           "pas, c'est elle qui est à corriger, pas ta cible.")
        return phrases
    if not (compte.get("sortie") or "").strip():
        phrases.append(f"{nom} a tourné jusqu'au bout mais n'a rien trouvé ni rien écrit. "
                       "Souvent, ça veut dire qu'il n'y a rien de public sur cette cible.")
        phrases += erreurs.expliquer(sortie)
        return phrases
    phrases.append(f"{nom} a bien tourné ({compte.get('secondes', 0)} s). Le résumé est "
                   "ci-dessous.")
    if not compte.get("verifiee"):
        phrases.append("La ligne de lancement a été devinée par Vigie dans la documentation "
                       "de l'outil : vérifie que le résultat a du sens.")
    return phrases


def raison_installation(nom):
    """La raison d'échec notée par la dernière installation pour cet outil, ou ""."""
    from . import presence
    return presence.echecs_installation().get((nom or "").lower(), "")


def _lancer_commande(commande, arguments, delai):
    import shutil
    import subprocess
    import time
    chemin = shutil.which(commande, path=outils.chemin_recherche())
    if not chemin:
        return {"lance": False, "absent": True, "commande_absente": commande,
                "raison": f"{commande} n'est pas installé", "secondes": 0, "sortie": ""}
    dossier = os.path.expanduser(DOSSIER_TRAVAIL)
    try:
        os.makedirs(dossier, exist_ok=True)
    except OSError:
        dossier = None
    depart = time.monotonic()
    try:
        fini = subprocess.run([chemin] + arguments, capture_output=True, text=True,
                              timeout=delai, errors="replace", cwd=dossier,
                              stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return {"lance": False, "depasse": True, "delai": delai,
                "raison": f"dépassement de {delai} s",
                "secondes": round(time.monotonic() - depart, 1), "sortie": ""}
    secondes = round(time.monotonic() - depart, 1)
    sortie = (fini.stdout or "") + ("\n" + fini.stderr if fini.returncode else "")
    return {"lance": True, "echoue": fini.returncode != 0 or not (fini.stdout or "").strip(),
            "raison": "", "secondes": secondes, "code": fini.returncode, "sortie": sortie,
            "erreurs": fini.stderr or ""}
