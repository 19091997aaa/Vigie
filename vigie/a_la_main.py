"""Brancher sur Vigie un outil installé à la main.

Beaucoup d'outils ne s'installent pas tout seuls (recettes.MANUELS, « pas de méthode
automatique sûre ») : Anass les pose à la main. Vigie retrouve un outil quand il trouve
SA commande (presence.binaires_possibles) dans /opt/vigie-outils/bin ou le PATH. Mais un
outil posé à la main est souvent ailleurs : un programme téléchargé dans ~/Téléchargements,
un dossier avec son propre lanceur (« ./shannon »), un script Python ou Java…

Ici, Anass montre où est le programme (ou son dossier). Vigie :
  1. écrit un petit lanceur au nom de la commande attendue, dans le dossier des outils ;
  2. vérifie que l'outil démarre (sauf une appli ou un service, qu'on n'ouvre pas d'ici) ;
  3. le note dans ~/vigie-installation.json : l'outil passe « installé » partout.
Rien n'est téléchargé ni installé : on relie seulement ce qui est déjà sur la machine.
"""
import os
import re
import stat

from . import fiches_outils, installeur, outils, presence, registre

MARQUE = "# Écrit par Vigie (outil installé à la main)."
# Les modes de fiches_outils pour lesquels on ne lance PAS l'outil pour le vérifier :
# une appli graphique s'ouvrirait, un service démarrerait.
SANS_ESSAI = {"appli", "service", "windows", "capture", "ressource"}
# Ce qu'un chemin ne doit pas contenir : il est recopié tel quel dans le lanceur.
_INTERDITS = re.compile(r'["$`\\\n\r]')
_INTERPRETES = {".py": "python3", ".sh": "bash", ".jar": "java -jar", ".rb": "ruby",
                ".pl": "perl", ".js": "node"}


class Refus(ValueError):
    """Le branchement est refusé ; le message dit pourquoi, en français."""


def dossier_commandes():
    """Où poser le lanceur : le dossier des outils de Vigie s'il existe, sinon ~/.local/bin.
    Les deux sont dans outils.DOSSIERS_OUTILS : Vigie y cherche toujours."""
    for dossier in ("/opt/vigie-outils/bin", os.path.expanduser("~/.local/bin")):
        if os.path.isdir(dossier) and os.access(dossier, os.W_OK):
            return dossier
    dossier = os.path.expanduser("~/.local/bin")
    os.makedirs(dossier, exist_ok=True)
    return dossier


def commande_de(nom):
    """Le nom de commande sous lequel Vigie cherchera l'outil."""
    possibles = presence.binaires_possibles(nom)
    if possibles:
        return possibles[0]
    return re.sub(r"[^a-z0-9]+", "-", nom.lower()).strip("-") or "outil"


def _executable_dans(dossier, nom):
    """Dans un dossier d'outil, le programme à lancer (même nom que l'outil ou sa commande)."""
    voulus = {n.lower() for n in presence.binaires_possibles(nom)}
    voulus |= {commande_de(nom).lower(), nom.lower(),
               re.sub(r"[^a-z0-9]", "", nom.lower())}
    for sous in ("", "bin"):
        ici = os.path.join(dossier, sous)
        if not os.path.isdir(ici):
            continue
        for fichier in sorted(os.listdir(ici)):
            chemin = os.path.join(ici, fichier)
            base, ext = os.path.splitext(fichier.lower())
            if os.path.isfile(chemin) and (fichier.lower() in voulus or base in voulus) \
                    and (os.access(chemin, os.X_OK) or ext in _INTERPRETES):
                return chemin
    return None


def _ligne_lancement(chemin):
    """La ligne qui lance le programme, selon son genre."""
    ext = os.path.splitext(chemin.lower())[1]
    if ext in _INTERPRETES:
        return f'exec {_INTERPRETES[ext]} "{chemin}" "$@"'
    if not os.access(chemin, os.X_OK):
        # Un programme téléchargé n'a souvent pas le droit d'être lancé : on le lui donne.
        os.chmod(chemin, os.stat(chemin).st_mode | stat.S_IXUSR)
    return f'exec "{chemin}" "$@"'


def brancher(nom, chemin, rapport=presence.RAPPORT):
    """Relie l'outil « nom » au programme (ou dossier) « chemin ». Renvoie un message.
    Lève Refus avec la raison en français si ce n'est pas possible."""
    fiche = next((o for o in registre.charger() if o["nom"].lower() == (nom or "").lower()),
                 None)
    if not fiche:
        raise Refus("Choisis un outil dans la liste.")
    nom = fiche["nom"]
    chemin = os.path.abspath(os.path.expanduser((chemin or "").strip().strip("'\"")))
    if not (chemin or "").strip() or chemin == os.path.abspath(""):
        raise Refus("Indique où est le programme (ou son dossier).")
    if _INTERDITS.search(chemin):
        raise Refus("Ce chemin contient un caractère spécial (\" $ ` \\) : renomme le "
                    "dossier ou le fichier, puis réessaie.")
    if not os.path.exists(chemin):
        raise Refus(f"Rien à cet endroit : {chemin}. Vérifie le chemin (astuce : clic droit "
                    "sur le fichier > Copier, puis colle ici avec Ctrl+V).")

    if os.path.isdir(chemin):
        programme = _executable_dans(chemin, nom)
        if not programme:
            raise Refus(f"Dans ce dossier, je ne trouve pas le programme de {nom} (un "
                        f"fichier nommé « {commande_de(nom)} » ou « {nom} »). Montre "
                        "directement le fichier du programme.")
        lignes = [f'cd "{os.path.dirname(programme)}" || exit 1',
                  _ligne_lancement(programme)]
    else:
        programme = chemin
        lignes = [_ligne_lancement(programme)]

    commande = commande_de(nom)
    lanceur = os.path.join(dossier_commandes(), commande)
    if os.path.exists(lanceur):
        with open(lanceur, encoding="utf-8", errors="replace") as lu:
            ancien = lu.read(400)
        # On ne remplace qu'un lanceur écrit par Vigie, jamais un vrai programme.
        if "Écrit par Vigie" not in ancien and "Écrit par l'installeur de Vigie" not in ancien:
            raise Refus(f"Un programme « {commande} » existe déjà dans {os.path.dirname(lanceur)} : "
                        "Vigie le voit déjà, il n'y a rien à brancher.")
    with open(lanceur, "w", encoding="utf-8") as fichier:
        fichier.write("#!/bin/sh\n" + MARQUE + "\n" + "\n".join(lignes) + "\n")
    os.chmod(lanceur, 0o755)

    mode = fiches_outils.fiche(nom, fiche).get("mode")
    if mode in SANS_ESSAI:
        demarre, verifie = True, False
    else:
        demarre, verifie = installeur.repond(lanceur), True
    noter(nom, commande, demarre, chemin, rapport)
    if not demarre:
        return (f"{nom} est branché sur Vigie (commande « {commande} »), mais il ne démarre "
                "pas : il lui manque sans doute quelque chose (voir sa documentation). "
                "Réessaie une fois réparé.")
    if not verifie:
        return (f"{nom} est branché sur Vigie (commande « {commande} »). C'est une application "
                "ou un service : Vigie ne l'a pas ouvert pour vérifier.")
    return f"{nom} est branché sur Vigie et démarre bien (commande « {commande} »)."


def noter(nom, commande, demarre, chemin, rapport=presence.RAPPORT):
    """Met l'outil dans le compte rendu d'installation, comme s'il avait été installé
    par Vigie : il est alors « installé » partout (badge, relance de l'installeur…)."""
    from . import cli
    rapport = os.path.expanduser(rapport)
    contenu = cli.lire_bilan(rapport) if os.path.exists(rapport) else {}
    details = [d for d in contenu.get("details", [])
               if isinstance(d, dict) and d.get("nom", "").lower() != nom.lower()]
    details.append({"nom": nom, "installe": True, "repond": bool(demarre),
                    "binaire": commande, "methode": "installé à la main",
                    "raison": "" if demarre else "installé mais ne démarre pas",
                    "chemin": chemin})
    contenu["details"] = details
    contenu["resume"] = installeur.resume(details)
    cli.ecrire_bilan(rapport, contenu)


def a_brancher():
    """Les outils du catalogue (non payants) que Vigie ne trouve pas encore ici."""
    etats = presence.etat()
    return sorted((o["nom"] for o in registre.charger()
                   if not o["payant"] and not etats.get(o["nom"])), key=str.lower)


def deja_la(nom):
    """Si l'outil est déjà sur la machine (posé à la main), sa commande ; sinon ""."""
    for binaire in presence.binaires_possibles(nom, presence.rapport_installation()):
        if outils.trouver(binaire):
            return binaire
    return ""
