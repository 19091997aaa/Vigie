"""Bloc Exposition - comptes publics du dirigeant, à partir de ses pseudos.

Quatre outils (Social Analyzer ajouté le 24/11/2026). Les trois premiers, comparés point par point le 21/11/2026 sur le pseudo « vigie » :
Sherlock 80 comptes, Maigret 68, user-scanner 110 ; seulement 40 à 46 en commun deux
à deux. Chacun rate un bon tiers de ce que voient les autres : Vigie les lance tous
(ceux qui sont installés) et compte, pour chaque site, combien d'outils l'ont vu.
Un compte vu par au moins 2 outils est « probable », les autres sont « à vérifier ».

Donnée personnelle : ce module ne tourne que si le dirigeant a donné ses pseudos
ET son accord écrit. Jamais sur un tiers. Les bases de FUITES que certains outils
interrogent (HudsonRock...) sont écartées : interdites hors offre payante.
"""
import concurrent.futures
import json
import os
import re
import tempfile
import urllib.parse

from .. import outils
from ..modeles import INFO, OK, Constat, ControleImpossible

BLOC = "Exposition"
PSEUDO = re.compile(r"[A-Za-z0-9._-]{2,40}")
LIGNE = re.compile(r"^\[\+\]\s*(.+?):\s*(https?://\S+)\s*$")
MAXIMUM_AFFICHE = 25
SOURCES_FUITES = ("hudsonrock", "haveibeenpwned", "dehashed", "leakcheck", "intelx", "breach")
# Bornes par outil (cas réel du 24/11/2026 : 13 minutes pour les quatre, l'un après
# l'autre). Désormais ils tournent EN MÊME TEMPS, 5 minutes au plus chacun, et chacun
# interroge au plus ~400 sites avec 10 secondes par site. Au-delà, on garde ce que
# l'outil a déjà trouvé (Sherlock, Social Analyzer) ou on passe sans lui.
DELAI_OUTIL = 300
ATTENTE_SITE = "10"
MAIGRET_SITES = "300"


def _site(nom):
    """« Steam Community (User) », « freelancer.com », « Instagram.creator » -> même clé."""
    nom = nom.lower().split(" (")[0].split(".")[0]
    return re.sub(r"[^a-z0-9]", "", nom)


def _fuite(nom):
    return any(f in nom.lower().replace(" ", "") for f in SOURCES_FUITES)


def lire_sortie(texte):
    """Sherlock : les comptes trouvés (hors bases de fuites)."""
    comptes = []
    for ligne in (texte or "").splitlines():
        trouve = LIGNE.match(ligne.strip())
        if trouve and not _fuite(trouve.group(1)):
            comptes.append({"site": trouve.group(1), "adresse": trouve.group(2)})
    return comptes


def lire_maigret(data):
    return [{"site": nom, "adresse": (fiche or {}).get("url_user", "")}
            for nom, fiche in (data or {}).items() if not _fuite(nom)]


def lire_user_scanner(data):
    return [{"site": x.get("site_name", "").split(".")[0], "adresse": x.get("url", "")}
            for x in data or [] if x.get("status") == "Found" and not _fuite(x.get("site_name", ""))]


def _sherlock(pseudo):
    with tempfile.TemporaryDirectory() as dossier:
        return lire_sortie(outils.executer(
            "sherlock", [pseudo, "--print-found", "--no-color", "--timeout", ATTENTE_SITE],
            delai=DELAI_OUTIL, dossier=dossier, partiel=True))


def _maigret(pseudo):
    with tempfile.TemporaryDirectory() as dossier:
        outils.executer("maigret", [pseudo, "--top-sites", MAIGRET_SITES, "--timeout",
                                    ATTENTE_SITE, "--no-color", "--no-progressbar",
                                    "--no-recursion", "-J", "simple", "--folderoutput", dossier],
                        delai=DELAI_OUTIL, dossier=dossier)
        chemin = os.path.join(dossier, f"report_{pseudo}_simple.json")
        try:
            with open(chemin, encoding="utf-8") as fichier:
                return lire_maigret(json.load(fichier))
        except (OSError, json.JSONDecodeError):
            return []


def _user_scanner(pseudo):
    with tempfile.TemporaryDirectory() as dossier:
        chemin = os.path.join(dossier, "resultat.json")
        outils.executer("user-scanner", ["-u", pseudo, "-f", "json", "-o", chemin, "-t",
                                         ATTENTE_SITE, "--no-nsfw"], delai=DELAI_OUTIL,
                        dossier=dossier)
        try:
            with open(chemin, encoding="utf-8") as fichier:
                return lire_user_scanner(json.load(fichier))
        except (OSError, json.JSONDecodeError):
            return []


def lire_social_analyzer(texte):
    """Social Analyzer (sortie JSON) : les profils jugés « bons » (hors bases de fuites)."""
    debut = (texte or "").find("{")
    if debut < 0:
        return []
    try:
        data = json.loads(texte[debut:texte.rfind("}") + 1])
    except json.JSONDecodeError:
        return []
    comptes = []
    for profil in data.get("detected") or []:
        lien = profil.get("link") or ""
        hote = urllib.parse.urlparse(lien).hostname or ""
        hote = hote.removeprefix("www.").removeprefix("m.")
        if hote and not _fuite(hote):
            comptes.append({"site": hote, "adresse": lien})
    return comptes


def _social_analyzer(pseudo):
    with tempfile.TemporaryDirectory() as dossier:
        return lire_social_analyzer(outils.executer(
            "social-analyzer", ["--username", pseudo, "--mode", "fast", "--output", "json",
                                "--filter", "good", "--method", "find", "--top", "100"],
            delai=DELAI_OUTIL, dossier=dossier, partiel=True))


OUTILS = (("Sherlock", "sherlock", _sherlock), ("Maigret", "maigret", _maigret),
          ("user-scanner", "user-scanner", _user_scanner),
          ("Social Analyzer", "social-analyzer", _social_analyzer))


def lancer_ensemble(pseudo, choisis):
    """Lance les outils choisis [(nom, fonction)] EN MÊME TEMPS sur un pseudo.

    Renvoie ({outil: [comptes]}, {outil: raison}) : un outil qui échoue ou dépasse son
    délai n'empêche pas les autres de rendre leurs résultats."""
    par_outil, ecartes = {}, {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(choisis))) as equipe:
        taches = {equipe.submit(fonction, pseudo): nom for nom, fonction in choisis}
        for tache in concurrent.futures.as_completed(taches):
            nom = taches[tache]
            try:
                par_outil[nom] = tache.result()
            except ControleImpossible as empechement:
                ecartes[nom] = str(empechement)
    # Ordre stable pour le rapport : celui de OUTILS.
    ordre = [nom for nom, _ in choisis]
    return {n: par_outil[n] for n in ordre if n in par_outil}, ecartes


def recouper(par_outil):
    """{outil: [comptes]} -> {clé de site: {"site", "adresse", "vu_par": [outils]}}."""
    sites = {}
    for outil, comptes in par_outil.items():
        for compte in comptes:
            cle = _site(compte["site"])
            if not cle:
                continue
            fiche = sites.setdefault(cle, {"site": compte["site"], "adresse": compte["adresse"],
                                           "vu_par": []})
            if outil not in fiche["vu_par"]:
                fiche["vu_par"].append(outil)
    return sites


def analyser(cible):
    if not cible.pseudos:
        raise ControleImpossible("aucun pseudo fourni par le dirigeant")
    if not cible.accord_dirigeant:
        raise ControleImpossible(
            "accord écrit du dirigeant requis pour chercher ses comptes (--accord-dirigeant)")
    constats, brut = [], {}
    for pseudo in cible.pseudos:
        if not PSEUDO.fullmatch(pseudo):
            raise ControleImpossible(f"pseudo invalide : {pseudo}")
        choisis = [(nom, fonction) for nom, commande, fonction in OUTILS
                   if outils.disponible(commande)]
        if not choisis:
            raise ControleImpossible("aucun outil de recherche de pseudo installé (Sherlock...)")
        par_outil, _ = lancer_ensemble(pseudo, choisis)
        if not par_outil:
            raise ControleImpossible("aucun outil de recherche de pseudo n'a répondu à temps")
        sites = recouper(par_outil)
        brut[pseudo] = {"par_outil": {n: len(c) for n, c in par_outil.items()},
                        "sites": sorted(sites.values(), key=lambda s: -len(s["vu_par"]))}
        if not sites:
            constats.append(Constat(BLOC, OK, f"Aucun compte public trouvé au pseudo « {pseudo} »",
                                    "Aucun des sites contrôlés n'affiche de compte à ce nom."))
            continue
        exiges = 2 if len(par_outil) > 1 else 1
        probables = [s["site"] for s in sites.values() if len(s["vu_par"]) >= exiges]
        a_verifier = len(sites) - len(probables)
        noms = ", ".join(probables[:MAXIMUM_AFFICHE]) or "aucun"
        if len(probables) > MAXIMUM_AFFICHE:
            noms += f" et {len(probables) - MAXIMUM_AFFICHE} autres"
        outils_utilises = ", ".join(f"{n} ({len(c)})" for n, c in par_outil.items())
        constats.append(Constat(
            BLOC, INFO, f"{len(probables)} comptes publics probables au pseudo « {pseudo} »",
            f"Vus par au moins {exiges} outil{'s' if exiges > 1 else ''} : {noms}. "
            f"{a_verifier} autres comptes vus par un seul outil restent à vérifier. "
            f"Outils : {outils_utilises}. Chaque compte oublié est une porte : mot de passe "
            "réutilisé, informations utiles à un escroc pour se faire passer pour vous. "
            "Un pseudo courant donne beaucoup d'homonymes : à confirmer compte par compte.",
            "Fermer les comptes inutilisés. Mot de passe unique et double authentification "
            "sur ceux que vous gardez."))
    return constats, brut
