"""Bloc Exposition - liens cassés du site (outil externe : LinkChecker).

LinkChecker parcourt le site comme un moteur de recherche (2 niveaux de pages,
4 pages à la fois) et vérifie chaque lien. Bornes (cas réel du 24/11/2026 : arrêté au
bout de 10 minutes sans RIEN rendre) : 4 minutes et 400 liens au plus, 10 secondes par
lien, 5 questions par seconde. À la borne, LinkChecker s'arrête proprement et rend ce
qu'il a vu. Deux cas :
  - un lien interne cassé : une page qui n'existe plus. Ce n'est pas une faille,
    mais un visiteur perdu (ne compte pas dans la note) ;
  - un lien vers un domaine qui n'existe plus : un escroc peut racheter ce domaine
    et récupérer vos visiteurs (« détournement de lien cassé »). Ça, c'est un risque.

Vu sur pavillon-noir.tech le 21/11/2026 : le bouton « Découvrir les offres » d'un
article menait à une page supprimée.
"""
import csv
import io
import os
import re
import tempfile
import urllib.parse

from .. import outils
from ..modeles import IMPORTANT, INFO, OK, Constat

BLOC = "Exposition"
MAXIMUM_AFFICHE = 5
DOMAINE_MORT = ("name or service not known", "nodename nor servname", "getaddrinfo failed",
                "no address associated", "name resolution")


def _hote(url):
    return (urllib.parse.urlparse(url).hostname or "").lower()


def lire_sortie(texte, domaine):
    """Les liens en erreur : (adresse, page qui le contient, erreur, interne ?)."""
    lignes = [ligne for ligne in (texte or "").splitlines() if ligne and not ligne.startswith("#")]
    casses = []
    for fiche in csv.DictReader(io.StringIO("\n".join(lignes)), delimiter=";"):
        if fiche.get("valid") == "True" or not fiche.get("urlname"):
            continue
        url = urllib.parse.urljoin(fiche.get("parentname") or "", fiche["urlname"])
        hote = _hote(url)
        casses.append({"url": url, "page": fiche.get("parentname", ""),
                       "erreur": fiche.get("result", ""),
                       "interne": hote == domaine or hote.endswith("." + domaine)})
    return casses


def _chemin(url):
    morceaux = urllib.parse.urlparse(url)
    return (morceaux.hostname or "") + (morceaux.path or "/")


# Fausses alertes propres à WordPress (cas réel du 26/11/2026 sur pavillon-noir.tech) :
# ces adresses sont dans le code de la page, pas des liens qu'un visiteur clique.
#   - /wp-json/... : l'accès technique de WordPress pour les programmes ;
#   - /feed/ : les flux RSS, souvent coupés exprès par une extension de sécurité ;
#   - xmlrpc.php, oembed, /comments/feed : accès techniques ;
#   - image-300x158.jpg : les tailles de miniature proposées au navigateur (srcset),
#     qui n'existent pas toujours ; le navigateur prend alors une autre taille.
TECHNIQUES_WORDPRESS = re.compile(
    r"/wp-json(/|$)|/feed/?$|/xmlrpc\.php|/oembed|[?&](?:rest_route|feed)=|"
    r"/wp-content/uploads/.+-\d{2,4}x\d{2,4}\.(?:jpe?g|png|gif|webp|avif)$", re.I)
# Le site a refusé le robot (protection anti-robots), il n'a pas dit « page absente ».
BLOQUE_ROBOT = re.compile(r"\b(401|403|405|406|429|999)\b")


def vraie_erreur(casse):
    """Un lien interne vraiment cassé ? Non pour les adresses techniques de WordPress et
    pour les refus anti-robots : ce ne sont pas des pages perdues pour un visiteur."""
    morceaux = urllib.parse.urlparse(casse["url"])
    if TECHNIQUES_WORDPRESS.search(morceaux.path + ("?" + morceaux.query if morceaux.query else "")):
        return False
    return not BLOQUE_ROBOT.search(casse.get("erreur") or "")


# Réglages lus par LinkChecker (section [checking] de son fichier de configuration).
REGLAGES = {"maxrunseconds": 240, "maxnumurls": 400, "timeout": 10, "aborttimeout": 30,
            "maxrequestspersecond": 5, "recursionlevel": 2, "threads": 4}


def configuration():
    return "[checking]\n" + "".join(f"{cle}={valeur}\n" for cle, valeur in REGLAGES.items())


def analyser(cible):
    with tempfile.TemporaryDirectory() as dossier:
        reglages = os.path.join(dossier, "linkcheckerrc")
        with open(reglages, "w", encoding="utf-8") as fichier:
            fichier.write(configuration())
        # partiel : si malgré tout il déborde, on garde les liens déjà vérifiés.
        texte = outils.executer("linkchecker", [
            "-f", reglages, "--no-status", "--no-warnings", "--recursion-level=2",
            "--threads=4", "--timeout=10", "--check-extern", "-o", "csv",
            "https://" + cible.domaine + "/"], delai=360, dossier=dossier, partiel=True)
    casses = lire_sortie(texte, cible.domaine)
    brut = {"liens_casses": casses, "bornes": dict(REGLAGES)}
    internes = [c for c in casses if c["interne"] and vraie_erreur(c)]
    brut["ecartes"] = len([c for c in casses if c["interne"]]) - len(internes)
    morts = [c for c in casses if not c["interne"]
             and any(m in c["erreur"].lower() for m in DOMAINE_MORT)]
    constats = []
    if morts:
        liste = ", ".join(_hote(c["url"]) for c in morts[:MAXIMUM_AFFICHE])
        constats.append(Constat(
            BLOC, IMPORTANT, f"{len(morts)} liens du site mènent à un domaine qui n'existe plus",
            f"Domaines concernés : {liste}. N'importe qui peut racheter ces domaines et y "
            "mettre une fausse page : vos visiteurs y arriveraient en vous faisant confiance.",
            "Retirer ou corriger ces liens.", cle="liens_domaines_morts"))
    if internes:
        liste = " ; ".join(f"{_chemin(c['url'])} (depuis {_chemin(c['page'])})"
                           for c in internes[:MAXIMUM_AFFICHE])
        constats.append(Constat(
            BLOC, INFO, (f"{len(internes)} liens cassés sur votre site" if len(internes) > 1
                         else "1 lien cassé sur votre site"),
            f"Liens vers une page qui n'existe plus : {liste}. Un visiteur qui clique "
            "tombe sur une erreur.", "Corriger ou retirer ces liens.",
            cle="liens_casses", hors_note=True))
    if not constats:
        constats.append(Constat(BLOC, OK, "Aucun lien cassé sur le site",
                                "Tous les liens vérifiés mènent quelque part.", cle="liens"))
    return constats, brut
