"""Bloc Exposition - anciennes pages du site gardées par les archives d'internet (outil : gau).

gau interroge les archives publiques (Wayback Machine, Common Crawl, AlienVault OTX,
URLScan) : aucune question n'est posée au site lui-même. Un fichier sensible mis en
ligne un jour (sauvegarde, export de base, fichier de réglages) peut y rester des
années après avoir été retiré du site.
"""
import re
import time
import urllib.parse
import urllib.request

from .. import outils, reseau
from ..modeles import IMPORTANT, INFO, OK, Constat, ControleImpossible

BLOC = "Exposition"
MAXIMUM_AFFICHE = 10
DUREE_CACHE = 600
_CACHE = {}

SENSIBLE = re.compile(
    r"(\.(sql|bak|backup|old|orig|swp|zip|tar|gz|tgz|rar|7z|env|log|conf|cfg|ini|db|sqlite|"
    r"key|pem|p12|pfx)$)|(/\.git/|/\.env|wp-config|phpinfo|/backup)", re.I)
DOCUMENT = re.compile(r"\.(pdf|docx?|xlsx?|pptx?|odt|ods|odp|csv|rtf)$", re.I)


def lire_sortie(texte, domaine):
    """Les adresses archivées du domaine et de ses sous-domaines, sans doublon."""
    adresses = set()
    for ligne in (texte or "").splitlines():
        url = ligne.strip()
        hote = (urllib.parse.urlparse(url).hostname or "").lower()
        if hote == domaine or hote.endswith("." + domaine):
            adresses.add(url)
    return sorted(adresses)


def _chemin(url):
    return urllib.parse.urlparse(url).path or "/"


# La Wayback Machine interrogée directement : 2e avis quand gau ne rend rien. Cas réel du
# 26/11/2026 : gau disait « aucune archive » pour un site qui publie des articles depuis
# des mois. Une liste vide de gau peut venir d'une source en panne ou trop lente ; Vigie
# ne dit plus « rien dans les archives » sans l'avoir vérifié lui-même.
WAYBACK = "https://web.archive.org/cdx/search/cdx"


def wayback(domaine):
    """Les adresses que la Wayback Machine garde pour le domaine, ou None si elle ne
    répond pas. Lecture publique : rien n'est envoyé au site de la société."""
    url = WAYBACK + "?" + urllib.parse.urlencode({
        "url": domaine, "matchType": "domain", "fl": "original", "collapse": "urlkey",
        "limit": "2000"})
    requete = urllib.request.Request(url, headers={"User-Agent": reseau.AGENT})
    for _ in range(2):  # la Wayback Machine est souvent lente : deux essais
        try:
            with urllib.request.urlopen(requete, timeout=60) as reponse:
                return lire_sortie(reponse.read().decode("utf-8", "replace"), domaine)
        except Exception:
            continue
    return None


def trouver_detail(domaine):
    """(adresses archivées, d'où elles viennent). Gardées 10 minutes (le module
    métadonnées s'en sert). Source : « gau », « wayback » (gau muet, Vigie a lu la
    Wayback Machine), « personne » (les deux d'accord : rien) ou « inconnu » (gau muet
    et Wayback injoignable : on ne peut pas conclure)."""
    instant, trouve = _CACHE.get(domaine, (0, None))
    if trouve is not None and time.time() - instant < DUREE_CACHE:
        return trouve
    sortie = outils.executer("gau", ["--subs", "--threads", "4", "--timeout", "30",
                                     "--providers", "wayback,commoncrawl,otx,urlscan",
                                     domaine], delai=300)
    liste, source = lire_sortie(sortie, domaine), "gau"
    if not liste:
        directe = wayback(domaine)
        if directe:
            liste, source = directe, "wayback"
        else:
            source = "personne" if directe is not None else "inconnu"
    trouve = (liste, source)
    _CACHE[domaine] = (time.time(), trouve)
    return trouve


def trouver(domaine):
    """Les adresses archivées (voir trouver_detail)."""
    return trouver_detail(domaine)[0]


def documents(adresses):
    return [u for u in adresses if DOCUMENT.search(_chemin(u))]


def analyser(cible):
    adresses, source = trouver_detail(cible.domaine)
    sensibles = [u for u in adresses if SENSIBLE.search(_chemin(u))]
    docs = documents(adresses)
    brut = {"archives": {"total": len(adresses), "sensibles": sensibles, "documents": docs,
                         "source": source}}
    if source == "inconnu":
        raise ControleImpossible("gau n'a rien rendu et la Wayback Machine ne répond pas : "
                                 "impossible de dire si des pages du site sont archivées")
    if not adresses:
        return [Constat(BLOC, OK, "Aucune ancienne page du site dans les archives",
                        "Les archives publiques d'internet ne gardent aucune page de votre "
                        "site (vérifié par gau et directement dans la Wayback Machine) : "
                        "rien d'ancien n'y traîne.", cle="archives")], brut
    constats = []
    if sensibles:
        liste = ", ".join(_chemin(u) for u in sensibles[:MAXIMUM_AFFICHE])
        constats.append(Constat(
            BLOC, IMPORTANT, f"{len(sensibles)} fichiers sensibles du site sont archivés publiquement",
            f"Fichiers concernés : {liste}. Sauvegardes, réglages ou exports peuvent contenir "
            "des mots de passe ou des données de clients, et rester consultables des années "
            "après leur retrait du site.",
            "Vérifier ce que contiennent ces fichiers, changer les mots de passe qui s'y "
            "trouveraient, et demander leur retrait aux archives.", cle="archives_sensibles"))
    if docs:
        constats.append(Constat(
            BLOC, INFO, f"{len(docs)} documents de la société restent consultables dans les archives",
            "Ils peuvent révéler des noms, des adresses ou l'organisation interne.",
            "Relire ces documents et demander le retrait de ceux qui ne doivent plus "
            "circuler.", cle="archives_documents"))
    if not constats:
        constats.append(Constat(BLOC, OK, f"{len(adresses)} pages archivées, rien de sensible",
                                "Les archives publiques gardent d'anciennes pages du site, mais "
                                "aucun fichier sensible." + (
                                    " (gau n'a rien rendu : liste lue directement dans la "
                                    "Wayback Machine.)" if source == "wayback" else ""),
                                cle="archives"))
    return constats, brut
