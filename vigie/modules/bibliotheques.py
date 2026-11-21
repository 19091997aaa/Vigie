"""Bloc Exposition - bibliothèques JavaScript trouées sur le site (outil externe : Retire.js).

Vigie télécharge les scripts de la page d'accueil, comme le ferait un navigateur, et
Retire.js les compare à sa liste de versions trouées (jQuery, Bootstrap...). Un
WordPress pas à jour traîne souvent un vieux jQuery. Les scripts d'autres sites
(publicité, statistiques) ne sont pas téléchargés.

Essai du 21/11/2026 sur pavillon-noir.tech : un seul script (celui du thème), rien
de connu.
"""
import json
import os
import re
import tempfile
import urllib.parse
import urllib.request

from .. import outils, reseau
from ..modeles import IMPORTANT, INFO, OK, Constat, ControleImpossible

BLOC = "Exposition"
SCRIPT = re.compile(r"<script[^>]+src=[\"']([^\"']+)", re.I)
MAXIMUM_SCRIPTS = 30


def _ouvrir(url, limite=3_000_000):
    requete = urllib.request.Request(url, headers={"User-Agent": reseau.AGENT})
    with urllib.request.urlopen(requete, timeout=20) as reponse:
        return reponse.read(limite)


def scripts(html, base, domaine):
    adresses = []
    for src in SCRIPT.findall(html or ""):
        url = urllib.parse.urljoin(base, src)
        morceaux = urllib.parse.urlparse(url)
        hote = (morceaux.hostname or "").lower()
        if morceaux.scheme in ("http", "https") and (hote == domaine or hote.endswith("." + domaine)) \
                and url not in adresses:
            adresses.append(url)
    return adresses[:MAXIMUM_SCRIPTS]


def lire_sortie(data):
    trouvees = []
    for fichier in (data or {}).get("data") or []:
        for resultat in fichier.get("results") or []:
            failles = resultat.get("vulnerabilities") or []
            if failles:
                trouvees.append({"bibliotheque": resultat.get("component", ""),
                                 "version": resultat.get("version", ""),
                                 "failles": len(failles),
                                 "graves": sum(1 for f in failles
                                               if f.get("severity") in ("high", "critical"))})
    return trouvees


def analyser(cible):
    base = "https://" + cible.domaine + "/"
    try:
        page = _ouvrir(base).decode("utf-8", "replace")
    except Exception:
        raise ControleImpossible("la page d'accueil n'a pas pu être lue")
    adresses = scripts(page, base, cible.domaine)
    with tempfile.TemporaryDirectory() as dossier:
        for numero, url in enumerate(adresses):
            try:
                contenu = _ouvrir(url)
            except Exception:
                continue
            nom = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(urllib.parse.urlparse(url).path))
            with open(os.path.join(dossier, f"{numero:02d}_{nom or 'script.js'}"), "wb") as f:
                f.write(contenu)
        resultat = os.path.join(dossier, "retire.json")
        outils.executer("retire", ["--path", dossier, "--outputformat", "json",
                                   "--outputpath", resultat], delai=180)
        try:
            with open(resultat, encoding="utf-8") as lu:
                trouvees = lire_sortie(json.load(lu))
        except (OSError, json.JSONDecodeError):
            trouvees = []   # Retire.js n'écrit rien quand il ne trouve rien
    brut = {"bibliotheques": {"scripts": len(adresses), "trouees": trouvees}}
    if not trouvees:
        return [Constat(BLOC, OK, "Aucune bibliothèque JavaScript trouée connue",
                        f"{len(adresses)} script(s) du site vérifié(s).",
                        cle="bibliotheques")], brut
    graves = sum(t["graves"] for t in trouvees)
    liste = ", ".join(f"{t['bibliotheque']} {t['version']}" for t in trouvees[:8])
    return [Constat(
        BLOC, IMPORTANT if graves else INFO,
        f"{len(trouvees)} bibliothèque(s) JavaScript avec des failles connues",
        f"Versions concernées : {liste}. Ces failles sont publiques : un attaquant peut "
        "s'en servir pour piéger les visiteurs du site.",
        "Mettre à jour le site (thème, extensions) pour charger des versions récentes.",
        cle="bibliotheques")], brut
