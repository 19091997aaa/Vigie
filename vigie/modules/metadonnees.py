"""Bloc Exposition - informations cachées dans les documents et photos publiés (outil : ExifTool).

Un PDF ou une photo mis en ligne garde souvent, sans qu'on le voie, le nom de la
personne qui l'a créé, le logiciel utilisé, parfois la position GPS de la prise de
vue. Vigie télécharge quelques fichiers publiés sur le site, comme un visiteur
(10 au plus, 5 Mo chacun), et les fait lire par ExifTool.

Règle du diagnostic gratuit : les noms de personnes ne sont que COMPTÉS, jamais
listés ni gardés (données personnelles). Seul leur nombre apparaît.
"""
import json
import os
import re
import tempfile
import urllib.parse
import urllib.request

from .. import outils, reseau
from ..modeles import IMPORTANT, INFO, OK, Constat, ControleImpossible
from . import archives

BLOC = "Exposition"
MAXIMUM_FICHIERS = 10
TAILLE_MAXIMUM = 5_000_000
DOCUMENT = archives.DOCUMENT
IMAGE = re.compile(r"\.(jpe?g|png|tiff?|heic|webp)$", re.I)
LIEN = re.compile(r'(?:href|src|srcset)=["\']([^"\']+)["\']', re.I)

# Groupe:Étiquette d'ExifTool (option -G). « PDF:Creator » est un logiciel, pas une personne.
PERSONNES = ("PDF:Author", "XMP:Creator", "XMP:Author", "EXIF:Artist", "EXIF:XPAuthor",
             "IPTC:By-line", "XML:Creator", "XML:LastModifiedBy", "FlashPix:Author",
             "FlashPix:LastModifiedBy")
LOGICIELS = ("PDF:Creator", "PDF:Producer", "XMP:CreatorTool", "EXIF:Software",
             "XML:Application")


def _du_domaine(url, domaine):
    hote = (urllib.parse.urlparse(url).hostname or "").lower()
    return hote == domaine or hote.endswith("." + domaine)


def liens_fichiers(html, base, domaine):
    """Documents et photos référencés par une page, sur le domaine lui-même seulement."""
    trouves = set()
    for valeur in LIEN.findall(html or ""):
        for morceau in valeur.split(","):  # srcset : « image.jpg 600w, image2.jpg 1200w »
            adresse = morceau.strip().split(" ")[0]
            if not adresse:
                continue
            url = urllib.parse.urljoin(base, adresse)
            chemin = urllib.parse.urlparse(url).path
            if _du_domaine(url, domaine) and (DOCUMENT.search(chemin) or IMAGE.search(chemin)):
                trouves.add(url)
    return sorted(trouves)


def _ouvrir(url, limite=TAILLE_MAXIMUM):
    requete = urllib.request.Request(url, headers={"User-Agent": reseau.AGENT})
    with urllib.request.urlopen(requete, timeout=20) as reponse:
        return reponse.read(limite + 1)


def choisir(domaine):
    """Les fichiers à analyser : documents d'abord (archives et page d'accueil), puis photos."""
    candidats = []
    try:
        candidats += archives.documents(archives.trouver(domaine))
    except ControleImpossible:
        pass  # sans gau, on se contente de la page d'accueil
    base = "https://" + domaine + "/"
    try:
        page = _ouvrir(base).decode("utf-8", "replace")
        candidats += liens_fichiers(page, base, domaine)
    except Exception:
        pass
    vus, docs, images = set(), [], []
    for url in candidats:
        if url in vus or not _du_domaine(url, domaine):
            continue
        vus.add(url)
        (docs if DOCUMENT.search(urllib.parse.urlparse(url).path) else images).append(url)
    return (docs + images)[:MAXIMUM_FICHIERS]


def lire_sortie(texte):
    """Compte les fichiers qui portent des noms, des logiciels, une position GPS."""
    try:
        fiches = json.loads(texte or "[]")
    except json.JSONDecodeError:
        raise ControleImpossible("ExifTool n'a pas renvoyé de résultat lisible")
    noms, logiciels, avec_gps = set(), set(), 0
    for fiche in fiches:
        for cle in PERSONNES:
            valeur = str(fiche.get(cle, "")).strip()
            if valeur:
                noms.add(valeur.lower())
        for cle in LOGICIELS:
            valeur = str(fiche.get(cle, "")).strip()
            if valeur:
                logiciels.add(valeur)
        if any("GPSLatitude" in cle or "GPSPosition" in cle for cle in fiche):
            avec_gps += 1
    # Les noms ne quittent jamais cette fonction : seul leur nombre est gardé.
    return {"fichiers": len(fiches), "noms": len(noms), "logiciels": sorted(logiciels),
            "avec_gps": avec_gps}


def analyser(cible):
    adresses = choisir(cible.domaine)
    if not adresses:
        return [Constat(BLOC, OK, "Aucun document ni photo publiés à analyser",
                        "La page d'accueil et les archives ne renvoient vers aucun fichier.",
                        cle="metadonnees")], {"metadonnees": {"fichiers": 0}}
    with tempfile.TemporaryDirectory() as dossier:
        telecharges = 0
        for numero, url in enumerate(adresses):
            nom = re.sub(r"[^A-Za-z0-9._-]", "_",
                         os.path.basename(urllib.parse.urlparse(url).path))[-80:]
            try:
                contenu = _ouvrir(url)
            except Exception:
                continue
            if len(contenu) > TAILLE_MAXIMUM:
                continue
            with open(os.path.join(dossier, f"{numero:02d}_{nom}"), "wb") as fichier:
                fichier.write(contenu)
            telecharges += 1
        if not telecharges:
            raise ControleImpossible("aucun fichier publié n'a pu être téléchargé")
        texte = outils.executer("exiftool", ["-json", "-G", "-n", "-q", "-q", dossier],
                                delai=120)
    resultat = lire_sortie(texte)
    constats = []
    if resultat["avec_gps"]:
        constats.append(Constat(
            BLOC, IMPORTANT, f"{resultat['avec_gps']} photos publiées donnent une position GPS",
            "Ces photos indiquent l'endroit exact où elles ont été prises : parfois un "
            "domicile ou un local que la société ne souhaite pas rendre public.",
            "Retirer la position des photos avant de les publier (réglage du téléphone ou "
            "extension du site).", cle="gps"))
    if resultat["noms"]:
        constats.append(Constat(
            BLOC, INFO, f"Les fichiers publiés révèlent {resultat['noms']} noms de personnes",
            "Ces noms servent aux escrocs pour fabriquer des mails piégés crédibles "
            "(« Bonjour, c'est Julie de la compta »). Le diagnostic ne les liste pas.",
            "Effacer l'auteur des documents avant de les publier.", cle="noms_documents"))
    if resultat["logiciels"]:
        constats.append(Constat(
            BLOC, INFO, "Les fichiers publiés révèlent les logiciels utilisés",
            "Logiciels visibles : " + ", ".join(resultat["logiciels"][:6]) + ". Un attaquant "
            "s'en sert pour viser les failles de ces logiciels.",
            "Nettoyer les informations des fichiers avant de les publier.",
            cle="logiciels_documents"))
    if not constats:
        constats.append(Constat(
            BLOC, OK, f"Aucune information cachée dans {resultat['fichiers']} fichiers publiés",
            "Ni nom, ni logiciel, ni position GPS dans les documents et photos analysés.",
            cle="metadonnees"))
    return constats, {"metadonnees": resultat}
