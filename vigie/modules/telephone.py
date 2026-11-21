"""Deux contrôles sur les numéros de téléphone.

1. telephones_publics (bloc Exposition, par défaut) : y a-t-il des numéros de PORTABLE
   (06, 07) publiés sur le site ? Lecture de quelques pages publiques (accueil, contact,
   mentions légales), comme un visiteur. Un portable de dirigeant affiché publiquement
   sert aux arnaques au faux conseiller bancaire et au détournement de ligne. Les numéros
   sont COMPTÉS, jamais listés ni gardés.

2. telephone (outil PhoneInfoga, sur demande) : ce que révèle le numéro DONNÉ par le
   dirigeant, avec son accord. Essai du 21/11/2026 : sans clé payante, PhoneInfoga
   donne surtout le pays et le format, et prépare des recherches Google à ouvrir à la
   main (réseaux sociaux, sites de SMS jetables). Vigie garde ces liens pour Anass.
"""
import re
import urllib.parse
import urllib.request

from .. import outils, reseau
from ..modeles import INFO, OK, Constat, ControleImpossible

BLOC = "Exposition"
PAGES = ("/", "/contact/", "/mentions-legales/", "/index.php/contact/",
         "/index.php/mentions-legales/")
# 06 12 34 56 78, 06.12.34.56.78, +33 6 12 34 56 78, +33612345678
PORTABLE = re.compile(r"(?<!\d)(?:\+33[\s.]?|0033[\s.]?|0)[67](?:[\s.-]?\d{2}){4}(?!\d)")
NUMERO = re.compile(r"\+?[0-9 .-]{8,20}")


def _ouvrir(url):
    requete = urllib.request.Request(url, headers={"User-Agent": reseau.AGENT})
    with urllib.request.urlopen(requete, timeout=15) as reponse:
        return reponse.read(2_000_000).decode("utf-8", "replace")


def portables(texte):
    """Les numéros de portable distincts d'un texte, en chiffres seuls."""
    vus = set()
    for brut in PORTABLE.findall(texte or ""):
        chiffres = re.sub(r"\D", "", brut)
        vus.add("0" + chiffres[-9:])
    return vus


def analyser_publics(cible):
    trouves, lues = set(), 0
    for page in PAGES:
        try:
            trouves |= portables(_ouvrir("https://" + cible.domaine + page))
            lues += 1
        except Exception:
            continue
    if not lues:
        raise ControleImpossible("aucune page du site n'a pu être lue")
    brut = {"telephones_publics": {"pages_lues": lues, "portables": len(trouves)}}
    if not trouves:
        return [Constat(BLOC, OK, "Aucun numéro de portable publié sur le site",
                        "Les pages d'accueil, de contact et les mentions légales n'affichent "
                        "pas de numéro de portable.", cle="portables")], brut
    return [Constat(
        BLOC, INFO, f"{len(trouves)} numéro{'s' if len(trouves) > 1 else ''} de portable "
                    "publié sur le site",
        "Un numéro de portable affiché publiquement, souvent celui du dirigeant, sert aux "
        "arnaques au faux conseiller bancaire et au détournement de ligne (un escroc se fait "
        "passer pour vous auprès de l'opérateur). Le diagnostic ne le recopie pas.",
        "Afficher plutôt un numéro fixe ou un standard, et protéger la ligne mobile par un "
        "code auprès de l'opérateur.", cle="portables")], brut


def lire_phoneinfoga(texte):
    infos = {}
    for ligne in (texte or "").splitlines():
        cle, _, valeur = ligne.strip().partition(": ")
        if cle in ("Country", "E164", "Local", "Found"):
            infos[cle] = valeur.strip()
    infos["recherches"] = re.findall(r"URL: (https://www\.google\.com/search\?\S+)", texte or "")
    return infos


def analyser(cible):
    if not cible.telephones:
        raise ControleImpossible("aucun numéro fourni par le dirigeant")
    if not cible.accord_dirigeant:
        raise ControleImpossible("accord écrit du dirigeant requis (--accord-dirigeant)")
    constats, brut = [], {}
    for numero in cible.telephones:
        if not NUMERO.fullmatch(numero.strip()):
            raise ControleImpossible(f"numéro invalide : {numero}")
        texte = outils.executer("phoneinfoga", ["scan", "-n", numero.strip(),
                                                "-D", "numverify", "-D", "googlecse"], delai=180)
        infos = lire_phoneinfoga(texte)
        brut[numero] = infos
        mobile = bool(portables(infos.get("Local", "") or numero))
        constats.append(Constat(
            BLOC, INFO, "Le numéro du dirigeant est un portable" if mobile
            else "Le numéro du dirigeant a été analysé",
            f"Pays : {infos.get('Country') or 'inconnu'}. "
            f"{len(infos['recherches'])} recherches à ouvrir à la main sont prêtes (réseaux "
            "sociaux, sites de SMS jetables) pour voir où ce numéro apparaît.",
            "Ne pas publier ce numéro ; demander à l'opérateur un code de protection contre "
            "le détournement de ligne.", hors_note=True))
    return constats, brut
