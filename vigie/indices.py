"""Ce que Vigie tire du domaine pour nourrir les outils qui attendent autre chose.

Beaucoup d'outils du diagnostic gratuit n'attendent pas un nom de domaine : Sherlock
veut un pseudo, Instaloader un compte Instagram, PhoneInfoga un numéro, dnsx une liste
de noms. Ce fichier les déduit de ce que la société publie elle-même sur son site,
comme le ferait un visiteur :
  - les comptes de réseaux sociaux affichés en lien sur le site ;
  - le nom de la société tel qu'il apparaît dans le domaine (pavillon-noir.tech ->
    « pavillon-noir ») ;
  - les numéros de téléphone affichés sur l'accueil, la page contact, les mentions.

Règle du diagnostic gratuit : ces informations servent d'ENTRÉE aux outils, en mémoire.
Les numéros ne sont jamais écrits dans le rapport (seulement comptés).

Les pages sont lues une seule fois, même si plusieurs outils les demandent en même
temps (le diagnostic lance des outils en parallèle).
"""
import re
import threading
import urllib.request

from . import reseau

PAGES = ("/", "/contact/", "/contact", "/mentions-legales/", "/index.php/contact/",
         "/index.php/mentions-legales/")
TAILLE_MAXIMUM = 2_000_000
PSEUDO = re.compile(r"[A-Za-z0-9._-]{2,40}")
MAXIMUM_PSEUDOS = 3
MAXIMUM_NUMEROS = 3

# Liens vers les comptes de la société. Les chemins génériques (partage, connexion…)
# ne sont pas des comptes.
RESEAUX = {
    "instagram": re.compile(r"instagram\.com/([A-Za-z0-9._]{2,30})", re.I),
    "facebook": re.compile(r"facebook\.com/([A-Za-z0-9.\-]{2,50})", re.I),
    "linkedin": re.compile(r"linkedin\.com/company/([A-Za-z0-9\-_%]{2,60})", re.I),
    "x": re.compile(r"(?:twitter|x)\.com/([A-Za-z0-9_]{2,15})", re.I),
    "tiktok": re.compile(r"tiktok\.com/@([A-Za-z0-9._]{2,30})", re.I),
    "youtube": re.compile(r"youtube\.com/@([A-Za-z0-9._\-]{2,50})", re.I),
}
GENERIQUES = {"sharer", "share", "intent", "p", "reel", "reels", "explore", "tr", "plugins",
              "dialog", "home", "watch", "channel", "login", "accounts", "privacy", "policy",
              "legal", "help", "about", "hashtag", "search", "pages", "groups", "events",
              "profile.php", "sharer.php", "embed", "i", "stories", "web"}
# Numéros français : 01 23 45 67 89, 06.12.34.56.78, +33 6 12 34 56 78…
NUMERO = re.compile(r"(?<![\d+])(?:\+33[\s.]?(?:\(0\))?|0033[\s.]?|0)[1-9](?:[\s.-]?\d{2}){4}(?!\d)")

_VERROU = threading.Lock()
_CACHE = {}


def _une_fois(cle, fabrique):
    """Calcule fabrique() une seule fois par clé, même si deux outils demandent ensemble."""
    with _VERROU:
        entree = _CACHE.setdefault(cle, {"verrou": threading.Lock(), "fait": False})
    with entree["verrou"]:
        if not entree["fait"]:
            try:
                entree["valeur"] = fabrique()
            except Exception:
                entree["valeur"] = None
            entree["fait"] = True
        return entree["valeur"]


def oublier():
    """Vide la mémoire (entre deux diagnostics, et pour les essais)."""
    with _VERROU:
        _CACHE.clear()


def _ouvrir(url):
    requete = urllib.request.Request(url, headers={"User-Agent": reseau.AGENT})
    with urllib.request.urlopen(requete, timeout=15) as reponse:
        return reponse.read(TAILLE_MAXIMUM).decode("utf-8", "replace")


def page(domaine, chemin="/"):
    """Le texte d'une page du site, lue une fois. None si elle ne répond pas."""
    return _une_fois(("page", domaine, chemin), lambda: _ouvrir(f"https://{domaine}{chemin}"))


def pages(domaine):
    """Les pages publiques utiles (accueil, contact, mentions) qui ont répondu."""
    return [texte for texte in (page(domaine, chemin) for chemin in PAGES) if texte]


def reseaux_sociaux(texte):
    """{réseau: [comptes]} d'après les liens d'une page."""
    trouves = {}
    for reseau_nom, motif in RESEAUX.items():
        for compte in motif.findall(texte or ""):
            compte = compte.strip(".").rstrip("/")
            if compte.lower() in GENERIQUES or not compte:
                continue
            liste = trouves.setdefault(reseau_nom, [])
            if compte.lower() not in (c.lower() for c in liste):
                liste.append(compte)
    return trouves


def comptes_societe(domaine):
    """Les comptes de réseaux sociaux que la société affiche sur son propre site."""
    fusion = {}
    for texte in pages(domaine):
        for reseau_nom, comptes in reseaux_sociaux(texte).items():
            liste = fusion.setdefault(reseau_nom, [])
            liste += [c for c in comptes if c.lower() not in (x.lower() for x in liste)]
    return fusion


def nom_dans_domaine(domaine):
    """pavillon-noir.tech -> pavillon-noir ; www.ex.co.uk -> ex."""
    morceaux = [m for m in domaine.lower().split(".") if m and m != "www"]
    if len(morceaux) >= 3 and morceaux[-2] in ("co", "com", "org", "gouv", "asso"):
        morceaux = morceaux[:-1]
    return morceaux[-2] if len(morceaux) >= 2 else (morceaux[0] if morceaux else "")


def pseudos_societe(domaine):
    """Les pseudos sous lesquels la société se présente : ses comptes affichés sur le site,
    puis le nom tiré du domaine. Jamais le nom d'une personne : seulement la marque."""
    candidats = []
    for comptes in comptes_societe(domaine).values():
        candidats += comptes
    candidats.append(nom_dans_domaine(domaine))
    retenus = []
    for pseudo in candidats:
        if PSEUDO.fullmatch(pseudo or "") and pseudo.lower() not in (p.lower() for p in retenus):
            retenus.append(pseudo)
    return retenus[:MAXIMUM_PSEUDOS]


def numeros(texte):
    """Les numéros français distincts d'un texte, au format international (+33…)."""
    vus = []
    for brut in NUMERO.findall(texte or ""):
        chiffres = re.sub(r"\D", "", brut)
        e164 = "+33" + chiffres[-9:]
        if e164 not in vus:
            vus.append(e164)
    return vus


def numeros_publics(domaine):
    """Les numéros affichés sur le site (en mémoire seulement, jamais dans le rapport)."""
    vus = []
    for texte in pages(domaine):
        vus += [n for n in numeros(texte) if n not in vus]
    return vus[:MAXIMUM_NUMEROS]
