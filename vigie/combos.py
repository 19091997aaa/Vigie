"""Les combos : plusieurs outils enchaînés sur la même cible, en un seul clic.

Demande d'Anass (28/11/2026) : au lieu de lancer chaque outil à la main dans « Lancer un
outil », choisir un combo (« Vue d'ensemble d'un domaine », « Failles connues »…) et
laisser Vigie lancer les outils l'un après l'autre, puis regrouper ce qu'ils ont trouvé.

Règles :
- Les outils tournent **un par un** (pas en parallèle) et en ligne de commande, sans
  fenêtre : ça ménage la mémoire de la machine.
- Chaque outil passe par les mêmes garde-fous que « Lancer un outil »
  (lancer_seul.preparer) : un outil actif ou offensif ne part que sur une propre cible
  prouvée (mes_cibles.py). Dans un combo passif, un outil actif est **sauté** (avec la
  raison) si la cible n'est pas une des tiennes ; un combo actif est refusé en entier.
- Les combos sur des **personnes** (pseudo, e-mail) demandent de cocher l'accord écrit
  de la personne ; c'est noté au journal.
- **Aucun outil GATE (offensif) dans un combo** : un combo est un enchaînement
  automatique, et les règles d'or l'interdisent (sqlmap reste dans « Lancer un outil »).
- Le regroupement retire les doublons (même sous-domaine, même profil vu par plusieurs
  outils) et dit quel outil a vu quoi : c'est le recoupement.
"""
import re
import urllib.parse

from . import fiches_outils, lancer_seul, registre


# Une étape = (nom de l'outil dans le registre, cible à lui donner).
# « cible » = la cible du combo telle quelle ; « domaine_email » = le domaine d'une adresse.
COMBOS = [
    {"id": "domaine", "titre": "Vue d'ensemble d'un domaine", "genre": "passif",
     "cible": "domaine",
     "but": "Trouver tous les sous-domaines (les « adresses » rattachées au site) et les "
            "vérifier, puis la vue d'ensemble de SpiderFoot (DNS, certificats, listes "
            "noires, domaines qui ressemblent, sous-domaines piratables).",
     "etapes": [("Subfinder", "cible"), ("dnsx", "cible"), ("SpiderFoot", "cible")],
     "note": "SpiderFoot ne part que sur tes propres cibles : sinon il est sauté et les "
             "deux autres tournent quand même."},
    {"id": "web", "titre": "Site web et technologies", "genre": "passif",
     "cible": "domaine",
     "but": "Voir si le site répond, avec quoi il est fait (CMS, serveur, extensions), et "
            "ses anciennes pages gardées par les archives d'Internet.",
     "etapes": [("httpx", "cible"), ("WhatWeb", "cible"), ("gau", "cible")]},
    {"id": "exposition", "titre": "Exposition publique", "genre": "passif",
     "cible": "domaine",
     "but": "Les faux sites qui imitent le nom de domaine (typosquatting), puis la vue "
            "d'ensemble de SpiderFoot.",
     "etapes": [("dnstwist", "cible"), ("SpiderFoot", "cible")],
     "note": "uncover (ce que Shodan et Censys ont déjà vu) n'est pas dans ce combo : il "
             "faut des clés payantes de ces services, et Vigie ne sait pas encore le lancer."},
    {"id": "pseudos", "titre": "Comptes d'un pseudo", "genre": "personne",
     "cible": "pseudo",
     "but": "Sur quels sites un pseudo a un compte. Trois outils, car chacun en rate : "
            "ensemble, ils se recoupent.",
     "etapes": [("Sherlock", "cible"), ("Maigret", "cible"), ("Social Analyzer", "cible")]},
    {"id": "email", "titre": "Une adresse e-mail", "genre": "personne",
     "cible": "email",
     "but": "Sur quels sites l'adresse est inscrite (Holehe), et combien d'adresses "
            "publiques existent sur son domaine (theHarvester, qui compte sans lister).",
     "etapes": [("theHarvester", "domaine_email"), ("Holehe", "cible")]},
    {"id": "failles", "titre": "Failles connues", "genre": "actif",
     "cible": "domaine",
     "but": "Lister les sous-domaines et vérifier que le site répond, puis chercher les "
            "failles connues (Nuclei) et les erreurs de réglage du serveur web (Nikto).",
     "etapes": [("Subfinder", "cible"), ("httpx", "cible"), ("Nuclei", "cible"),
                ("Nikto", "cible")]},
    {"id": "endpoints", "titre": "Pages et paramètres cachés", "genre": "actif",
     "cible": "domaine",
     "but": "Parcourir le site pour lister toutes ses pages (Katana), puis chercher les "
            "paramètres cachés qu'elles acceptent (Arjun).",
     "etapes": [("Katana", "cible"), ("Arjun", "cible")],
     "note": "sqlmap (test d'injection) n'est jamais lancé par un combo : c'est un outil "
             "offensif. Si Arjun trouve une page intéressante, lance sqlmap toi-même dans "
             "« Lancer un outil »."},
]

PAR_ID = {c["id"]: c for c in COMBOS}

GENRES = {
    "passif": "Passif : libre (informations publiques)",
    "personne": "Sur une personne : avec son accord écrit",
    "actif": "Actif : seulement sur tes propres cibles",
}

ACCORD = ("J'ai l'accord écrit de la personne concernée (ou c'est moi) pour chercher ses "
          "comptes en ligne.")


class Refus(lancer_seul.Refus):
    """Le combo ne peut pas partir : la raison est dite en français."""


def _cible_combo(combo, cible):
    """Vérifie et arrange la cible tapée pour ce combo. Lève Refus sinon."""
    cible = (cible or "").strip()
    if not cible:
        raise Refus("Indique une cible : " + {
            "domaine": "un nom de domaine (exemple : pavillon-noir.tech).",
            "pseudo": "un pseudo (exemple : jean.dupont).",
            "email": "une adresse e-mail (exemple : contact@exemple.fr)."}[combo["cible"]])
    fiche = {"cible": combo["cible"]}
    try:
        cible, _ = fiches_outils.adapter_cible(f"Le combo « {combo['titre']} »", cible,
                                               fiche)
    except fiches_outils.CibleInadaptee as erreur:
        raise Refus(str(erreur)) from None
    return cible


def _cible_etape(cible, quoi):
    if quoi == "domaine_email":
        return cible.split("@", 1)[1]
    return cible


def preparer(ident, cible, accord=False, propre=None):
    """Tout ce qu'on vérifie AVANT de lancer un combo.

    `propre(nom, cible)` dit si un outil actif peut partir sur cette cible (True), si
    l'outil est passif (False), ou lève lancer_seul.Refus (cible pas à soi). Renvoie
    {"combo", "cible", "etapes": [{"outil", "cible", "propre", "saute", "raison"}]}.
    Lève Refus si le combo entier ne peut pas partir.
    """
    combo = PAR_ID.get(ident)
    if not combo:
        raise Refus("Combo inconnu.")
    cible = _cible_combo(combo, cible)
    if combo["genre"] == "personne" and not accord:
        raise Refus("Ce combo cherche des informations sur une personne : coche la case "
                    "qui dit que tu as son accord écrit (ou que c'est toi). Sans accord, "
                    "Vigie ne le lance pas.")
    propre = propre or (lambda nom, c: False)
    etapes = []
    for nom, quoi in combo["etapes"]:
        etape = {"outil": nom, "cible": _cible_etape(cible, quoi), "propre": False,
                 "saute": False, "raison": ""}
        fiche = lancer_seul.info(nom)
        try:
            if fiche and fiche.get("famille") == "gate":
                raise lancer_seul.Refus(f"{nom} est offensif : jamais dans un combo.")
            etape["propre"] = propre(nom, etape["cible"])
            prepa = lancer_seul.preparer(nom, etape["cible"], propre_ok=etape["propre"])
            etape["cible"] = prepa["cible"]
        except lancer_seul.Refus as erreur:
            if combo["genre"] == "actif":
                raise Refus(str(erreur)) from None
            etape.update(saute=True, raison=str(erreur))
        etapes.append(etape)
    if all(e["saute"] for e in etapes):
        raise Refus("Aucun outil de ce combo ne peut partir : "
                    + " ".join(e["raison"] for e in etapes))
    return {"combo": combo, "cible": cible, "etapes": etapes}


def reussi(compte):
    """Même règle que « Lancer un outil » : lancé, sans erreur, et il a écrit quelque chose."""
    return bool(compte.get("lance")) and not compte.get("code") \
        and not compte.get("panne") and bool((compte.get("sortie") or "").strip())


# --- Regroupement des résultats (sans doublons, avec qui a vu quoi) ------------------

_URL = re.compile(r"https?://[^\s\"'<>\]\)]+", re.I)
_HOTE = re.compile(r"(?<![\w.-])((?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})"
                   r"(?![\w-])", re.I)
_SANS_COULEUR = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
# Adresses qui ne sont pas des profils : sites des outils eux-mêmes, aides…
_PAS_PROFIL = ("github.com/sherlock-project", "github.com/soxoj", "github.com/qeeqbox",
               "github.com/megadose", "maigret", "localhost", "127.0.0.1")


def sous_domaines(domaine, texte):
    """Les noms de machine du domaine (lui compris) cités dans une sortie."""
    domaine = domaine.lower().strip(".")
    trouves = set()
    for nom in _HOTE.findall(_SANS_COULEUR.sub("", texte or "")):
        nom = nom.lower().lstrip("*.").strip(".")
        if nom == domaine or nom.endswith("." + domaine):
            trouves.add(nom)
    return trouves


def adresses_web(texte):
    """Les adresses web (http/https) citées dans une sortie, sans doublon."""
    vues = set()
    for url in _URL.findall(_SANS_COULEUR.sub("", texte or "")):
        vues.add(url.rstrip(".,;:"))
    return vues


def profils(texte):
    """{site : adresse du profil} pour les profils trouvés (une ligne « [+] » ou une URL)."""
    trouves = {}
    for ligne in _SANS_COULEUR.sub("", texte or "").splitlines():
        if "[-]" in ligne or "not found" in ligne.lower():
            continue
        for url in _URL.findall(ligne):
            url = url.rstrip(".,;:")
            if any(m in url.lower() for m in _PAS_PROFIL):
                continue
            site = (urllib.parse.urlsplit(url).hostname or "").lower()
            site = site[4:] if site.startswith("www.") else site
            if site:
                trouves.setdefault(site, url)
    return trouves


def regrouper(combo, cible, resultats):
    """Le bilan commun d'un combo : ce qui a marché, et les trouvailles sans doublons.

    `resultats` : [{"outil", "reussi", "sortie"}]. Renvoie {"bilan": [phrases],
    "blocs": [{"titre", "lignes": [(chose, [outils qui l'ont vue])], "reste"}]}.
    """
    faits = [r for r in resultats if r.get("lance_par_vigie")]
    bons = [r for r in faits if r.get("reussi")]
    bilan = []
    if faits:
        bilan.append(f"{len(bons)} outil{'s' if len(bons) > 1 else ''} sur {len(faits)} "
                     f"{'ont' if len(bons) > 1 else 'a'} donné un résultat.")
    sautes = [r["outil"] for r in resultats if r.get("saute")]
    if sautes:
        bilan.append("Sautés (voir la raison plus bas) : " + ", ".join(sautes) + ".")
    blocs = []

    def ajouter(titre, trouvailles, unite, max_lignes=60):
        # trouvailles : {chose : set(outils)}
        if not trouvailles:
            return
        rangees = sorted(trouvailles.items(), key=lambda x: (-len(x[1]), x[0]))
        recoupees = sum(1 for _, v in rangees if len(v) > 1)
        phrase = f"{len(rangees)} {unite} différent{'s' if len(rangees) > 1 else ''}"
        if len(bons) > 1:
            phrase += (f", dont {recoupees} vu{'s' if recoupees > 1 else ''} par "
                       "plusieurs outils (recoupés)" if recoupees else
                       ", chacun vu par un seul outil")
        bilan.append(phrase + ".")
        blocs.append({"titre": titre,
                      "lignes": [(chose, sorted(v)) for chose, v in rangees[:max_lignes]],
                      "reste": max(0, len(rangees) - max_lignes)})

    if combo["cible"] == "domaine":
        hotes, urls = {}, {}
        for r in bons:
            for nom in sous_domaines(cible, r.get("sortie", "")):
                hotes.setdefault(nom, set()).add(r["outil"])
            for url in adresses_web(r.get("sortie", "")):
                if lancer_seul.hote(url).endswith(cible):
                    urls.setdefault(url, set()).add(r["outil"])
        ajouter("Sous-domaines trouvés (sans doublon)", hotes, "nom de machine")
        ajouter("Pages du site trouvées (sans doublon)", urls, "adresse", max_lignes=40)
    elif combo["cible"] in ("pseudo", "email"):
        premiere, vus = {}, {}
        for r in bons:
            if r["outil"] == "theHarvester":
                continue
            for site, url in profils(r.get("sortie", "")).items():
                premiere.setdefault(site, url)
                vus.setdefault(site, set()).add(r["outil"])
        ajouter("Comptes trouvés (un par site, sans doublon)",
                {f"{site} : {premiere[site]}": v for site, v in vus.items()}, "site")
    if faits and not bons:
        bilan.append("Aucun outil n'a rien rendu : regarde plus bas ce qui s'est passé "
                     "pour chacun.")
    return {"bilan": bilan, "blocs": blocs}


def resume_combos():
    """Pour la page : chaque combo avec ses outils et ce qui manque au catalogue."""
    noms = {o["nom"] for o in registre.charger()}
    sortie = []
    for combo in COMBOS:
        manquants = [n for n, _ in combo["etapes"] if n not in noms]
        sortie.append(dict(combo, manquants=manquants))
    return sortie
