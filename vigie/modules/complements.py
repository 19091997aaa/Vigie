"""Compléments : des outils gardés parce qu'ils apportent AU MOINS UNE information que
les autres n'ont pas (règle d'Anass du 21/11/2026 : « même une seule chose, on garde »).
Aucun ne retire de points : ce sont des informations, pas des failles.

  - dns_complet (dnsrecon, par défaut) : la fiche DNS complète. Seul à montrer les
    services déclarés (messagerie IMAP, envoi, configuration automatique) et l'IPv6.
  - toutes_pages (Unlighthouse, sur demande car long : ~1 min 30) : Lighthouse sur TOUTES
    les pages, pas seulement l'accueil. Sur pavillon-noir.tech, seul à voir qu'un
    article est aussi lent que l'accueil.
"""
import glob
import json
import os
import tempfile

from .. import outils, pdf, reseau
from ..modeles import INFO, OK, Constat, ControleImpossible

BLOC = "Exposition"
SERVICES = {"_imaps": "lecture des mails (IMAP chiffré)", "_imap": "lecture des mails (IMAP)",
            "_pop3s": "lecture des mails (POP chiffré)", "_submission": "envoi des mails",
            "_autodiscover": "configuration automatique des logiciels de mail",
            "_caldav": "agenda", "_carddav": "carnet d'adresses", "_sip": "téléphonie",
            "_xmpp-client": "messagerie instantanée"}
LENT_MS = 4000


def lire_dnsrecon(fiches):
    services, ipv6 = [], set()
    for fiche in fiches or []:
        if fiche.get("type") == "SRV":
            prefixe = (fiche.get("name") or "").split(".")[0]
            libelle = SERVICES.get(prefixe, prefixe)
            if libelle not in services:
                services.append(libelle)
        elif fiche.get("type") == "AAAA" and fiche.get("address"):
            ipv6.add(fiche["address"])
    return {"services": services, "ipv6": sorted(ipv6)}


def analyser_dns(cible):
    with tempfile.TemporaryDirectory() as dossier:
        chemin = os.path.join(dossier, "dnsrecon.json")
        outils.executer("dnsrecon", ["-d", cible.domaine, "-t", "std", "-n",
                                     reseau.SERVEURS_DNS[0], "-j", chemin], delai=180,
                        dossier=dossier)
        try:
            with open(chemin, encoding="utf-8") as lu:
                infos = lire_dnsrecon(json.load(lu))
        except (OSError, json.JSONDecodeError):
            raise ControleImpossible("dnsrecon n'a rien produit")
    brut = {"dns_complet": infos}
    if not infos["services"] and not infos["ipv6"]:
        return [Constat(BLOC, OK, "Fiche DNS sans service particulier déclaré",
                        "Aucun service supplémentaire n'est annoncé dans le DNS.",
                        cle="dns_complet", hors_note=True)], brut
    morceaux = []
    if infos["services"]:
        morceaux.append("services annoncés : " + ", ".join(infos["services"]))
    if infos["ipv6"]:
        morceaux.append("le site répond aussi en IPv6 (adresse internet nouvelle génération)")
    return [Constat(
        BLOC, INFO, "Ce que le DNS annonce publiquement — vu par dnsrecon",
        "Pour information : " + " ; ".join(morceaux) + ". Tout le monde peut le lire : "
        "c'est normal, mais chaque service annoncé doit être protégé (mot de passe fort, "
        "double authentification sur la messagerie).",
        "Vérifier que chaque service annoncé sert encore.", cle="dns_complet",
        hors_note=True)], brut


def lire_unlighthouse(dossier):
    lentes = []
    for chemin in glob.glob(os.path.join(dossier, "**", "lighthouse.json"), recursive=True):
        try:
            with open(chemin, encoding="utf-8") as lu:
                data = json.load(lu)
        except (OSError, json.JSONDecodeError):
            continue
        ms = ((data.get("audits") or {}).get("largest-contentful-paint") or {}).get("numericValue") or 0
        if ms > LENT_MS:
            lentes.append((round(ms / 1000, 1), data.get("finalDisplayedUrl") or data.get("finalUrl", "")))
    pages = len(glob.glob(os.path.join(dossier, "**", "lighthouse.json"), recursive=True))
    return pages, sorted(lentes, reverse=True)


def analyser_pages(cible):
    navigateur = pdf.trouver_navigateur()
    if not navigateur:
        raise ControleImpossible("aucun navigateur Chrome ou Edge pour Unlighthouse")
    os.environ.setdefault("PUPPETEER_EXECUTABLE_PATH", navigateur)
    with tempfile.TemporaryDirectory() as dossier:
        sortie = os.path.join(dossier, "ul")
        outils.executer("unlighthouse", ["--site", "https://" + cible.domaine, "--reporter",
                                         "jsonExpanded", "--output-path", sortie, "--no-cache"],
                        delai=900, dossier=dossier)
        pages, lentes = lire_unlighthouse(sortie)
    if not pages:
        raise ControleImpossible("Unlighthouse n'a analysé aucune page (Chrome est-il installé ?)")
    brut = {"toutes_pages": {"pages": pages, "lentes": lentes}}
    if not lentes:
        return [Constat(BLOC, OK, f"Les {pages} pages du site s'affichent vite",
                        "Aucune page ne dépasse 4 secondes.", cle="toutes_pages",
                        hors_note=True)], brut
    liste = " ; ".join(f"{url} ({s} s)" for s, url in lentes[:5])
    return [Constat(
        BLOC, INFO, f"{len(lentes)} pages lentes sur {pages} — vu par Unlighthouse",
        f"Pages concernées : {liste}. Ce n'est pas une faille, mais une page lente fait "
        "partir des visiteurs.", "Alléger les images de ces pages.", cle="toutes_pages",
        hors_note=True)], brut
