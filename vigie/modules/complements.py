"""Compléments : des outils gardés parce qu'ils apportent AU MOINS UNE information que
les autres n'ont pas (règle d'Anass du 21/11/2026 : « même une seule chose, on garde »).
Aucun ne retire de points : ce sont des informations, pas des failles.

  - dns_complet (dnsrecon, par défaut) : la fiche DNS complète. Seul à montrer les
    services déclarés (messagerie IMAP, envoi, configuration automatique) et l'IPv6.
  - toutes_pages (Unlighthouse, long : 2 à 8 minutes selon le nombre de pages, 7 min 25
    pour 30 pages sur la VM Ubuntu le 26/11/2026) : Lighthouse sur TOUTES les pages, pas
    seulement l'accueil. Sur pavillon-noir.tech, seul à voir qu'un article est aussi
    lent que l'accueil. La page d'accueil, déjà mesurée par Lighthouse, n'est pas
    recomptée : deux chiffres pour la même page déroutaient le client (26/11/2026).
"""
import glob
import json
import os
import tempfile
import urllib.parse

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


def _dnsrecon(domaine, serveur):
    """(fiches lues ou None, résultat brut). serveur None = DNS de la machine."""
    with tempfile.TemporaryDirectory() as dossier:
        chemin = os.path.join(dossier, "dnsrecon.json")
        arguments = ["-d", domaine, "-t", "std", "-j", chemin]
        if serveur:
            arguments[4:4] = ["-n", serveur]
        resultat = outils.executer_detail("dnsrecon", arguments, delai=150, dossier=dossier)
        try:
            with open(chemin, encoding="utf-8") as lu:
                return json.load(lu), resultat
        except (OSError, json.JSONDecodeError, ValueError):
            return None, resultat


def analyser_dns(cible):
    """dnsrecon, d'abord par un résolveur public, puis (s'il ne produit rien) par le DNS de
    la machine. dnsrecon écrit ses erreurs à l'écran et s'arrête en 1 seconde sans fichier
    (« Could not resolve domain », délai DNS, version cassée) : on dit lequel, au lieu
    d'un vague « n'a rien produit » (cas réel du 24/11/2026)."""
    fiches, resultat = _dnsrecon(cible.domaine, reseau.SERVEURS_DNS[0])
    if fiches is None:
        fiches, resultat = _dnsrecon(cible.domaine, None)
    panne = ""
    if fiches is None:
        # dnsrecon en panne (plantage du 26/11/2026 sur la VM Ubuntu) : Vigie lit lui-même
        # les mêmes fiches publiques (services SRV et IPv6), par les résolveurs publics.
        panne = "dnsrecon n'a rien produit — " + _raison_dnsrecon(resultat)
        fiches = fiches_par_vigie(cible.domaine)
        if fiches is None:
            raise ControleImpossible(panne)
    infos = lire_dnsrecon(fiches)
    brut = {"dns_complet": infos}
    if panne:
        brut["panne"] = {"dnsrecon": panne + " ; Vigie a lu lui-même les mêmes fiches DNS "
                                             "(services et IPv6)"}
    # Qui a lu la fiche : le rapport doit le dire (même règle que tlsx / SSLyze).
    sources = ["Fiche DNS lue par Vigie (dnsrecon en panne)"] if panne else []
    if not infos["services"] and not infos["ipv6"]:
        return [Constat(BLOC, OK, "Fiche DNS sans service particulier déclaré",
                        "Aucun service supplémentaire n'est annoncé dans le DNS.",
                        cle="dns_complet", hors_note=True, sources=sources)], brut
    morceaux = []
    if infos["services"]:
        morceaux.append("services annoncés : " + ", ".join(infos["services"]))
    if infos["ipv6"]:
        morceaux.append("le site répond aussi en IPv6 (adresse internet nouvelle génération)")
    return [Constat(
        BLOC, INFO, "Ce que le DNS annonce publiquement" + ("" if panne else " — vu par dnsrecon"),
        "Pour information : " + " ; ".join(morceaux) + ". Tout le monde peut le lire : "
        "c'est normal, mais chaque service annoncé doit être protégé (mot de passe fort, "
        "double authentification sur la messagerie).",
        "Vérifier que chaque service annoncé sert encore.", cle="dns_complet",
        hors_note=True, sources=sources)], brut


# Les noms SRV que dnsrecon interroge pour les services de SERVICES.
NOMS_SRV = {"_imaps": "_tcp", "_imap": "_tcp", "_pop3s": "_tcp", "_submission": "_tcp",
            "_autodiscover": "_tcp", "_caldav": "_tcp", "_carddav": "_tcp", "_sip": "_udp",
            "_xmpp-client": "_tcp"}


def fiches_par_vigie(domaine):
    """Les fiches SRV et AAAA du domaine, au format de dnsrecon, lues par Vigie lui-même.
    None si le DNS est injoignable (on ne conclut pas)."""
    fiches = []
    try:
        for prefixe, transport in NOMS_SRV.items():
            nom = f"{prefixe}.{transport}.{domaine}"
            if reseau.dns(nom, "SRV"):
                fiches.append({"type": "SRV", "name": nom})
        for adresse in reseau.dns(domaine, "AAAA"):
            fiches.append({"type": "AAAA", "address": adresse})
    except ControleImpossible:
        return None
    return fiches


def _raison_dnsrecon(resultat):
    """dnsrecon écrit ses erreurs sur sa sortie normale, préfixées par « [-] »."""
    texte = (resultat.stdout or "") + "\n" + (resultat.stderr or "")
    if "could not resolve domain" in texte.lower():
        return ("il n'a pas pu lire le domaine dans le DNS, ni par un résolveur public, ni "
                "par celui de la machine : DNS bloqué par le pare-feu ou coupé")
    if "timeout" in texte.lower() and "[-]" in texte:
        return ("les serveurs DNS n'ont pas répondu à temps : le pare-feu filtre "
                "peut-être les questions DNS")
    return outils.pourquoi(resultat)


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
    accueil_a_part = outils.disponible("lighthouse")
    if accueil_a_part:
        lentes = [(s, url) for s, url in lentes if not est_accueil(url, cible.domaine)]
    if not lentes:
        autres = " (en dehors de la page d'accueil, mesurée à part)" if accueil_a_part else ""
        return [Constat(BLOC, OK, f"Les {pages} pages du site s'affichent vite{autres}",
                        "Aucune page ne dépasse 4 secondes.", cle="toutes_pages",
                        hors_note=True)], brut
    liste = " ; ".join(f"{url} ({s} s)" for s, url in lentes[:5])
    accueil = (" La page d'accueil n'est pas dans cette liste : sa vitesse est donnée à "
               "part, mesurée par Lighthouse." if accueil_a_part else "")
    nombre = (f"{len(lentes)} pages lentes" if len(lentes) > 1 else "1 page lente")
    return [Constat(
        BLOC, INFO, f"{nombre} sur {pages} — vu par Unlighthouse",
        f"Pages concernées : {liste}. Ce n'est pas une faille, mais une page lente fait "
        f"partir des visiteurs.{accueil}", "Alléger les images de ces pages.",
        cle="toutes_pages", hors_note=True)], brut


def est_accueil(url, domaine):
    """La page d'accueil du domaine (avec ou sans www, avec ou sans « / » final)."""
    morceaux = urllib.parse.urlparse(url or "")
    hote = (morceaux.hostname or "").lower()
    return hote in (domaine, "www." + domaine) and morceaux.path in ("", "/") \
        and not morceaux.query
