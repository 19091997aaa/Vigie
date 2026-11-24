"""Bloc Exposition - ce que les sites de la société disent d'eux-mêmes (outil externe : httpx).

httpx ouvre la page d'accueil de chaque adresse connue de la société, comme un
visiteur, sur les ports web habituels, et reconnaît les logiciels utilisés
(WordPress, PHP...). Il ne cherche aucune faille : c'est lire ce que le site
publie, la zone sûre du cadre légal (MARCHE.md §2).

Adresses visitées : le domaine, www, et les sous-domaines trouvés par Subfinder
s'il est installé.
"""
import json
import os
import re
import tempfile

from .. import outils, reseau
from ..modeles import IMPORTANT, INFO, Constat, ControleImpossible, OK
from . import sousdomaines

BLOC = "Exposition"
MAXIMUM_ADRESSES = 25
# Logiciels de site qu'on installe et met à jour soi-même : les robots pirates les visent.
CMS = ("WordPress", "Joomla", "Drupal", "PrestaShop", "Magento", "TYPO3", "Dolibarr",
       "OpenCart", "WooCommerce", "SPIP", "Contao", "Craft CMS")


def adresses(domaine):
    liste = [domaine, "www." + domaine]
    try:
        liste += [nom for nom in sousdomaines.trouver(domaine) if nom not in liste]
    except ControleImpossible:
        pass  # sans Subfinder, on se contente du domaine et de www
    return liste[:MAXIMUM_ADRESSES]


def lire_sortie(texte):
    """Une ligne JSON par adresse qui répond."""
    sites = []
    for ligne in (texte or "").splitlines():
        try:
            d = json.loads(ligne)
        except json.JSONDecodeError:
            continue
        if not isinstance(d, dict):
            continue
        sites.append({
            "adresse": d.get("input", ""),
            "url": d.get("url", ""),
            "finale": d.get("final_url") or d.get("url", ""),
            "code": d.get("status_code"),
            "titre": (d.get("title") or "").strip(),
            "serveur": d.get("webserver", ""),
            "technos": d.get("tech") or [],
            # httpx essaie d'abord https, puis http si https n'a pas répondu à temps. Une
            # adresse vue en http mais REDIRIGÉE vers https est bien chiffrée (cas réel du
            # 24/11/2026 : www passait pour « non chiffré » à cause d'un https trop lent).
            "chiffre": (d.get("scheme") == "https"
                        or str(d.get("final_url") or d.get("url") or "").startswith("https://")),
        })
    return sites


def _hote(url):
    return re.sub(r"^https?://", "", url or "").split("/")[0].split(":")[0].lower()


def analyser(cible):
    domaine = cible.domaine
    liste = adresses(domaine)
    sites = []
    # Deux essais : un réseau qui hoquette (pare-feu, box) ne doit pas donner « rien ».
    for _ in range(2):
        with tempfile.TemporaryDirectory() as dossier:
            fichier = os.path.join(dossier, "adresses.txt")
            with open(fichier, "w", encoding="utf-8") as sortie:
                sortie.write("\n".join(liste) + "\n")
            texte = outils.executer("httpx", [
                "-l", fichier, "-json", "-silent", "-no-color", "-title", "-tech-detect",
                "-status-code", "-web-server", "-follow-redirects",
                "-rate-limit", "5", "-timeout", "15", "-retries", "2"], delai=300,
                dossier=dossier)
        sites = lire_sortie(texte)
        if sites:
            break
    brut = {"sites": sites}
    if not sites:
        raise ControleImpossible("aucune adresse de la société n'a répondu à httpx")

    constats = []
    technos = sorted({t for s in sites for t in s["technos"]})
    cms = sorted({t.split(":")[0] for t in technos if t.split(":")[0] in CMS})
    if cms:
        noms = " et ".join(cms)
        constats.append(Constat(
            BLOC, INFO, f"Votre site tourne sous {noms}",
            f"{noms} est un logiciel de site très répandu, donc la première cible des "
            "robots pirates : ils cherchent sans relâche les sites dont le logiciel ou les "
            "extensions ne sont pas à jour. Ce n'est pas un défaut, c'est un point à tenir.",
            "Activer les mises à jour automatiques du logiciel et des extensions, supprimer "
            "les extensions inutilisées, et garder une sauvegarde récente du site.", cle="cms",
            hors_note=True))

    versions = [t for t in technos if re.search(r":\d", t)]
    if versions:
        constats.append(Constat(
            BLOC, INFO, "Le site affiche la version de ses logiciels",
            "Information visible par tous : " + ", ".join(v.replace(":", " ") for v in versions)
            + ". Elle aide un attaquant à chercher les failles connues de cette version.",
            "Masquer les versions dans la configuration du serveur.", cle="versions_visibles"))

    # Les autres adresses qui répondent avec leur propre site (pas une simple redirection).
    principal = {domaine, "www." + domaine}
    annexes = [s for s in sites if _hote(s["adresse"]) not in principal
               and _hote(s["finale"]) not in principal]
    if annexes:
        detail = " ; ".join(f"{_hote(s['url'])} ({s['titre'] or 'sans titre'})"
                            for s in annexes[:10])
        constats.append(Constat(
            BLOC, INFO, f"{len(annexes)} autres sites de la société répondent",
            f"En plus du site principal : {detail}. Chacun doit être tenu à jour comme le "
            "site principal, ou fermé s'il ne sert plus.",
            "Vérifier qui s'occupe de chacun de ces sites.", cle="sites_annexes"))

    # Recoupement AVANT de noter : httpx seul ne suffit pas pour un point « important ».
    # Vigie refait lui-même une connexion chiffrée vers l'adresse (deux essais).
    brut["https_recoupe"] = {}
    for site in [s for s in sites if not s["chiffre"]]:
        hote = _hote(site["url"])
        verdict = reseau.https_repond(hote)
        brut["https_recoupe"][hote] = verdict
        if verdict == reseau.OUI:
            continue  # httpx s'est trompé (réponse trop lente) : rien à signaler
        if verdict == reseau.NON:
            constats.append(Constat(
                BLOC, IMPORTANT, f"{hote} n'est pas chiffré",
                "Ce site ne répond qu'en connexion non protégée : ce que les visiteurs y "
                "saisissent peut être lu sur un Wi-Fi public. Vérifié deux fois.",
                "Activer HTTPS sur cette adresse.", cle=f"https_{hote}"))
        else:
            constats.append(Constat(
                BLOC, INFO, f"{hote} : connexion chiffrée à confirmer",
                "httpx n'a vu cette adresse qu'en connexion non protégée, mais la "
                "vérification de Vigie n'a pas eu de réponse claire (réseau lent ou "
                "coupé). À vérifier à la relecture en ouvrant https://" + hote + ".",
                "Ouvrir l'adresse en https dans un navigateur pour confirmer.",
                cle=f"https_{hote}", hors_note=True))

    if not constats:
        constats.append(Constat(BLOC, OK, "Le site ne dévoile pas ses logiciels",
                                "Aucun logiciel ni aucune version n'est reconnaissable de "
                                "l'extérieur.", cle="versions_visibles"))
    return constats, brut
