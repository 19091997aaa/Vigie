"""Bloc Exposition - la page d'accueil vue par Chrome (outil externe : Lighthouse, de Google).

Lighthouse charge la page dans Chrome, comme un visiteur, et note ses protections
et sa vitesse. Il faut Chrome (ou Chromium) installé sur la machine.

Piège relevé sur un vrai diagnostic (21/11/2026) : pour les protections (HSTS, CSP,
cadre, COOP), Lighthouse affiche « réussi » même quand elles manquent. Ces contrôles
sont « informatifs » : le vrai verdict est dans le détail, champ « severity ».
On lit donc le détail, jamais la note.
"""
import json
import os
import tempfile

from .. import outils
from ..modeles import IMPORTANT, INFO, OK, Constat, ControleImpossible

BLOC = "Exposition"
LENT_MS = 4000  # au-delà, beaucoup de visiteurs partent avant la fin du chargement

# Contrôle Lighthouse -> (clé Vigie, niveau, titre, explication, correction).
# Mêmes clés que le module « site » : les deux avis se recoupent dans le rapport.
PROTECTIONS = {
    "has-hsts": ("hsts", IMPORTANT, "Le site n'impose pas la connexion chiffrée (HSTS absent)",
                 "Sur un Wi-Fi public, un attaquant peut ramener vos visiteurs vers une "
                 "version non chiffrée du site.",
                 "Ajouter l'en-tête Strict-Transport-Security."),
    "csp-xss": ("csp", INFO, "Pas de politique de contenu (CSP absente)",
                "Le site n'a pas de filet de sécurité contre l'injection de code dans ses pages.",
                "Ajouter une Content-Security-Policy adaptée au site."),
    "clickjacking-mitigation": ("cadre", INFO, "Le site peut être affiché dans une page piégée",
                                "Aucune protection contre l'encadrement du site par un autre site.",
                                "Ajouter X-Frame-Options: DENY ou une règle frame-ancestors."),
    "origin-isolation": ("coop", INFO, "Le site ne s'isole pas des fenêtres qu'il ouvre (COOP)",
                         "Une page piégée ouverte depuis le site, ou qui l'ouvre, peut "
                         "interagir avec lui.",
                         "Ajouter l'en-tête Cross-Origin-Opener-Policy: same-origin."),
}


def lire_sortie(data):
    """Les protections manquantes (détail « High ») et la vitesse de la page."""
    if not data or data.get("runtimeError"):
        raise ControleImpossible("Lighthouse n'a pas pu charger la page : "
                                 + str((data or {}).get("runtimeError", {}).get("code", "")))
    audits = data.get("audits") or {}
    manquantes = []
    for nom in PROTECTIONS:
        items = ((audits.get(nom) or {}).get("details") or {}).get("items") or []
        if any(item.get("severity") == "High" for item in items):
            manquantes.append(nom)
    https = (audits.get("is-on-https") or {}).get("score")
    affichage = (audits.get("largest-contentful-paint") or {}).get("numericValue")
    note_vitesse = ((data.get("categories") or {}).get("performance") or {}).get("score")
    return {"manquantes": manquantes, "tout_en_https": https != 0,
            "affichage_ms": affichage, "note_vitesse": note_vitesse}


def analyser(cible):
    url = "https://" + cible.domaine + "/"
    with tempfile.TemporaryDirectory() as dossier:
        fichier = os.path.join(dossier, "lighthouse.json")
        outils.executer("lighthouse", [
            url, "--output=json", "--output-path=" + fichier, "--quiet",
            "--chrome-flags=--headless=new", "--only-categories=best-practices,performance"],
            delai=240, dossier=dossier)
        try:
            with open(fichier, encoding="utf-8") as lu:
                data = json.load(lu)
        except (OSError, json.JSONDecodeError):
            raise ControleImpossible("Lighthouse n'a rien produit (Chrome est-il installé ?)")
    resultat = lire_sortie(data)
    constats = []
    for nom in resultat["manquantes"]:
        cle, niveau, titre, explication, correction = PROTECTIONS[nom]
        constats.append(Constat(BLOC, niveau, titre, explication, correction, cle=cle))
    if not resultat["tout_en_https"]:
        constats.append(Constat(
            BLOC, IMPORTANT, "Des éléments de la page arrivent sans chiffrement",
            "La page est chiffrée, mais certaines images ou certains scripts sont chargés en "
            "clair : un attaquant sur le même Wi-Fi peut les remplacer.",
            "Charger toutes les ressources du site en https.", cle="contenu_mixte"))
    ms = resultat["affichage_ms"]
    if ms and ms > LENT_MS:
        constats.append(Constat(
            BLOC, INFO, f"Votre page d'accueil met {ms / 1000:.1f} secondes à s'afficher",
            "Ce n'est pas une faille, mais une page lente fait partir des visiteurs avant "
            "la fin du chargement, et elle est moins bien classée par Google.",
            "Alléger les images et activer un cache (sur WordPress, une extension suffit).",
            cle="lenteur"))
    if not constats:
        constats.append(Constat(BLOC, OK, "La page d'accueil passe les contrôles de Chrome",
                                "Protections en place et affichage rapide.", cle="lighthouse"))
    return constats, {"lighthouse": resultat}
