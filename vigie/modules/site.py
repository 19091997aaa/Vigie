"""Bloc Exposition - site internet : chiffrement, certificat, protections de base.

Le module fait ce que fait un navigateur : il ouvre la page d'accueil et lit
la réponse. Il ne cherche pas de faille et n'envoie rien d'autre.
"""
import re
import socket
import ssl
import time
import urllib.error
import urllib.request

from .. import reseau
from ..modeles import CRITIQUE, IMPORTANT, INFO, OK, Constat

BLOC = "Exposition"


def _c(niveau, titre, explication, correction="", cle=""):
    # Une clé par problème : elle permet de recouper avec SSLyze et Lighthouse sans
    # jamais fondre deux problèmes différents en un seul (vu sur un vrai diagnostic).
    return Constat(BLOC, niveau, titre, explication, correction, cle=cle)


def _ouvrir(url):
    """Ouvre une page comme un navigateur. Renvoie (adresse finale, code, en-têtes)."""
    requete = urllib.request.Request(url, headers={"User-Agent": reseau.AGENT})
    try:
        with urllib.request.urlopen(requete, timeout=15) as reponse:
            entetes = {cle.lower(): valeur for cle, valeur in reponse.headers.items()}
            return reponse.geturl(), reponse.status, entetes
    except urllib.error.HTTPError as erreur:  # le site répond, mais par une erreur
        entetes = {cle.lower(): valeur for cle, valeur in erreur.headers.items()}
        return erreur.geturl(), erreur.code, entetes


def _jours_certificat(domaine):
    """Nombre de jours avant la fin du certificat. Lève ssl.SSLError s'il est invalide."""
    contexte = ssl.create_default_context()
    with socket.create_connection((domaine, 443), timeout=10) as brut:
        with contexte.wrap_socket(brut, server_hostname=domaine) as connexion:
            certificat = connexion.getpeercert()
    fin = ssl.cert_time_to_seconds(certificat["notAfter"])
    return int((fin - time.time()) // 86400)


def _certificat(domaine):
    try:
        jours = _jours_certificat(domaine)
    except ssl.SSLError:
        return None, [_c(CRITIQUE, "Certificat du site invalide ou expiré",
                         "Les navigateurs affichent une alerte de sécurité à vos visiteurs.",
                         "Renouveler ou réinstaller le certificat.", cle="certificat")]
    except OSError:
        return None, [_c(IMPORTANT, "Le site ne répond pas en connexion chiffrée (HTTPS)",
                         "Ce qui transite entre vos visiteurs et le site peut être lu ou modifié.",
                         "Activer HTTPS chez l'hébergeur.", cle="https")]
    if jours < 15:
        return jours, [_c(IMPORTANT, f"Le certificat expire dans {jours} jours",
                          "Passé cette date, vos visiteurs verront une alerte de sécurité.",
                          "Renouveler le certificat, et activer le renouvellement automatique.",
                          cle="certificat")]
    return jours, [_c(OK, "Certificat valide", f"Il reste {jours} jours avant son expiration.",
                      cle="certificat")]


def _redirection(domaine):
    try:
        finale, _, _ = _ouvrir("http://" + domaine + "/")
    except Exception:
        return None, []  # pas de version non chiffrée : rien à signaler
    if finale.lower().startswith("https://"):
        return finale, [_c(OK, "Redirection vers la version chiffrée",
                           "Un visiteur qui tape l'adresse simple arrive sur la version sécurisée.",
                           cle="redirection_https")]
    return finale, [_c(IMPORTANT, "Le site reste accessible sans chiffrement",
                       "Un visiteur peut naviguer sur une version non protégée du site.",
                       "Rediriger automatiquement http vers https.", cle="redirection_https")]


def _entetes(domaine):
    try:
        _, code, entetes = _ouvrir("https://" + domaine + "/")
    except Exception:
        return {}, []  # déjà signalé par le contrôle du certificat
    constats = []
    if "strict-transport-security" not in entetes:
        constats.append(_c(
            IMPORTANT, "Le site n'impose pas la connexion chiffrée (HSTS absent)",
            "Sur un Wi-Fi public, un attaquant peut ramener vos visiteurs vers une version "
            "non chiffrée du site.",
            "Ajouter l'en-tête Strict-Transport-Security.", cle="hsts"))
    if "content-security-policy" not in entetes:
        constats.append(_c(
            INFO, "Pas de politique de contenu (CSP absente)",
            "Le site n'a pas de filet de sécurité contre l'injection de code dans ses pages.",
            "Ajouter une Content-Security-Policy adaptée au site.", cle="csp"))
    if "x-content-type-options" not in entetes:
        constats.append(_c(INFO, "Protection contre les fichiers déguisés absente",
                           "L'en-tête X-Content-Type-Options n'est pas envoyé.",
                           "Ajouter X-Content-Type-Options: nosniff.", cle="nosniff"))
    if "x-frame-options" not in entetes and "frame-ancestors" not in entetes.get(
            "content-security-policy", ""):
        constats.append(_c(INFO, "Le site peut être affiché dans une page piégée",
                           "Aucune protection contre l'encadrement du site par un autre site.",
                           "Ajouter X-Frame-Options: DENY ou une règle frame-ancestors.",
                           cle="cadre"))
    bavards = [f"{nom}: {entetes[nom]}" for nom in ("server", "x-powered-by")
               if re.search(r"\d", entetes.get(nom, ""))]
    if bavards:
        constats.append(_c(
            INFO, "Le site affiche la version de ses logiciels",
            "Information visible par tous : " + " ; ".join(bavards) + ". "
            "Elle aide un attaquant à chercher les failles connues de cette version.",
            "Masquer les versions dans la configuration du serveur.", cle="versions_visibles"))
    if not constats:
        constats.append(_c(OK, "Protections de base du site en place",
                           "Les en-têtes de sécurité attendus sont présents."))
    return {"code": code, "entetes": entetes}, constats


def analyser(cible):
    """Renvoie (liste de constats, données brutes)."""
    domaine = cible.domaine
    # Lève ErreurReseau si internet est coupé : on ne conclut rien sans réseau.
    if not reseau.dns(domaine, "A") and not reseau.dns("www." + domaine, "A"):
        return [_c(INFO, "Aucun site internet sur ce domaine",
                   "Le nom de domaine ne pointe vers aucun site.")], {"site": False}
    jours, c_cert = _certificat(domaine)
    finale, c_redir = _redirection(domaine)
    reponse, c_entetes = _entetes(domaine)
    brut = {"jours_certificat": jours, "adresse_finale_http": finale, "reponse": reponse}
    return c_cert + c_redir + c_entetes, brut
