"""Bloc Exposition - les versions du chiffrement acceptées par le site (outil externe : SSLyze).

SSLyze se présente au site comme des navigateurs d'âges différents et note les
versions du chiffrement que le site accepte, ainsi que son certificat. Vigie ne lui
demande QUE cela : aucun test de faille (Heartbleed, ROBOT...), qui relèverait du
scan sur autorisation. Lire ce que le site propose à un visiteur est la zone sûre du
cadre légal (MARCHE.md §2).
"""
import json
import os
import tempfile

from .. import outils, reseau
from ..modeles import CRITIQUE, IMPORTANT, INFO, OK, Constat, ControleImpossible

BLOC = "Exposition"
# Réglages passés à SSLyze : versions du chiffrement et certificat, rien d'autre.
CONTROLES = ["--certinfo", "--sslv2", "--sslv3", "--tlsv1", "--tlsv1_1", "--tlsv1_2",
             "--tlsv1_3"]
VERSIONS = {"ssl_2_0_cipher_suites": "SSL 2", "ssl_3_0_cipher_suites": "SSL 3",
            "tls_1_0_cipher_suites": "TLS 1.0", "tls_1_1_cipher_suites": "TLS 1.1",
            "tls_1_2_cipher_suites": "TLS 1.2", "tls_1_3_cipher_suites": "TLS 1.3"}
FAIBLES = ("RC4", "3DES", "_DES_", "NULL", "EXPORT", "ANON", "MD5")


class InjoignableSSLyze(ControleImpossible):
    """SSLyze n'a pas pu se connecter. raison : ce que SSLyze en dit (dernière ligne)."""

    def __init__(self, message, raison=""):
        super().__init__(message)
        self.raison = raison


def _raison(resultat):
    trace = resultat.get("connectivity_error_trace") or resultat.get("connectivity_result") or ""
    lignes = [l.strip() for l in str(trace).splitlines() if l.strip()]
    return lignes[-1][:160] if lignes else ""


def lire_sortie(data):
    """Extrait des résultats de SSLyze : versions acceptées, chiffrements faibles, certificat."""
    resultats = (data or {}).get("server_scan_results") or []
    if not resultats or resultats[0].get("connectivity_status") != "COMPLETED":
        raise InjoignableSSLyze("le site ne répond pas en connexion chiffrée (SSLyze)",
                                _raison((resultats or [{}])[0]))
    scan = resultats[0].get("scan_result") or {}
    acceptees, faibles = [], []
    for cle, nom in VERSIONS.items():
        partie = (scan.get(cle) or {}).get("result") or {}
        suites = [s["cipher_suite"]["name"] for s in partie.get("accepted_cipher_suites") or []]
        if suites:
            acceptees.append(nom)
            faibles += [s for s in suites if any(m in s.upper() for m in FAIBLES)]
    certificat = None
    info = (scan.get("certificate_info") or {}).get("result") or {}
    for deploiement in info.get("certificate_deployments") or []:
        validations = [v.get("was_validation_successful")
                       for v in deploiement.get("path_validation_results") or []]
        chaine = deploiement.get("received_certificate_chain") or [{}]
        emetteur = (chaine[0].get("issuer") or {}).get("rfc4514_string", "")
        # « CN=YE2,O=Let's Encrypt,C=US » -> « Let's Encrypt » : le nom qui parle au patron.
        organisation = [p[2:] for p in emetteur.split(",") if p.startswith("O=")]
        certificat = {"reconnu": any(validations),
                      "fin": chaine[0].get("not_valid_after", ""),
                      "emetteur": organisation[0] if organisation else emetteur}
        break
    return {"versions": acceptees, "faibles": sorted(set(faibles)), "certificat": certificat}


def _un_passage(domaine):
    with tempfile.TemporaryDirectory() as dossier:
        fichier = os.path.join(dossier, "sslyze.json")
        outils.executer("sslyze", ["--quiet", "--json_out", fichier] + CONTROLES
                        + [domaine], delai=180, dossier=dossier)
        try:
            with open(fichier, encoding="utf-8") as lu:
                data = json.load(lu)
        except (OSError, json.JSONDecodeError):
            raise InjoignableSSLyze("SSLyze n'a pas produit de résultat lisible")
    return lire_sortie(data)


def lancer_sslyze(domaine):
    """SSLyze, avec un 2e essai si la connexion a raté. Si elle rate encore alors que Vigie,
    lui, arrive à se connecter en chiffré, on le dit : c'est l'outil ou le réseau qui a
    hoqueté, pas le site (cas réel du 24/11/2026, derrière un pare-feu de labo)."""
    for essai in range(2):
        try:
            return _un_passage(domaine)
        except InjoignableSSLyze as echec:
            derniere = echec
            if essai == 0:
                continue
    if reseau.https_repond(domaine) == reseau.OUI:
        detail = f" ; SSLyze : {derniere.raison}" if derniere.raison else ""
        raise ControleImpossible(
            "SSLyze n'a pas réussi à se connecter, alors que le site répond bien en "
            "connexion chiffrée (vérifié par Vigie) : souci passager du réseau ou de "
            "l'outil, à relancer" + detail)
    raise derniere


def analyser(cible):
    resultat = lancer_sslyze(cible.domaine)
    versions = resultat["versions"]
    constats = []

    cassees = [v for v in versions if v.startswith("SSL")]
    depassees = [v for v in versions if v in ("TLS 1.0", "TLS 1.1")]
    if cassees:
        constats.append(Constat(
            BLOC, CRITIQUE, "Le site accepte un chiffrement cassé (" + ", ".join(cassees) + ")",
            "Ces versions se cassent en quelques heures : un attaquant sur le même réseau "
            "qu'un visiteur peut lire ce qu'il échange avec le site.",
            "Désactiver SSL 2 et SSL 3 chez l'hébergeur.", cle="protocoles_anciens"))
    elif depassees:
        constats.append(Constat(
            BLOC, IMPORTANT, "Le site accepte un chiffrement dépassé (" + ", ".join(depassees) + ")",
            "Les navigateurs ont abandonné ces versions en 2020 pour leurs faiblesses connues.",
            "Désactiver TLS 1.0 et TLS 1.1 chez l'hébergeur.", cle="protocoles_anciens"))
    else:
        constats.append(Constat(BLOC, OK, "Les vieilles versions du chiffrement sont refusées",
                                "Le site n'accepte que des versions sûres.",
                                cle="protocoles_anciens"))

    if versions and "TLS 1.3" not in versions:
        constats.append(Constat(
            BLOC, INFO, "La version la plus récente du chiffrement n'est pas proposée (TLS 1.3)",
            "Ce n'est pas une faille : la version actuelle reste sûre. Mais TLS 1.3 est plus "
            "rapide et plus robuste, et c'est la norme attendue aujourd'hui.",
            "Demander à l'hébergeur d'activer TLS 1.3.", cle="tls13"))

    if resultat["faibles"]:
        constats.append(Constat(
            BLOC, IMPORTANT, "Le site accepte des méthodes de chiffrement faibles",
            "Méthodes acceptées : " + ", ".join(resultat["faibles"][:5]) + ".",
            "Retirer ces méthodes de la configuration du serveur.", cle="chiffrements_faibles"))

    certificat = resultat["certificat"]
    if certificat and not certificat["reconnu"]:
        constats.append(Constat(
            BLOC, CRITIQUE, "Certificat du site non reconnu par les navigateurs",
            "Les navigateurs affichent une alerte de sécurité à vos visiteurs.",
            "Installer un certificat d'une autorité reconnue (Let's Encrypt est gratuit).",
            cle="certificat"))
    elif certificat:
        constats.append(Constat(BLOC, OK, "Certificat valide",
                                f"Délivré par {certificat['emetteur'] or 'une autorité reconnue'}.",
                                cle="certificat"))
    # tlsx, gardé pour ce qu'il est seul à voir (comparaison du 21/11/2026) : le certificat
    # de « www », que le serveur peut servir à part. Un www sans certificat valide = alerte
    # de sécurité pour les visiteurs qui tapent www.
    if outils.disponible("tlsx"):
        www = "www." + cible.domaine
        sortie = outils.executer("tlsx", ["-u", www, "-json", "-silent"], delai=60)
        fiche = next((json.loads(l) for l in (sortie or "").splitlines() if l.startswith("{")), None)
        if fiche:
            noms = [n.lower() for n in (fiche.get("subject_an") or [])]
            couvert = any(n == www or (n.startswith("*.") and www.endswith(n[1:])) for n in noms)
            if couvert and not fiche.get("expired") and not fiche.get("untrusted"):
                constats.append(Constat(BLOC, OK, "Certificat de www valide — vu par tlsx",
                                        "Les visiteurs qui tapent « www » n'ont pas d'alerte.",
                                        cle="certificat_www"))
            else:
                constats.append(Constat(BLOC, IMPORTANT, "Certificat de www absent ou invalide — vu par tlsx",
                                        "Les visiteurs qui tapent « www » devant l'adresse voient "
                                        "une alerte de sécurité.",
                                        "Ajouter www au certificat du site.", cle="certificat_www"))
            resultat["certificat_www"] = {"noms": noms, "couvert": couvert}
    return constats, {"chiffrement": resultat}
