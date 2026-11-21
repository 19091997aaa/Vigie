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

from .. import outils
from ..modeles import CRITIQUE, IMPORTANT, INFO, OK, Constat, ControleImpossible

BLOC = "Exposition"
# Réglages passés à SSLyze : versions du chiffrement et certificat, rien d'autre.
CONTROLES = ["--certinfo", "--sslv2", "--sslv3", "--tlsv1", "--tlsv1_1", "--tlsv1_2",
             "--tlsv1_3"]
VERSIONS = {"ssl_2_0_cipher_suites": "SSL 2", "ssl_3_0_cipher_suites": "SSL 3",
            "tls_1_0_cipher_suites": "TLS 1.0", "tls_1_1_cipher_suites": "TLS 1.1",
            "tls_1_2_cipher_suites": "TLS 1.2", "tls_1_3_cipher_suites": "TLS 1.3"}
FAIBLES = ("RC4", "3DES", "_DES_", "NULL", "EXPORT", "ANON", "MD5")


def lire_sortie(data):
    """Extrait des résultats de SSLyze : versions acceptées, chiffrements faibles, certificat."""
    resultats = (data or {}).get("server_scan_results") or []
    if not resultats or resultats[0].get("connectivity_status") != "COMPLETED":
        raise ControleImpossible("le site ne répond pas en connexion chiffrée (SSLyze)")
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


def analyser(cible):
    with tempfile.TemporaryDirectory() as dossier:
        fichier = os.path.join(dossier, "sslyze.json")
        outils.executer("sslyze", ["--quiet", "--json_out", fichier] + CONTROLES
                        + [cible.domaine], delai=180, dossier=dossier)
        try:
            with open(fichier, encoding="utf-8") as lu:
                data = json.load(lu)
        except (OSError, json.JSONDecodeError):
            raise ControleImpossible("SSLyze n'a pas produit de résultat lisible")
    resultat = lire_sortie(data)
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
    return constats, {"chiffrement": resultat}
