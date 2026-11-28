"""Traduire les outils d'audit ACTIF en français de patron.

Ces outils (naabu, nuclei, sslscan) touchent la machine visée : Vigie ne les lance
JAMAIS tout seul ni dans le diagnostic gratuit. Ils ne partent que par les « outils
manuels » (manuel.py), après autorisation signée. Ce fichier ne lance rien : il lit
seulement le fichier de sortie déjà produit et le réécrit en clair, comme ports.py
le fait pour Nmap.

    python3 -m vigie.audit_actif naabu  sortie.json
    python3 -m vigie.audit_actif nuclei sortie.jsonl
    python3 -m vigie.audit_actif sslscan sortie.xml
"""
import json
import sys
import xml.etree.ElementTree as ET

from .modeles import CRITIQUE, IMPORTANT, INFO, OK
from .ports import INCONNU, PORTS

ORDRE = {CRITIQUE: 0, IMPORTANT: 1, INFO: 2, OK: 3}


def _lignes_triees(lignes):
    """lignes : [(niveau, texte)]. Trié du plus grave au moins grave, doublons ôtés."""
    vus, propres = set(), []
    for niveau, texte in lignes:
        if texte not in vus:
            vus.add(texte)
            propres.append((niveau, texte))
    return sorted(propres, key=lambda l: ORDRE[l[0]])


# --- naabu : des portes ouvertes sur la cible -------------------------------
def traduire_naabu(chemin):
    """Sortie naabu (-json : un objet par ligne {ip, host, port}) -> français.

    naabu dit seulement QUELLES portes sont ouvertes (pas le service). On réutilise
    le dictionnaire de ports de ports.py pour expliquer chaque porte au dirigeant.
    """
    lignes = []
    with open(chemin, encoding="utf-8") as fichier:
        for brute in fichier:
            brute = brute.strip()
            if not brute:
                continue
            try:
                enregistrement = json.loads(brute)
            except json.JSONDecodeError:
                continue
            port = enregistrement.get("port")
            if isinstance(port, dict):            # certaines versions : {"port": {"Port": 443}}
                port = port.get("Port") or port.get("port")
            if not isinstance(port, int):
                continue
            qui = enregistrement.get("host") or enregistrement.get("ip") or "la cible"
            niveau, quoi, pourquoi = PORTS.get(port, INCONNU)
            lignes.append((niveau, f"{qui} : porte {port}, {quoi}. {pourquoi}"))
    return _lignes_triees(lignes)


# --- nuclei : des failles connues -------------------------------------------
# Gravité nuclei -> niveau Vigie. « info » reste INFO (utile, pas une faille).
GRAVITE = {"critical": CRITIQUE, "high": CRITIQUE, "medium": IMPORTANT,
           "low": INFO, "info": INFO, "unknown": INFO}


def traduire_nuclei(chemin):
    """Sortie nuclei (-jsonl : un résultat par ligne) -> français.

    Chaque ligne est une faille ou un point relevé sur la cible. On garde le nom du
    modèle (ce qui a été trouvé) et l'endroit, en français simple.
    """
    lignes = []
    with open(chemin, encoding="utf-8") as fichier:
        for brute in fichier:
            brute = brute.strip()
            if not brute:
                continue
            try:
                res = json.loads(brute)
            except json.JSONDecodeError:
                continue
            info = res.get("info") or {}
            gravite = (info.get("severity") or "unknown").lower()
            niveau = GRAVITE.get(gravite, INFO)
            nom = info.get("name") or res.get("template-id") or "point relevé"
            ou = res.get("matched-at") or res.get("host") or ""
            detail = f" ({ou})" if ou else ""
            lignes.append((niveau, f"{nom}{detail}"))
    return _lignes_triees(lignes)


# --- sslscan : les versions du chiffrement acceptées ------------------------
FAIBLES = ("RC4", "3DES", "DES", "NULL", "EXP", "ANON", "MD5")
# Protocoles trop vieux : les accepter est un défaut.
VIEUX = {"SSLv2": CRITIQUE, "SSLv3": CRITIQUE, "TLSv1.0": IMPORTANT, "TLSv1.1": IMPORTANT}


def traduire_sslscan(chemin):
    """Sortie sslscan (--xml=-) -> français : vieux protocoles et chiffrements faibles.

    Comme sslyze mais en version active. On signale les protocoles périmés encore
    acceptés et les chiffrements faibles. Rien d'offensif : on lit ce que le serveur
    propose à un visiteur.
    """
    lignes = []
    try:
        racine = ET.parse(chemin).getroot()  # nosemgrep : fichier produit localement
    except ET.ParseError:
        return []
    acceptes_vieux, faibles = [], set()
    for test in racine.iter("protocol"):
        version = f"{test.get('type', '').upper().replace('TLS', 'TLSv').replace('SSL', 'SSLv')}{test.get('version', '')}"
        # Normalise « tls 1.0 » / « ssl 3 » en TLSv1.0 / SSLv3.
        brut = (test.get("type", "") + test.get("version", "")).lower()
        cle = {"tls1.0": "TLSv1.0", "tls1.1": "TLSv1.1", "tls1.2": "TLSv1.2",
               "tls1.3": "TLSv1.3", "ssl2": "SSLv2", "ssl3": "SSLv3"}.get(brut)
        if test.get("enabled") == "1" and cle in VIEUX:
            acceptes_vieux.append(cle)
    for cipher in racine.iter("cipher"):
        if cipher.get("status") in ("accepted", "preferred"):
            nom = (cipher.get("cipher") or "").upper()
            if any(f in nom for f in FAIBLES):
                faibles.add(cipher.get("cipher"))
    for version in sorted(set(acceptes_vieux), key=lambda v: ORDRE[VIEUX[v]]):
        lignes.append((VIEUX[version],
                        f"Le site accepte encore {version}, une version du chiffrement périmée. "
                        "À désactiver : un visiteur peut être forcé de l'utiliser."))
    for nom in sorted(faibles):
        lignes.append((IMPORTANT, f"Chiffrement faible accepté : {nom}. À retirer."))
    if not lignes:
        lignes.append((OK, "Aucune version périmée ni chiffrement faible détecté."))
    return _lignes_triees(lignes)


TRADUCTEURS = {"naabu": traduire_naabu, "nuclei": traduire_nuclei, "sslscan": traduire_sslscan}


def _principal(argv):
    if len(argv) != 2 or argv[0] not in TRADUCTEURS:
        print("usage : python3 -m vigie.audit_actif {naabu|nuclei|sslscan} <fichier>")
        return 1
    for niveau, texte in TRADUCTEURS[argv[0]](argv[1]):
        print(f"[{niveau}] {texte}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_principal(sys.argv[1:]))
