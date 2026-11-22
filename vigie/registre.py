"""Le registre de TOUS les outils du catalogue (222), lu depuis docs_outils.json.

But : que Vigie connaisse chaque outil non payant — sa famille, comment l'installer,
comment le lancer — pour pouvoir le lancer un par un (voir interface_manuel.py) et
afficher sa sortie en français. Vigie n'embarque toujours aucun code d'outil : il les
appelle s'ils sont installés (voir outils.executer).

Les quatre familles (voir chantier/synthese_familles.md) décident des garde-fous :
  - diag  : OSINT passif / public -> lançable seul sans autorisation.
  - secu  : défensif / durcissement, tourne sur SA machine -> lançable seul.
  - audit : scan ACTIF sur la cible -> autorisation signée obligatoire (manuel.py).
  - gate  : offensif -> autorisation signée, jamais en auto ni en gratuit.

Les outils PAYANTS (ou à compte perso payant) sont marqués et NON installés.

    python3 -m vigie registre            # tout, par famille
    python3 -m vigie registre audit      # une famille
"""
import json
import os
import sys

_ICI = os.path.dirname(__file__)
_DOCS = os.path.join(_ICI, "docs_outils.json")

# facette (taguée au chantier) -> famille. Repris de chantier/familles.py (source unique).
MAP = {
    "urls": "diag", "domaines": "diag", "pseudos": "diag", "email": "diag",
    "instagram": "diag", "telephone": "diag", "documents": "diag", "darkweb": "diag",
    "geoloc": "diag", "ip": "diag", "easm": "diag", "metadonnees": "diag",
    "verification": "diag", "graphe": "diag", "archivage": "diag", "dns": "diag",
    "ports": "audit", "failles": "audit", "web-scanner": "audit", "tls": "audit",
    "cloud": "audit", "kubernetes": "audit", "iac": "audit", "conformite": "audit",
    "sbom": "audit", "dependances": "audit", "azure": "audit", "m365": "audit",
    "azure-ad": "audit", "audit-ad": "audit", "audit-mdp": "audit", "reseau": "audit",
    "reseau-local": "audit", "fingerprinting": "audit", "multi": "audit", "crawl": "audit",
    "params": "audit", "js": "audit", "web-proxy": "audit", "proxy": "audit",
    "fuzzing": "audit", "secrets": "audit", "sbom ": "audit",
    "durcissement": "secu", "pare-feu": "secu", "waf": "secu", "ids": "secu",
    "ips": "secu", "honeypot": "secu", "edr": "secu", "siem": "secu", "antivirus": "secu",
    "detection": "secu", "runtime": "secu", "journalisation": "secu", "supervision": "secu",
    "supervision-reseau": "secu", "threat-hunting": "secu", "nsm": "secu",
    "detection-malware": "secu", "chiffrement": "secu", "sast-ia": "secu",
    "sensibilisation": "secu", "audit-code-ia": "secu", "analyse-donnees": "secu",
    "capture-reseau": "secu", "analyse-reseau": "secu", "reverse-engineering": "secu",
    "forensic-disque": "secu", "forensic-memoire": "secu", "dfir-endpoint": "secu",
    "dfir-triage": "secu", "dfir-timeline": "secu", "dfir-artefacts": "secu", "code": "secu",
    "serveur-web": "secu", "ia-supply-chain": "secu", "llm-scan": "secu", "cti": "secu",
    "audit-wifi": "secu",
    "offensif": "gate", "offensif-ad": "gate", "offensif-agent": "gate",
    "offensif-wifi": "gate", "offensif-mdp": "gate", "offensif-assistant": "gate",
    "offensif-test": "gate", "offensif-dangereux": "gate", "osint-offensif": "gate",
    "bruteforce": "gate", "privesc": "gate", "exploitation": "gate", "sqli": "gate",
    "rce": "gate", "xss": "gate", "ssrf": "gate", "mitm": "gate", "jwt": "gate",
    "oob": "gate", "exploits": "gate", "wordpress": "gate", "mdp": "gate",
    "hash-id": "gate", "wordlists": "gate", "llm-redteam": "gate", "orchestrateur": "gate",
}

FAMILLES = {
    "diag": "Diagnostic gratuit (OSINT passif, public)",
    "audit": "Audit (scan actif, sur autorisation signée)",
    "secu": "Sécurisation (défensif, durcissement, forensic)",
    "gate": "Offensif (autorisation signée, jamais en auto ni en gratuit)",
}
ORDRE = ["diag", "audit", "secu", "gate"]

# Outils payants ou à compte/jeton payant : connus de Vigie mais NON installés ni lancés.
PAYANTS = {"uncover", "robin", "snyk", "pentagi"}


def _est_payant(outil):
    nom = (outil.get("nom") or "").strip().lower()
    cle = (outil.get("cle_api") or "").lower()
    if nom in PAYANTS:
        return True
    # Jeton explicitement payant (Snyk) ou accès obligatoire type dark web payant.
    return "token snyk" in cle or cle.startswith("oui, obligatoire")


def charger(chemin=_DOCS):
    """Renvoie la liste des outils enrichis (famille, flags). Les introuvables sont ôtés."""
    with open(chemin, encoding="utf-8") as fichier:
        brut = json.load(fichier)
    outils = brut if isinstance(brut, list) else brut.get("outils", [])
    registre = []
    for o in outils:
        if o.get("statut") == "introuvable":
            continue
        famille = MAP.get(o.get("facette", ""), "audit")   # défaut prudent : autorisation
        payant = _est_payant(o)
        registre.append({
            "nom": o.get("nom", "?"),
            "lien": o.get("lien", ""),
            "categorie": o.get("categorie", ""),
            "facette": o.get("facette", ""),
            "famille": famille,
            "install": o.get("install", ""),
            "usage": o.get("usage", ""),
            "cle_api": o.get("cle_api", "non"),
            "payant": payant,
            # Garde-fous : qui exige une autorisation signée, qui est offensif.
            "actif": famille in ("audit", "gate"),
            "attaque": famille == "gate",
            "autorisation_requise": famille in ("audit", "gate"),
            # Installable par Vigie = non payant et trouvé.
            "installable": not payant,
        })
    return registre


def non_payants(chemin=_DOCS):
    return [o for o in charger(chemin) if not o["payant"]]


def par_famille(chemin=_DOCS):
    groupes = {f: [] for f in ORDRE}
    for o in charger(chemin):
        groupes.setdefault(o["famille"], []).append(o)
    return groupes


def _principal(argv):
    groupes = par_famille()
    familles = argv or ORDRE
    total, payants = 0, 0
    for f in familles:
        liste = sorted(groupes.get(f, []), key=lambda x: x["nom"].lower())
        print(f"\n=== {FAMILLES.get(f, f)}  ({len(liste)}) ===")
        for o in liste:
            marques = []
            if o["payant"]:
                marques.append("PAYANT"); payants += 1
            if o["attaque"]:
                marques.append("offensif")
            elif o["autorisation_requise"]:
                marques.append("autorisation")
            total += 1
            suffixe = f"  [{', '.join(marques)}]" if marques else ""
            print(f"  - {o['nom']}{suffixe}")
    print(f"\n{total} outils ({payants} payants, non installés).")
    return 0


if __name__ == "__main__":
    raise SystemExit(_principal(sys.argv[1:]))
