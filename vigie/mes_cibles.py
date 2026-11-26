"""« Mes propres cibles » : ce qui appartient à Anass, prouvé une fois, sans autorisation.

Demande d'Anass (26/11/2026) : tester SON site (pavillon-noir.tech) ou SES machines
virtuelles de labo ne doit pas demander une autorisation signée à lui-même. Mais une
faute de frappe ou un sous-domaine qui pointe chez quelqu'un d'autre ne doit jamais
passer. Donc :

  - Un DOMAINE ne compte que s'il est PROUVÉ : Vigie donne un code, Anass le colle dans
    la zone DNS du domaine (enregistrement TXT), Vigie le lit. Seul le propriétaire du
    domaine peut faire ça. Le code est relu à CHAQUE lancement : s'il disparaît, le
    domaine ne compte plus.
  - Un SOUS-DOMAINE du domaine prouvé ne compte que s'il pointe vers la MÊME machine
    que le domaine (mêmes adresses IP) ou vers une VM déclarée. Un sous-domaine qui
    renvoie vers un autre service (CNAME vers un hébergeur, une boutique en ligne…)
    ou une autre adresse ne compte pas : cette machine-là n'est pas à Anass.
  - Une MACHINE DE LABO (VM) se déclare par son adresse ou son réseau, et seulement des
    adresses PRIVÉES (192.168.x.x, 10.x.x.x, 172.16-31.x.x) : elles ne sont pas sur
    internet, ce ne peut être que du matériel à soi.
  - Une adresse IP publique n'est jamais « à soi » ici (souvent un hébergeur partagé) :
    autorisation signée.
Toute déclaration, preuve ou retrait est noté au journal (journal/mes-cibles.jsonl).
Pour tout le reste, l'autorisation signée reste obligatoire (manuel.py).
"""
import datetime
import ipaddress
import json
import os
import re
import secrets

from . import reseau

FICHIER = "mes-cibles.json"
PREFIXE = "vigie-verification="
DOMAINE = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")


# Les seules plages acceptées pour un labo (RFC 1918 et IPv6 locales). Pas « is_private »
# de Python : il compte aussi les plages de documentation et d'autres cas limites.
LABO = [ipaddress.ip_network(r) for r in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                                          "fc00::/7")]


class Refus(ValueError):
    """Déclaration refusée ou cible non couverte : la raison est en français."""


# ---------------------------------------------------------------------------
# Le fichier
def _chemin(dossier):
    return os.path.join(dossier, FICHIER)


def lire(dossier):
    try:
        with open(_chemin(dossier), encoding="utf-8") as fichier:
            donnees = json.load(fichier)
    except (OSError, ValueError):
        donnees = {}
    donnees.setdefault("domaines", {})
    donnees.setdefault("reseaux", [])
    return donnees


def _ecrire(dossier, donnees):
    os.makedirs(dossier, exist_ok=True)
    temporaire = _chemin(dossier) + ".tmp"
    with open(temporaire, "w", encoding="utf-8") as fichier:
        json.dump(donnees, fichier, ensure_ascii=False, indent=2)
    os.replace(temporaire, _chemin(dossier))


def _maintenant():
    return datetime.datetime.now().isoformat(timespec="seconds")


def _noter(journal, entree):
    os.makedirs(journal, exist_ok=True)
    with open(os.path.join(journal, "mes-cibles.jsonl"), "a", encoding="utf-8") as fichier:
        fichier.write(json.dumps(dict(entree, quand=_maintenant()), ensure_ascii=False) + "\n")


ATTESTATION = "je suis propriétaire de cette cible ou j'en ai la responsabilité"


# ---------------------------------------------------------------------------
# Déclarer
def nettoyer_domaine(texte):
    domaine = (texte or "").strip().lower()
    domaine = re.sub(r"^[a-z]+://", "", domaine).split("/")[0].split(":")[0].strip(".")
    if domaine.startswith("www."):
        domaine = domaine[4:]
    if not DOMAINE.fullmatch(domaine):
        raise Refus(f"« {texte} » n'est pas un nom de domaine (exemple : mon-site.fr).")
    return domaine


def ajouter_domaine(dossier, journal, texte):
    """Déclare un domaine (pas encore prouvé). Renvoie (domaine, valeur TXT à poser)."""
    domaine = nettoyer_domaine(texte)
    donnees = lire(dossier)
    fiche = donnees["domaines"].get(domaine)
    if not fiche:
        fiche = {"jeton": PREFIXE + secrets.token_hex(16), "prouve_le": "",
                 "declare_le": _maintenant()}
        donnees["domaines"][domaine] = fiche
        _ecrire(dossier, donnees)
        _noter(journal, {"action": "domaine déclaré", "cible": domaine,
                         "attestation": ATTESTATION})
    return domaine, fiche["jeton"]


def _txt(domaine, resoudre):
    return [t.strip() for t in resoudre(domaine, "TXT")]


def prouver_domaine(dossier, journal, domaine, resoudre=reseau.dns):
    """Lit le DNS : le code est-il posé ? Renvoie True, ou lève Refus (en français)."""
    domaine = nettoyer_domaine(domaine)
    donnees = lire(dossier)
    fiche = donnees["domaines"].get(domaine)
    if not fiche:
        raise Refus(f"{domaine} n'est pas dans tes cibles : ajoute-le d'abord.")
    try:
        trouves = _txt(domaine, resoudre)
    except reseau.ErreurReseau as erreur:
        raise Refus(f"Vigie n'arrive pas à lire le DNS de {domaine} ({erreur}). "
                    "Vérifie la connexion internet et réessaie.") from erreur
    if fiche["jeton"] not in trouves:
        raise Refus(f"Le code n'est pas (encore) dans le DNS de {domaine}. Ajoute chez ton "
                    f"hébergeur un enregistrement TXT sur « {domaine} » avec la valeur "
                    f"« {fiche['jeton']} ». Un changement DNS peut mettre de quelques "
                    "minutes à une heure à se voir.")
    fiche["prouve_le"] = _maintenant()
    _ecrire(dossier, donnees)
    _noter(journal, {"action": "domaine prouvé (code DNS lu)", "cible": domaine,
                     "attestation": ATTESTATION})
    return True


def ajouter_reseau(dossier, journal, texte):
    """Déclare une VM ou un réseau de labo : adresses PRIVÉES seulement."""
    try:
        reseau_ip = ipaddress.ip_network((texte or "").strip(), strict=False)
    except ValueError as erreur:
        raise Refus(f"« {texte} » n'est pas une adresse ou un réseau (exemple : "
                    "192.168.56.10 ou 192.168.56.0/24).") from erreur
    if not any(reseau_ip.version == p.version and reseau_ip.subnet_of(p) for p in LABO):
        raise Refus(f"{reseau_ip} n'est pas une adresse privée. Seules les adresses de "
                    "labo (192.168.x.x, 10.x.x.x, 172.16 à 172.31.x.x) peuvent être "
                    "déclarées ici. Une adresse publique demande une autorisation signée.")
    donnees = lire(dossier)
    texte_reseau = str(reseau_ip)
    if texte_reseau not in donnees["reseaux"]:
        donnees["reseaux"].append(texte_reseau)
        _ecrire(dossier, donnees)
        _noter(journal, {"action": "réseau de labo déclaré", "cible": texte_reseau,
                         "attestation": ATTESTATION})
    return texte_reseau


def retirer(dossier, journal, cible):
    donnees = lire(dossier)
    if cible in donnees["domaines"]:
        del donnees["domaines"][cible]
    elif cible in donnees["reseaux"]:
        donnees["reseaux"].remove(cible)
    else:
        return False
    _ecrire(dossier, donnees)
    _noter(journal, {"action": "retiré", "cible": cible})
    return True


# ---------------------------------------------------------------------------
# Vérifier une cible au moment de lancer
def _dans_reseaux(ip, reseaux):
    return any(ip in ipaddress.ip_network(r) for r in reseaux)


def _adresses(nom, resoudre):
    adresses = set()
    for typ in ("A", "AAAA"):
        for valeur in resoudre(nom, typ):
            try:
                adresses.add(ipaddress.ip_address(valeur.strip()))
            except ValueError:
                continue
    return adresses


def raison_refus(dossier, cible, resoudre=reseau.dns):
    """None si la cible est à Anass (prouvé maintenant), sinon la raison en français."""
    cible = (cible or "").strip().lower().strip(".")
    donnees = lire(dossier)
    # 1. Une adresse IP : seulement dans un réseau de labo déclaré.
    try:
        ip = ipaddress.ip_address(cible)
    except ValueError:
        ip = None
    if ip is not None:
        if _dans_reseaux(ip, donnees["reseaux"]):
            return None
        return (f"{cible} n'est pas dans tes réseaux de labo déclarés. Une adresse "
                "publique demande une autorisation signée.")
    # 2. Un nom : il faut un domaine prouvé qui le contient.
    racine = next((d for d in sorted(donnees["domaines"], key=len, reverse=True)
                   if cible == d or cible.endswith("." + d)), None)
    if not racine:
        return f"{cible} n'est pas dans tes propres cibles : autorisation signée obligatoire."
    fiche = donnees["domaines"][racine]
    if not fiche.get("prouve_le"):
        return (f"{racine} est déclaré mais pas encore prouvé : pose le code DNS et "
                "clique sur « Vérifier ».")
    try:
        # Le code doit TOUJOURS être là : relu à chaque lancement.
        if fiche["jeton"] not in _txt(racine, resoudre):
            return (f"Le code de preuve n'est plus dans le DNS de {racine} : le domaine ne "
                    "compte plus comme le tien. Remets-le, puis « Vérifier ».")
        # Pas de renvoi vers un service extérieur (CNAME hors du domaine prouvé).
        for alias in resoudre(cible, "CNAME"):
            alias = alias.strip().lower().rstrip(".")
            if alias and alias != racine and not alias.endswith("." + racine):
                return (f"{cible} renvoie vers {alias}, un service qui n'est pas à toi "
                        "(hébergeur, boutique en ligne…). Il faut l'autorisation de ce "
                        "service.")
        if cible == racine:
            return None
        # Un sous-domaine : mêmes machines que le domaine prouvé, ou une VM déclarée.
        a_tester = _adresses(cible, resoudre)
        if not a_tester:
            return f"{cible} ne pointe vers aucune adresse : rien à tester."
        connues = _adresses(racine, resoudre)
        etrangeres = [str(a) for a in a_tester
                      if a not in connues and not _dans_reseaux(a, donnees["reseaux"])]
        if etrangeres:
            return (f"{cible} pointe vers {', '.join(sorted(etrangeres))}, une autre machine "
                    f"que {racine}. Rien ne prouve qu'elle est à toi : autorisation signée "
                    "obligatoire.")
    except reseau.ErreurReseau as erreur:
        return f"Vigie n'arrive pas à lire le DNS ({erreur}) : impossible de prouver."
    return None
