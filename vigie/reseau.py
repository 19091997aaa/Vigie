"""Accès réseau partagés par les modules. Tout ce qui sort vers internet passe ici."""
import json
import re
import socket
import ssl
import urllib.parse
import urllib.request

from .modeles import ControleImpossible

AGENT = "Vigie/0.1 (diagnostic de securite, avec accord du proprietaire)"
RESOLVEURS = ["https://dns.google/resolve", "https://cloudflare-dns.com/dns-query"]
# Les mêmes résolveurs publics, pour les outils externes (dnstwist, checkdmarc).
# Sans eux, les outils passent par la box internet : elle met jusqu'à 2 secondes par
# question et ne tient pas les milliers de questions de dnstwist (essai réel du
# 21/11/2026 : plus de 10 minutes avec la box, 13 secondes avec ces résolveurs).
SERVEURS_DNS = ["8.8.8.8", "1.1.1.1"]
TYPES_DNS = {"TXT": 16, "MX": 15, "CNAME": 5, "A": 1}


class ErreurReseau(ControleImpossible):
    """Le contrôle n'a pas pu être fait (pas d'internet, service indisponible)."""


def _nettoie_txt(donnee):
    morceaux = re.findall(r'"((?:[^"\\]|\\.)*)"', donnee)
    return "".join(morceaux) if morceaux else donnee


def dns(nom, typ):
    """Lit le DNS public d'un nom. Lecture seule, rien n'est envoyé au domaine testé."""
    derniere_erreur = None
    for base in RESOLVEURS:
        url = base + "?" + urllib.parse.urlencode({"name": nom, "type": typ})
        requete = urllib.request.Request(url, headers={"accept": "application/dns-json",
                                                       "User-Agent": AGENT})
        try:
            with urllib.request.urlopen(requete, timeout=10) as reponse:
                data = json.load(reponse)
        except Exception as erreur:
            derniere_erreur = erreur
            continue
        resultats = []
        for ligne in data.get("Answer") or []:
            if ligne.get("type") == TYPES_DNS[typ]:
                valeur = ligne.get("data", "")
                resultats.append(_nettoie_txt(valeur) if typ == "TXT" else valeur)
        return resultats
    raise ErreurReseau(f"DNS injoignable : {derniere_erreur}")


# Réponses possibles de https_repond().
OUI, NON, INCONNU = "oui", "non", "inconnu"


def _poignee_tls(hote, delai):
    """Une poignée de main chiffrée sur le port 443, comme un navigateur qui arrive.

    Le certificat n'est PAS vérifié ici : on veut seulement savoir si l'adresse parle
    en chiffré. Un certificat faux est un autre problème, relevé par d'autres contrôles.
    """
    contexte = ssl.create_default_context()
    contexte.check_hostname = False
    contexte.verify_mode = ssl.CERT_NONE
    with socket.create_connection((hote, 443), timeout=delai) as brut:
        with contexte.wrap_socket(brut, server_hostname=hote):
            return True


def https_repond(hote, essais=2, delai=10):
    """L'adresse répond-elle en connexion chiffrée (HTTPS) ? Vérification de Vigie lui-même.

    Sert à recouper un outil qui dit « pas chiffré » ou « injoignable » avant d'en faire
    un constat (cas réel du 24/11/2026 : httpx disait www non chiffré alors que le
    certificat et la redirection étaient bons). Réponses :
      OUI     : la poignée de main chiffrée a réussi ;
      NON     : refus net, deux fois (rien n'écoute en chiffré, ou le serveur parle en clair) ;
      INCONNU : pas de réponse claire (délai dépassé, réseau coupé) : à confirmer.
    """
    refus = 0
    for _ in range(max(1, essais)):
        try:
            if _poignee_tls(hote, delai):
                return OUI
        except ConnectionRefusedError:
            refus += 1
        except ssl.SSLError as erreur:
            # « wrong version number » : le port 443 répond, mais en clair.
            if "wrong version number" in str(erreur).lower() or "http request" in str(erreur).lower():
                refus += 1
        except OSError:
            pass  # délai dépassé, nom introuvable, réseau coupé : on ne conclut pas
    return NON if refus >= max(1, essais) else INCONNU
