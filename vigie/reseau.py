"""Accès réseau partagés par les modules. Tout ce qui sort vers internet passe ici."""
import json
import re
import urllib.parse
import urllib.request

from .modeles import ControleImpossible

AGENT = "Vigie/0.1 (diagnostic de securite, avec accord du proprietaire)"
RESOLVEURS = ["https://dns.google/resolve", "https://cloudflare-dns.com/dns-query"]
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
