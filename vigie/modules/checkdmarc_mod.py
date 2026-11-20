"""Bloc Exposition - réglages mail, deuxième source : l'outil checkdmarc.

Il recoupe Vigie sur SPF et DMARC, et regarde EN PLUS des facettes que Vigie
ne couvre pas (MTA-STS, DNSSEC, rapports TLS). C'est tout l'intérêt de la
comparaison : voir ce qu'un deuxième outil apporte.

Les clés (cle=) sont les mêmes que le module mail pour les facettes communes,
pour que la convergence et la comparaison les rapprochent.
"""
import json

from .. import outils
from ..modeles import CRITIQUE, IMPORTANT, INFO, OK, Constat, ControleImpossible

BLOC = "Exposition"
RESEAU_HS = ("unreachable", "failed to answer", "timeout", "timed out")


def _erreur_reseau(champ):
    err = (champ or {}).get("error") or ""
    return any(motif in err.lower() for motif in RESEAU_HS)


def lire_sortie(texte):
    try:
        return json.loads(texte)
    except (json.JSONDecodeError, TypeError):
        raise ControleImpossible("checkdmarc n'a pas renvoyé de résultat lisible")


def analyser(cible):
    sortie = outils.executer("checkdmarc", ["--format", "json", cible.domaine], delai=120)
    data = lire_sortie(sortie)
    # Si tout échoue au réseau, ce n'est pas un défaut du domaine : contrôle non réalisé.
    if _erreur_reseau(data.get("spf")) and _erreur_reseau(data.get("dmarc")):
        raise ControleImpossible("checkdmarc n'a pas pu interroger le DNS du domaine")

    constats = []

    spf = data.get("spf") or {}
    if spf.get("record"):
        regle = spf["record"].lower()
        if "-all" in regle:
            constats.append(Constat(BLOC, OK, "SPF strict (-all) — vu par checkdmarc",
                                    "Les expéditeurs non listés sont refusés.", cle="spf"))
        else:
            constats.append(Constat(BLOC, INFO, "SPF présent mais non strict — vu par checkdmarc",
                                    "La règle n'interdit pas clairement les expéditeurs inconnus.",
                                    "Terminer l'enregistrement SPF par -all.", cle="spf"))
    elif not _erreur_reseau(spf):
        constats.append(Constat(BLOC, CRITIQUE, "SPF absent — vu par checkdmarc",
                                "Aucune liste des serveurs autorisés à écrire en votre nom.",
                                "Publier un enregistrement SPF.", cle="spf"))

    dmarc = data.get("dmarc") or {}
    if dmarc.get("record"):
        politique = ((dmarc.get("tags") or {}).get("p") or {}).get("value", "").lower()
        if politique == "reject":
            constats.append(Constat(BLOC, OK, "DMARC en blocage — vu par checkdmarc",
                                    "Les faux mails à votre nom sont refusés.", cle="dmarc"))
        elif politique in ("quarantine", "none", ""):
            constats.append(Constat(BLOC, IMPORTANT, "DMARC présent mais pas en blocage — vu par checkdmarc",
                                    f"Politique actuelle : {politique or 'non précisée'}.",
                                    "Viser p=reject après lecture des rapports.", cle="dmarc"))
    elif not _erreur_reseau(dmarc):
        constats.append(Constat(BLOC, CRITIQUE, "DMARC absent — vu par checkdmarc",
                                "Rien n'ordonne aux messageries de bloquer les faux mails à votre nom.",
                                "Publier un enregistrement DMARC.", cle="dmarc"))

    # Facettes que Vigie natif ne regarde pas : c'est là que checkdmarc apporte en plus.
    mta = data.get("mta_sts") or {}
    if not _erreur_reseau(mta):
        if mta.get("valid"):
            constats.append(Constat(BLOC, OK, "MTA-STS en place — vu par checkdmarc",
                                    "Vos mails entrants sont forcés en connexion chiffrée.", cle="mta_sts"))
        else:
            constats.append(Constat(BLOC, INFO, "MTA-STS absent — vu par checkdmarc",
                                    "Rien ne force vos mails entrants à passer en chiffré.",
                                    "Publier une politique MTA-STS.", cle="mta_sts"))

    if data.get("dnssec") is False:
        constats.append(Constat(BLOC, INFO, "DNSSEC non activé — vu par checkdmarc",
                                "Votre zone DNS n'est pas signée : un attaquant peut plus "
                                "facilement en falsifier les réponses.",
                                "Activer DNSSEC chez votre hébergeur DNS.", cle="dnssec"))

    tlsrpt = data.get("smtp_tls_reporting") or {}
    if not _erreur_reseau(tlsrpt) and not tlsrpt.get("valid"):
        constats.append(Constat(BLOC, INFO, "Pas de rapport TLS mail (TLS-RPT) — vu par checkdmarc",
                                "Vous n'êtes pas alerté si la livraison chiffrée de vos mails échoue.",
                                "Publier un enregistrement TLS-RPT.", cle="tls_rpt"))

    return constats, {"checkdmarc": data}
