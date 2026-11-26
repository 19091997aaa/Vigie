"""SpiderFoot piloté par Vigie : des sources publiques choisies, et un résumé en français.

SpiderFoot (licence MIT, github.com/smicallef/spiderfoot) rassemble à lui seul plus de
200 sources de renseignement. Vigie ne copie pas son code : il lance le SpiderFoot
installé (recettes.py : lanceur « spiderfoot » = sf.py du dépôt officiel) en ligne de
commande, sur une liste FERMÉE de sources, puis traduit sa sortie JSON en français.

Pourquoi une liste fermée : la plupart des 230 modules sortent des règles de Vigie.
  - fuites de données et dark web (Have I Been Pwned, Dehashed, Ahmia, Tor…) : interdit
    tant que le client n'a pas prouvé qu'il contrôle son domaine (MARCHE.md §2) ;
  - scans actifs ou attaques (ports, force brute DNS, transfert de zone, nmap, nuclei) ;
  - données personnelles (e-mails, noms, comptes de réseaux sociaux, téléphones) ;
  - clé API obligatoire, ou trop lents pour un lancement à la demande.
Restent 25 sources gratuites, sans clé, qui ne touchent la cible que comme un simple
visiteur (lire son certificat, résoudre ses noms) : noms et adresses, hébergeur, bureau
d'enregistrement, faux domaines qui imitent le vrai, sous-domaines détournables, et
présence sur les listes noires (spam, hameçonnage, logiciels malveillants).

Le scan reste aussi dans la base de SpiderFoot : son interface (onglet « Ouvrir un
outil », SpiderFoot, puis « Scans ») le montre en entier, avec ses graphiques.
"""
import json
import os
import re
import sqlite3
import subprocess
from contextlib import closing

# --- Les 25 sources gardées (vérifiées dans SpiderFoot 4.0.0, le 26/11/2026) --------
MODULES = (
    # Noms et adresses du domaine : DNS public, certificats publiés, DNS « passif ».
    "sfp_dnsresolve", "sfp_dnsraw", "sfp_crt", "sfp_dnsdumpster", "sfp_robtex",
    "sfp_mnemonic", "sfp_threatminer", "sfp_urlscan",
    # Qui a enregistré le domaine, qui l'héberge.
    "sfp_whois", "sfp_bgpview", "sfp_hosting",
    # Certificat HTTPS, faux domaines qui imitent le vrai, sous-domaines détournables.
    "sfp_sslcert", "sfp_similar", "sfp_subdomain_takeover",
    # Listes noires : spam, hameçonnage, logiciels malveillants.
    "sfp_spamhaus", "sfp_sorbs", "sfp_spamcop", "sfp_uceprotect", "sfp_surbl",
    "sfp_phishtank", "sfp_openphish", "sfp_threatfox", "sfp_quad9", "sfp_cloudflaredns",
    "sfp_opendns",
)

# Écartés exprès (pour qu'on ne les rajoute pas par erreur), avec la raison.
ECARTES = {
    "fuites de données ou dark web : interdit à froid (MARCHE.md §2)": (
        "sfp_haveibeenpwned", "sfp_dehashed", "sfp_psbdmp", "sfp_wikileaks",
        "sfp_leakix", "sfp_citadel", "sfp_trashpanda", "sfp_zoneh", "sfp_ahmia",
        "sfp_torch", "sfp_onionsearchengine"),
    "scan actif ou attaque": (
        "sfp_portscan_tcp", "sfp_dnsbrute", "sfp_dnszonexfer", "sfp_junkfiles",
        "sfp_tool_nmap", "sfp_tool_nuclei"),
    "données personnelles (e-mails, noms, comptes, téléphones)": (
        "sfp_email", "sfp_emailformat", "sfp_names", "sfp_accounts", "sfp_social",
        "sfp_hunter", "sfp_filemeta", "sfp_flickr", "sfp_myspace"),
    "trop lent pour un lancement à la demande": (
        "sfp_archiveorg", "sfp_tldsearch", "sfp_spider", "sfp_dnscommonsrv"),
}

# Ce que SpiderFoot écrit à l'écran (option -F) : seulement ce que Vigie résume, avec
# son libellé dans la sortie JSON. Jamais les données brutes (WHOIS complet, réponses
# des API, certificat entier) : elles peuvent contenir le nom ou le téléphone d'une
# personne, et Vigie ne liste jamais de données personnelles.
LIBELLES = {
    "INTERNET_NAME": "Internet Name",
    "INTERNET_NAME_UNRESOLVED": "Internet Name - Unresolved",
    "DOMAIN_NAME": "Domain Name",
    "IP_ADDRESS": "IP Address",
    "IPV6_ADDRESS": "IPv6 Address",
    "INTERNAL_IP_ADDRESS": "IP Address - Internal Network",
    "PROVIDER_HOSTING": "Hosting Provider",
    "PROVIDER_MAIL": "Email Gateway (DNS 'MX' Records)",
    "PROVIDER_DNS": "Name Server (DNS 'NS' Records)",
    "DOMAIN_REGISTRAR": "Domain Registrar",
    "BGP_AS_MEMBER": "BGP AS Membership",
    "NETBLOCK_MEMBER": "Netblock Membership",
    "SIMILARDOMAIN": "Similar Domain",
    "CO_HOSTED_SITE": "Co-Hosted Site",
    "DNS_SPF": "DNS SPF Record",
    "DNS_TEXT": "DNS TXT Record",
    "WEBSERVER_BANNER": "Web Server",
    "TCP_PORT_OPEN": "Open TCP Port",
    "SSL_CERTIFICATE_ISSUED": "SSL Certificate - Issued to",
    "SSL_CERTIFICATE_ISSUER": "SSL Certificate - Issued by",
    "SSL_CERTIFICATE_MISMATCH": "SSL Certificate Host Mismatch",
    "SSL_CERTIFICATE_EXPIRED": "SSL Certificate Expired",
    "SSL_CERTIFICATE_EXPIRING": "SSL Certificate Expiring",
    "AFFILIATE_INTERNET_NAME_HIJACKABLE": "Affiliate - Internet Name Hijackable",
    "PROXY_HOST": "Proxy Host",
    "BLACKLISTED_IPADDR": "Blacklisted IP Address",
    "BLACKLISTED_INTERNET_NAME": "Blacklisted Internet Name",
    "BLACKLISTED_COHOST": "Blacklisted Co-Hosted Site",
    "BLACKLISTED_SUBNET": "Blacklisted IP on Same Subnet",
    "BLACKLISTED_NETBLOCK": "Blacklisted IP on Owned Netblock",
    "BLACKLISTED_AFFILIATE_IPADDR": "Blacklisted Affiliate IP Address",
    "BLACKLISTED_AFFILIATE_INTERNET_NAME": "Blacklisted Affiliate Internet Name",
    "MALICIOUS_IPADDR": "Malicious IP Address",
    "MALICIOUS_INTERNET_NAME": "Malicious Internet Name",
    "MALICIOUS_COHOST": "Malicious Co-Hosted Site",
    "MALICIOUS_SUBNET": "Malicious IP on Same Subnet",
    "MALICIOUS_NETBLOCK": "Malicious IP on Owned Netblock",
    "MALICIOUS_AFFILIATE_IPADDR": "Malicious Affiliate IP Address",
    "MALICIOUS_AFFILIATE_INTERNET_NAME": "Malicious Affiliate",
}
TYPES = tuple(LIBELLES)
_CODE = {libelle: code for code, libelle in LIBELLES.items()}

# Un scan sur un petit domaine prend quelques minutes ; au-delà, Vigie l'arrête et
# garde ce qui a déjà été trouvé.
DELAI = 20 * 60


def ligne():
    """La ligne de lancement (pour fiches_outils) : {cible} = le domaine."""
    return ["spiderfoot", "-s", "{cible}", "-m", ",".join(MODULES), "-o", "json",
            "-max-threads", "10", "-F", ",".join(TYPES)]


# --- Avant le scan : le résolveur DNS ------------------------------------------------
def chemin_base():
    """La base de SpiderFoot (scans + réglages), comme SpiderFoot la cherche."""
    dossier = os.environ.get("SPIDERFOOT_DATA") or os.path.expanduser("~/.spiderfoot")
    return os.path.join(dossier, "spiderfoot.db")


def regler_resolveur(serveur, base=None):
    """Fait passer les questions DNS de SpiderFoot par un résolveur public.

    La box internet sature et met ~2 s par question (CLAUDE.md, 21/11/2026) ; la
    recherche de faux domaines (sfp_similar) en pose des centaines. C'est le réglage
    « _dnsserver » de la page Settings de SpiderFoot, écrit dans sa base. On ne touche
    pas à un serveur déjà choisi. Renvoie True si Vigie vient de le régler.
    """
    base = base or chemin_base()
    if not os.path.exists(base):
        return False
    try:
        with closing(sqlite3.connect(base, timeout=5)) as connexion:
            deja = connexion.execute("SELECT val FROM tbl_config WHERE scope = 'GLOBAL' "
                                     "AND opt = '_dnsserver'").fetchone()
            if deja and (deja[0] or "").strip():
                return False
            connexion.execute("REPLACE INTO tbl_config (scope, opt, val) "
                              "VALUES ('GLOBAL', '_dnsserver', ?)", (serveur,))
            connexion.commit()
            return True
    except sqlite3.Error:
        return False


def avant_lancement(chemin, serveur=None, base=None):
    """Prépare un scan. Renvoie les remarques à montrer (liste de phrases).

    La base de SpiderFoot n'existe qu'après son premier lancement : si elle manque,
    « spiderfoot -T » (liste des types, rien n'est scanné) la crée.
    """
    base = base or chemin_base()
    if not os.path.exists(base) and chemin:
        try:
            subprocess.run([chemin, "-T"], capture_output=True, timeout=120,
                           stdin=subprocess.DEVNULL)
        except (OSError, subprocess.SubprocessError):
            pass
    if serveur is None:
        from . import reseau
        serveur = reseau.SERVEURS_DNS[0]
    if regler_resolveur(serveur, base):
        return [f"SpiderFoot posera ses questions DNS au résolveur public {serveur} : par "
                "la box, chaque question peut prendre 2 secondes et le scan des heures."]
    return []


# --- Lire la sortie ------------------------------------------------------------------
def evenements(sortie):
    """Les événements JSON de la sortie de SpiderFoot, même tronquée ou salie.

    SpiderFoot écrit « [ », un objet par ligne, puis « ] ». Mais une bibliothèque
    (python-whois) écrit parfois au milieu (« Error trying to connect to socket »), et
    un scan arrêté au bout du temps maximum n'a pas de « ] » final : on lit donc chaque
    objet un par un au lieu du tableau entier.
    """
    lecteur = json.JSONDecoder()
    texte = sortie or ""
    trouves, position = [], 0
    while True:
        position = texte.find("{", position)
        if position < 0:
            return trouves
        try:
            objet, fin = lecteur.raw_decode(texte, position)
        except ValueError:
            position += 1
            continue
        if isinstance(objet, dict) and "type" in objet and "data" in objet:
            code = _CODE.get(objet["type"], objet["type"])
            trouves.append({"code": code, "data": str(objet.get("data") or "").strip(),
                            "source": str(objet.get("source") or "").strip(),
                            "module": str(objet.get("module") or "")})
            position = fin
        else:
            position += 1


_LIGNE_JOURNAL = re.compile(r"^\S+ \S+ \[(\w+)\] (\S+) : (.*)$")
_INJOIGNABLE = re.compile(r"Failed to connect to https?://([^/:\s]+)")
_ABSENT = re.compile(r"Failed to load module: (sfp_\w+)")
_STATUT = re.compile(r"Scan completed with status ([A-Z-]+)")


def journal(erreurs):
    """Ce que dit le journal de SpiderFoot (sa sortie d'erreurs) : statut final,
    sources injoignables, modules en erreur, modules absents de cette version."""
    lu = {"statut": "", "injoignables": [], "modules_en_erreur": [], "absents": []}
    for brute in (erreurs or "").splitlines():
        ligne_lue = _LIGNE_JOURNAL.match(brute.strip())
        if not ligne_lue:
            continue
        niveau, qui, message = ligne_lue.groups()
        statut = _STATUT.search(message)
        if statut:
            lu["statut"] = statut.group(1)
        if niveau not in ("ERROR", "CRITICAL"):
            continue
        hote = _INJOIGNABLE.search(message)
        if hote and hote.group(1) not in lu["injoignables"]:
            lu["injoignables"].append(hote.group(1))
        absent = _ABSENT.search(message)
        if absent and absent.group(1) not in lu["absents"]:
            lu["absents"].append(absent.group(1))
        if qui.startswith("sfp_") and qui not in lu["modules_en_erreur"]:
            lu["modules_en_erreur"].append(qui)
    return lu


def _derniere_erreur(erreurs):
    """La vraie ligne d'erreur d'une trace Python (« ValueError: … »), ou ""."""
    for brute in reversed((erreurs or "").splitlines()):
        texte = brute.strip()
        if re.match(r"^[A-Za-z_.]*(Error|Exception)\b.*:", texte):
            return texte
    return ""


def _utiles(liste, cible):
    """Les événements trouvés par les sources (sans la cible de départ elle-même)."""
    return [e for e in liste if e["module"] != "SpiderFoot UI"
            and not (e["code"] in ("INTERNET_NAME", "DOMAIN_NAME")
                     and e["data"].lower().strip(".") == (cible or "").lower())]


def panne(sortie, erreurs, cible=""):
    """Pourquoi le scan n'a pas vraiment eu lieu (en français), ou "" s'il a tourné.

    SpiderFoot répond « fini » (code 0) même quand le scan a planté : il faut lire son
    journal pour le savoir.
    """
    texte = erreurs or ""
    if "Could not update TLD list" in texte:
        return ("SpiderFoot n'a pas pu démarrer le scan : il télécharge d'abord la liste "
                "officielle des extensions de domaines (.fr, .com…) sur publicsuffix.org, "
                "et ça n'a pas marché. Vérifie qu'Internet marche sur cet ordinateur, puis "
                "relance.")
    if "Could not determine target type" in texte:
        return ("SpiderFoot n'a pas reconnu la cible. Donne un nom de domaine simple, "
                "par exemple « exemple.fr ».")
    if "no modules were enabled" in texte:
        return ("SpiderFoot n'a trouvé aucune des sources choisies par Vigie : sa version "
                "est peut-être différente. Relance l'installeur de Vigie.")
    lu = journal(texte)
    utiles = _utiles(evenements(sortie), cible)
    if lu["statut"] in ("ERROR-FAILED", "ABORTED") and not utiles:
        return ("SpiderFoot a arrêté le scan sur une erreur avant d'avoir trouvé quoi que "
                "ce soit (détail technique ci-dessous, en anglais).")
    if "Traceback (most recent call last)" in texte and not utiles:
        cause = _derniere_erreur(texte)
        return ("SpiderFoot a planté avant d'avoir trouvé quoi que ce soit"
                + (f" (erreur : « {cause} »)" if cause else "") + ". Montre le détail "
                "technique ci-dessous à Claude pour qu'il corrige.")
    if not utiles and len(lu["injoignables"]) >= 3:
        return ("SpiderFoot n'a pu joindre presque aucune source publique ("
                f"{_n(len(lu['injoignables']), 'source')} sans réponse : "
                f"{_liste(lu['injoignables'], 5)}). Internet est peut-être coupé ou filtré "
                "sur cet ordinateur : vérifie la connexion, puis relance.")
    return ""


# --- Le résumé en français -----------------------------------------------------------
def _n(nombre, singulier, pluriel=None):
    """« 1 source », « 3 sources »."""
    return f"{nombre} {singulier if nombre == 1 else (pluriel or singulier + 's')}"


def _liste(valeurs, maximum=8):
    valeurs = list(valeurs)
    texte = ", ".join(valeurs[:maximum])
    if len(valeurs) > maximum:
        texte += f"… (+{len(valeurs) - maximum})"
    return texte


def _uniques(liste, code, champ="data"):
    vus = []
    for e in liste:
        if e["code"] == code:
            valeur = e[champ].splitlines()[0].strip() if e[champ] else ""
            if valeur and valeur not in vus:
                vus.append(valeur)
    return vus


def duree(secondes):
    """« 45 s », « 3 min 12 s », « 20 min »."""
    try:
        total = int(round(float(secondes)))
    except (TypeError, ValueError):
        return ""
    minutes, reste = divmod(total, 60)
    if not minutes:
        return f"{reste} s"
    return f"{minutes} min" + (f" {reste} s" if reste else "")


def _sous_domaines(noms, cible):
    cible = (cible or "").lower().strip(".")
    dessous = sorted({n.lower().strip(".") for n in noms
                      if cible and n.lower().strip(".").endswith("." + cible)})
    return dessous


def resumer(sortie, erreurs="", cible="", secondes=None, partiel=False):
    """Le résumé en français d'un scan SpiderFoot : d'abord ce qui doit inquiéter, puis
    ce qui a été trouvé, puis ce qui n'a pas pu être vérifié."""
    tout = evenements(sortie)
    utiles = _utiles(tout, cible)
    lu = journal(erreurs)
    lignes = [f"SpiderFoot : {len(MODULES)} sources publiques interrogées sur "
              f"{cible or 'la cible'}" + (f" ({duree(secondes)})" if secondes else "")
              + (" : arrêté au bout du temps maximum, résultat incomplet" if partiel
                 else "") + "."]

    # 1. Ce qui doit inquiéter.
    alertes = []
    listes_noires = [e for e in utiles if e["code"].startswith(("BLACKLISTED_",
                                                                  "MALICIOUS_"))]
    if listes_noires:
        detail = _liste(dict.fromkeys(e["data"].splitlines()[0] for e in listes_noires
                                      if e["data"]), 5)
        alertes.append(f"Listes noires : {_n(len(listes_noires), 'signalement')}. Les e-mails "
                       "envoyés depuis ces adresses risquent de finir en spam, et des "
                       f"visiteurs peuvent être bloqués. Détail : {detail}")
    for e in utiles:
        if e["code"] == "SSL_CERTIFICATE_EXPIRED":
            alertes.append(f"Certificat HTTPS expiré sur {e['source'] or 'un nom'} "
                           f"(fin : {e['data']}) : les visiteurs voient une alerte de "
                           "sécurité.")
        elif e["code"] == "SSL_CERTIFICATE_EXPIRING":
            alertes.append(f"Certificat HTTPS qui expire bientôt sur "
                           f"{e['source'] or 'un nom'} (fin : {e['data']}).")
        elif e["code"] == "SSL_CERTIFICATE_MISMATCH":
            alertes.append(f"Certificat HTTPS qui ne correspond pas au nom "
                           f"{e['source'] or ''} (il couvre : {e['data']}) : alerte de "
                           "sécurité pour les visiteurs.")
    detournables = _uniques(utiles, "AFFILIATE_INTERNET_NAME_HIJACKABLE")
    if detournables:
        alertes.append("Sous-domaine détournable : un de vos noms pointe vers un service "
                       f"extérieur abandonné ({_liste(detournables, 5)}). N'importe qui "
                       "peut le réclamer et publier sa propre page sous votre nom.")
    internes = _uniques(utiles, "INTERNAL_IP_ADDRESS")
    if internes:
        alertes.append("Le DNS public donne des adresses du réseau interne "
                       f"({_liste(internes, 5)}) : ça renseigne un attaquant sur "
                       "l'organisation de vos machines.")
    relais = _uniques(utiles, "PROXY_HOST")
    if relais:
        alertes.append(f"Adresse signalée comme relais ouvert (proxy) : {_liste(relais, 5)}.")
    if alertes:
        lignes += ["", "À regarder en premier :"] + [f"  • {a}" for a in alertes]
    elif utiles:
        # Jamais un « rien d'alarmant » sans vraie recherche (CLAUDE.md, 26/11/2026).
        qui = "les sources qui ont répondu" if lu["injoignables"] else "ces sources"
        lignes += ["", f"Rien d'alarmant vu par {qui} : ni liste noire, ni certificat "
                   "expiré, ni sous-domaine détournable."]

    # 2. Ce qui a été trouvé.
    faits = []
    noms = _uniques(utiles, "INTERNET_NAME")
    sous = _sous_domaines(noms, cible)
    if sous:
        courts = [n[: -len(cible) - 1] for n in sous]
        faits.append(f"{_n(len(sous), 'sous-domaine')} visible(s) publiquement : "
                     f"{_liste(courts)}")
    morts = _sous_domaines(_uniques(utiles, "INTERNET_NAME_UNRESOLVED"), cible)
    if morts:
        faits.append(f"{_n(len(morts), 'ancien nom', 'anciens noms')} qui ne "
                     f"répond(ent) plus : {_liste(morts, 5)}")
    adresses = _uniques(utiles, "IP_ADDRESS") + _uniques(utiles, "IPV6_ADDRESS")
    if adresses:
        faits.append(f"{_n(len(adresses), 'adresse IP', 'adresses IP')} : "
                     f"{_liste(adresses, 5)}")
    hebergeurs = [h.split(": http")[0] for h in _uniques(utiles, "PROVIDER_HOSTING")]
    if hebergeurs:
        faits.append(f"Hébergeur : {_liste(dict.fromkeys(hebergeurs), 3)}")
    bureaux = _uniques(utiles, "DOMAIN_REGISTRAR")
    if bureaux:
        faits.append(f"Bureau d'enregistrement du domaine : {_liste(bureaux, 2)}")
    mx = _uniques(utiles, "PROVIDER_MAIL")
    if mx:
        faits.append(f"Serveurs qui reçoivent les e-mails (MX) : {_liste(mx, 4)}")
    ns = _uniques(utiles, "PROVIDER_DNS")
    if ns:
        faits.append(f"Serveurs DNS du domaine : {_liste(ns, 4)}")
    if _uniques(utiles, "DNS_SPF"):
        faits.append("Règle d'envoi des e-mails (SPF) : présente")
    elif any(e["code"] == "DNS_TEXT" for e in utiles):
        faits.append("Règle d'envoi des e-mails (SPF) : pas vue par SpiderFoot")
    ressemblants = _uniques(utiles, "SIMILARDOMAIN")
    if ressemblants:
        faits.append(f"{_n(len(ressemblants), 'domaine')} qui ressemble(nt) au vôtre et "
                     "existe(nt) (à surveiller : faux sites, hameçonnage) : "
                     f"{_liste(ressemblants, 6)}")
    voisins = _uniques(utiles, "CO_HOSTED_SITE")
    if voisins:
        faits.append(f"{_n(len(voisins), 'autre site', 'autres sites')} sur le même "
                     "serveur (hébergement partagé)")
    serveurs_web = _uniques(utiles, "WEBSERVER_BANNER")
    if serveurs_web:
        faits.append(f"Logiciel du serveur web : {_liste(serveurs_web, 3)}")
    ports = _uniques(utiles, "TCP_PORT_OPEN")
    if ports:
        faits.append(f"Ports HTTPS vus en lisant le certificat : {_liste(ports, 5)}")
    emetteurs = _uniques(utiles, "SSL_CERTIFICATE_ISSUER")
    if emetteurs:
        faits.append(f"Certificat délivré par : {_liste(emetteurs, 2)}")
    autres = [d for d in _uniques(utiles, "DOMAIN_NAME")
              if d.lower().strip(".") != (cible or "").lower()]
    if autres:
        faits.append(f"Autres domaines liés : {_liste(autres, 5)}")
    lignes.append("")
    if faits:
        lignes.append("Ce que SpiderFoot a trouvé :")
        lignes += [f"  • {f}" for f in faits]
    else:
        lignes.append("SpiderFoot n'a rien trouvé de public au-delà du nom lui-même.")

    # 3. Ce qui n'a pas pu être vérifié : jamais un « rien » sans le dire.
    if lu["injoignables"]:
        lignes += ["", "Attention, résultat incomplet : "
                   f"{_n(len(lu['injoignables']), 'source')} sans réponse "
                   f"({_liste(lu['injoignables'], 6)})."]
    if lu["absents"]:
        lignes += ["", f"Sources absentes de ce SpiderFoot : {_liste(lu['absents'], 6)}."]
    lignes += ["", "Tout le détail, avec des graphiques : onglet « Ouvrir un outil », "
               "SpiderFoot, puis « Scans »."]
    return "\n".join(lignes)
