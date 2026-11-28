"""Le bilan d'une cible : tous les outils lancés dessus, regroupés en un seul bilan.

Demande d'Anass (28/11/2026) : lancer plusieurs outils sur une cible (un par un, en
combo, à la main, ou dans leur propre interface comme ZAP) puis que Vigie RÉUNISSE tout
en un seul bilan en français, recoupé et sans doublons.

1. **Ranger** : chaque lancement est gardé dans `resultats/<cible>/<date>_<outil>.json`
   (Lancer un outil, Combos, Outils manuels, import d'un rapport ZAP). Avant, le
   résultat d'un outil était perdu à la fermeture de Vigie.
2. **Traduire** : chaque sortie devient des « trouvailles » au même format
   {genre, cle, niveau, texte} (sous-domaine, page, porte ouverte, faille, technologie,
   compte, domaine imitateur). Les traducteurs existants sont réutilisés (audit_actif,
   ports, spiderfoot, combos).
3. **Regrouper** : une trouvaille vue par plusieurs outils n'apparaît qu'une fois, avec
   « vu par » (le recoupement) et le niveau le plus grave.
4. **Rapport** : les points à corriger deviennent des constats du rapport habituel
   (rapport.py), avec la note et l'onglet Conséquences quand la clé existe.

Rien n'est lancé ici : ce module ne fait que lire ce que les garde-fous ont déjà laissé
passer. Le rapport dit si des résultats viennent d'outils actifs (autorisation ou propre
cible) ; il est toujours relu par Anass avant envoi.
"""
import datetime
import hashlib
import json
import os
import re
import tempfile
import xml.etree.ElementTree as ET

from . import audit_actif, combos, lancer_seul, ports, spiderfoot
from .modeles import CRITIQUE, IMPORTANT, INFO, OK, ORDRE, Constat

DOSSIER = "resultats"
_NOM_SUR = re.compile(r"[^a-z0-9@._-]+")


# --- 1. Ranger ------------------------------------------------------------------------

def cle_cible(cible):
    """Le nom du dossier d'une cible : « https://www.a.fr/x » -> « www.a.fr »."""
    texte = (cible or "").strip().lower()
    if "@" not in texte:
        texte = lancer_seul.hote(texte) or texte
    texte = _NOM_SUR.sub("_", texte).strip("._")
    return texte[:120] or "sans-cible"


def enregistrer(dossier, outil, cible, sortie, erreurs="", depuis="", garde="passif",
                commande="", reussi=True):
    """Garde un lancement pour le bilan. Renvoie le chemin du fichier écrit."""
    if not dossier:
        return ""
    quand = datetime.datetime.now()
    rep = os.path.join(dossier, cle_cible(cible))
    os.makedirs(rep, exist_ok=True)
    nom = f"{quand:%Y%m%d-%H%M%S}_{_NOM_SUR.sub('-', outil.lower())}"
    chemin = os.path.join(rep, nom + ".json")
    n = 1
    while os.path.exists(chemin):
        n += 1
        chemin = os.path.join(rep, f"{nom}-{n}.json")
    donnees = {"outil": outil, "cible": cible, "quand": quand.isoformat(timespec="seconds"),
               "depuis": depuis, "garde": garde or "passif", "commande": commande,
               "reussi": bool(reussi), "sortie": sortie or "", "erreurs": erreurs or ""}
    with open(chemin, "w", encoding="utf-8") as fichier:
        json.dump(donnees, fichier, ensure_ascii=False)
    return chemin


def cibles(dossier):
    """[(cible, nombre de lancements, dernier)] des cibles qui ont des résultats."""
    if not dossier or not os.path.isdir(dossier):
        return []
    sortie = []
    for nom in sorted(os.listdir(dossier)):
        rep = os.path.join(dossier, nom)
        if not os.path.isdir(rep):
            continue
        fichiers = sorted(f for f in os.listdir(rep) if f.endswith(".json"))
        if fichiers:
            sortie.append((nom, len(fichiers), fichiers[-1][:15]))
    return sortie


def lancements(dossier, cible):
    """Les lancements gardés pour une cible ET ses sous-domaines, du plus récent au plus
    ancien. Chacun a en plus « id » (son nom de fichier, pour le décocher)."""
    cle = cle_cible(cible)
    trouves = []
    for nom, _, _ in cibles(dossier):
        if nom != cle and not nom.endswith("." + cle):
            continue
        rep = os.path.join(dossier, nom)
        for fichier in os.listdir(rep):
            if not fichier.endswith(".json"):
                continue
            try:
                with open(os.path.join(rep, fichier), encoding="utf-8") as f:
                    donnees = json.load(f)
            except (OSError, ValueError):
                continue
            donnees["id"] = f"{nom}/{fichier}"
            trouves.append(donnees)
    return sorted(trouves, key=lambda d: d.get("quand", ""), reverse=True)


# --- 2. Traduire chaque sortie en trouvailles ----------------------------------------
# Trouvaille = (genre, cle, niveau, texte). Deux trouvailles de même (genre, cle) sont la
# même chose vue par deux outils.

GENRES = {
    "faille": "Points relevés par les outils",
    "porte": "Portes ouvertes sur Internet",
    "imitation": "Domaines qui imitent le vôtre",
    "techno": "Technologies repérées",
    "sous-domaine": "Sous-domaines",
    "page": "Pages du site",
    "compte": "Comptes trouvés",
}
ORDRE_GENRES = list(GENRES)


def _par_fichier(traducteur, texte, suffixe=".txt"):
    """Les traducteurs existants lisent un fichier : on leur en donne un, temporaire."""
    with tempfile.NamedTemporaryFile("w", suffix=suffixe, delete=False,
                                     encoding="utf-8") as tmp:
        tmp.write(texte or "")
    try:
        return traducteur(tmp.name)
    except Exception:
        return []
    finally:
        os.unlink(tmp.name)


def _jsonl(texte):
    for ligne in (texte or "").splitlines():
        ligne = ligne.strip()
        if ligne.startswith("{"):
            try:
                yield json.loads(ligne)
            except ValueError:
                continue


def _nuclei(sortie, cible):
    for res in _jsonl(sortie):
        info = res.get("info") or {}
        niveau = audit_actif.GRAVITE.get((info.get("severity") or "unknown").lower(), INFO)
        nom = info.get("name") or res.get("template-id") or "point relevé"
        ou = res.get("matched-at") or res.get("host") or ""
        debut = "Nuclei a relevé" if niveau == INFO else "Faille connue détectée"
        yield ("faille", f"nuclei:{res.get('template-id', nom)}:{ou}", niveau,
               f"{debut} : {nom}" + (f" ({ou})" if ou else ""))


def _lignes_traduites(nom_traducteur, suffixe=".txt"):
    def lire(sortie, cible):
        for niveau, texte in _par_fichier(audit_actif.TRADUCTEURS[nom_traducteur], sortie,
                                          suffixe):
            if niveau != OK:
                yield ("faille", f"{nom_traducteur}:{texte.lower()}", niveau, texte)
    return lire


def _nmap(sortie, cible):
    if "<nmaprun" not in (sortie or ""):
        return
    for appareil in _par_fichier(ports.lire_nmap, sortie, ".xml"):
        qui = appareil["nom"] or appareil["ip"]
        for p in appareil["ports"]:
            niveau, quoi, pourquoi = ports.PORTS.get(p["port"], ports.INCONNU)
            detail = f" ({p['produit']})" if p["produit"] else ""
            yield ("porte", f"{qui}:{p['port']}", niveau,
                   f"{qui} : porte {p['port']} ouverte, {quoi}{detail}. {pourquoi}")


def _naabu(sortie, cible):
    for enr in _jsonl(sortie):
        port = enr.get("port")
        if isinstance(port, dict):
            port = port.get("Port") or port.get("port")
        if not isinstance(port, int):
            continue
        qui = enr.get("host") or enr.get("ip") or cible
        niveau, quoi, pourquoi = ports.PORTS.get(port, ports.INCONNU)
        yield ("porte", f"{qui}:{port}", niveau,
               f"{qui} : porte {port} ouverte, {quoi}. {pourquoi}")


# Les événements SpiderFoot qui sont des problèmes, en français.
_SF_PROBLEMES = {
    "AFFILIATE_INTERNET_NAME_HIJACKABLE": (CRITIQUE, "sous_domaines",
                                           "Sous-domaine qui peut être repris par un pirate"),
    "SSL_CERTIFICATE_EXPIRED": (CRITIQUE, "certificat", "Certificat expiré"),
    "SSL_CERTIFICATE_EXPIRING": (IMPORTANT, "certificat", "Certificat bientôt expiré"),
    "SSL_CERTIFICATE_MISMATCH": (IMPORTANT, "certificat",
                                 "Certificat qui ne correspond pas au nom du site"),
}


def _spiderfoot(sortie, cible):
    for ev in spiderfoot.evenements(sortie):
        code, donnee = ev["code"], ev["data"]
        if code in _SF_PROBLEMES:
            niveau, cle, texte = _SF_PROBLEMES[code]
            yield ("faille", f"{cle}:{donnee.lower()}", niveau, f"{texte} : {donnee}")
        elif code.startswith(("BLACKLISTED_", "MALICIOUS_")) and "AFFILIATE" not in code \
                and "COHOST" not in code:
            yield ("faille", f"liste_noire:{donnee.lower()}", IMPORTANT,
                   f"Sur une liste noire (spam, virus ou hameçonnage) : {donnee}")
        elif code == "SIMILARDOMAIN":
            yield ("imitation", donnee.lower(), INFO, donnee.lower())
        elif code == "TCP_PORT_OPEN" and ":" in donnee:
            qui, port = donnee.rsplit(":", 1)
            if port.isdigit():
                niveau, quoi, pourquoi = ports.PORTS.get(int(port), ports.INCONNU)
                yield ("porte", f"{qui}:{port}", niveau,
                       f"{qui} : porte {port} ouverte, {quoi}. {pourquoi}")
        elif code == "WEBSERVER_BANNER":
            yield ("techno", donnee.split("/")[0].lower(), INFO, f"Serveur web : {donnee}")


def _dnstwist(sortie, cible):
    try:
        lignes = json.loads(sortie or "[]")
    except ValueError:
        return
    for enr in lignes if isinstance(lignes, list) else []:
        domaine = (enr.get("domain") or enr.get("domain-name") or "").lower()
        if domaine and enr.get("fuzzer") != "*original" and domaine != cible:
            yield ("imitation", domaine, INFO, domaine)


# WhatWeb : « Apache[2.4.58], WordPress[6.4], Country[FR] ». On garde les technologies.
_WHATWEB = re.compile(r"([A-Za-z][\w .-]{1,40})\[([^\]]{0,80})\]")
_PAS_TECHNO = {"country", "ip", "title", "redirectlocation", "uncommonheaders", "cookies",
               "httponly", "email", "html5", "script", "strict-transport-security",
               "x-frame-options", "x-xss-protection", "meta-author", "open-graph-protocol",
               "frame", "object", "passwordfield", "x-ua-compatible", "via-proxy", "meta-refresh"}


def _whatweb(sortie, cible):
    for nom, valeur in _WHATWEB.findall(lancer_seul.outils.sans_couleurs(sortie or "")):
        nom = nom.strip().split(" ")[-1]
        if nom.lower() in _PAS_TECHNO or nom.isdigit() or "." in nom or "/" in nom:
            continue
        if nom.lower() == "httpserver":
            yield ("techno", valeur.split("/")[0].lower(), INFO, f"Serveur web : {valeur}")
        else:
            texte = f"{nom} {valeur}".strip() if re.match(r"^[\d.]+$", valeur) else nom
            yield ("techno", nom.lower(), INFO, texte)


def _pseudos(sortie, cible):
    for site, url in combos.profils(sortie).items():
        yield ("compte", site, INFO, f"{site} : {url}")


LECTEURS = {
    "nuclei": _nuclei, "nikto": _lignes_traduites("nikto"),
    "tlsx": _lignes_traduites("tlsx"), "sslscan": _lignes_traduites("sslscan", ".xml"),
    "nmap": _nmap, "naabu": _naabu, "spiderfoot": _spiderfoot, "dnstwist": _dnstwist,
    "whatweb": _whatweb, "sherlock": _pseudos, "maigret": _pseudos,
    "social analyzer": _pseudos,
}
# Ces outils listent des noms et des adresses : sous-domaines et pages en sont tirés.
_SANS_ADRESSES = {"sherlock", "maigret", "social analyzer", "holehe", "dnstwist", "zap"}


def trouvailles(lancement, cible):
    """Les trouvailles d'un lancement gardé (liste de tuples, doublons possibles)."""
    outil = (lancement.get("outil") or "").lower()
    sortie = lancement.get("sortie") or ""
    if outil == "zap":
        return list(lire_zap(sortie))
    sortie_propre = lancer_seul.outils.sans_couleurs(sortie)
    resultat = []
    lecteur = LECTEURS.get(outil)
    if lecteur:
        resultat += list(lecteur(sortie_propre, cible))
    if outil not in _SANS_ADRESSES and "@" not in cible:
        domaine = cle_cible(cible)
        for nom in combos.sous_domaines(domaine, sortie_propre) - {domaine}:
            resultat.append(("sous-domaine", nom, INFO, nom))
        for url in combos.adresses_web(sortie_propre):
            if lancer_seul.hote(url).endswith(domaine):
                resultat.append(("page", url, INFO, url))
    return resultat


# --- Import d'un rapport ZAP (JSON ou XML « traditionnel ») ---------------------------
# Les alertes ZAP les plus courantes, en français. La clé de conséquences (quand Vigie
# en a une) relie l'alerte à l'onglet Conséquences du rapport.
ZAP_FR = {
    "10020": ("cadre", "Le site peut être affiché dans un autre site (piège au clic)",
              "Ajouter l'en-tête X-Frame-Options ou la règle frame-ancestors."),
    "10021": ("nosniff", "Le navigateur peut mal deviner le type des fichiers",
              "Ajouter l'en-tête X-Content-Type-Options: nosniff."),
    "10038": ("csp", "Aucune politique de contenu (CSP) : les scripts injectés passent",
              "Ajouter l'en-tête Content-Security-Policy."),
    "10035": ("hsts", "Le site n'impose pas le chiffrement (HSTS absent)",
              "Ajouter l'en-tête Strict-Transport-Security."),
    "10036": ("versions_visibles", "Le serveur affiche sa version",
              "Masquer la version dans l'en-tête Server."),
    "10037": ("versions_visibles", "Le site affiche sa technologie (X-Powered-By)",
              "Retirer l'en-tête X-Powered-By."),
    "10010": ("", "Cookie lisible par un script (HttpOnly absent)",
              "Ajouter l'option HttpOnly aux cookies."),
    "10011": ("", "Cookie envoyé sans chiffrement (Secure absent)",
              "Ajouter l'option Secure aux cookies."),
    "10054": ("", "Cookie sans protection SameSite",
              "Ajouter l'option SameSite=Lax aux cookies."),
    "10202": ("", "Formulaire sans jeton anti-falsification (CSRF)",
              "Ajouter un jeton anti-CSRF aux formulaires."),
    "10098": ("", "Le site autorise d'autres sites à lire ses données (CORS trop large)",
              "Restreindre l'en-tête Access-Control-Allow-Origin."),
    "10063": ("", "Pas de politique de permissions (caméra, micro, position…)",
              "Ajouter l'en-tête Permissions-Policy."),
    "10017": ("", "Le site charge des scripts depuis d'autres sites",
              "Héberger les scripts soi-même ou ajouter un contrôle d'intégrité (SRI)."),
    "10027": ("", "Commentaires suspects dans le code des pages",
              "Retirer les commentaires techniques des pages publiées."),
    "10096": ("", "Dates techniques visibles dans les pages", ""),
    "10015": ("", "Pages sensibles gardées en cache par le navigateur",
              "Ajouter Cache-Control: no-store aux pages privées."),
    "40012": ("", "Faille XSS (injection de script) réfléchie", "Filtrer les entrées."),
    "40014": ("", "Faille XSS (injection de script) persistante", "Filtrer les entrées."),
    "40018": ("", "Faille d'injection SQL (accès à la base de données)",
              "Utiliser des requêtes préparées."),
    "90033": ("", "Cookie valable sur trop de sous-domaines", "Restreindre le domaine du cookie."),
}
_ZAP_NIVEAU = {"3": CRITIQUE, "2": IMPORTANT, "1": INFO, "0": INFO}


class ImportImpossible(ValueError):
    """Le fichier donné n'est pas un rapport ZAP lisible (raison en français)."""


def _alertes_zap(texte):
    """[(pluginid, nom, riskcode, [adresses])] d'un rapport ZAP JSON ou XML."""
    texte = (texte or "").strip()
    alertes = []
    if texte.startswith("{"):
        try:
            donnees = json.loads(texte)
        except ValueError:
            raise ImportImpossible("Le fichier ressemble à du JSON mais il est abîmé.")
        sites = donnees.get("site") or []
        for site in sites if isinstance(sites, list) else [sites]:
            for a in site.get("alerts") or []:
                adresses = [i.get("uri", "") for i in a.get("instances") or []]
                alertes.append((str(a.get("pluginid", "")), a.get("alert") or a.get("name")
                                or "", str(a.get("riskcode", "1")), adresses))
    elif "<OWASPZAPReport" in texte[:500]:
        # Fichier enregistré par ZAP sur la machine d'Anass. ElementTree ne charge pas
        # les entités externes (Python 3.7.1+).
        racine = ET.fromstring(texte)  # nosemgrep
        for a in racine.iter("alertitem"):
            adresses = [u.text or "" for u in a.iter("uri")]
            alertes.append(((a.findtext("pluginid") or ""),
                            a.findtext("alert") or a.findtext("name") or "",
                            a.findtext("riskcode") or "1", adresses))
    else:
        raise ImportImpossible(
            "Ce n'est pas un rapport ZAP. Dans ZAP : menu « Rapport » → « Générer un "
            "rapport », modèle « Traditional JSON Report » (ou XML), puis choisis ce "
            "fichier ici.")
    return alertes


def lire_zap(texte):
    for pluginid, nom, risque, adresses in _alertes_zap(texte):
        cle, francais, _ = ZAP_FR.get(pluginid, ("", "", ""))
        niveau = _ZAP_NIVEAU.get(risque, INFO)
        ou = f" ({len(set(adresses))} page{'s' if len(set(adresses)) > 1 else ''})" \
            if adresses else ""
        texte_fr = francais or f"ZAP a relevé : {nom} (nom anglais de ZAP)"
        yield ("faille", cle or f"zap:{pluginid or nom.lower()}", niveau, texte_fr + ou)


def importer_zap(dossier, cible, texte):
    """Garde un rapport ZAP comme un lancement de la cible. Lève ImportImpossible."""
    cible = (cible or "").strip()
    if not cible:
        raise ImportImpossible("Indique la cible que ZAP a analysée (exemple : "
                               "pavillon-noir.tech).")
    nombre = len(_alertes_zap(texte))
    enregistrer(dossier, "ZAP", cible, texte, depuis="Import d'un rapport ZAP",
                garde="rapport ZAP importé (scan fait dans ZAP)")
    return nombre


# --- 3. Regrouper -----------------------------------------------------------------------

def regrouper(liste, cible):
    """Le bilan commun d'une liste de lancements.

    Renvoie {"genres": {genre: [{"texte", "niveau", "outils", "cle"}]}, "phrases": [...],
    "actifs": [gardes des lancements non passifs], "outils": [...]}.
    """
    vus = {}                                    # (genre, cle) -> trouvaille regroupée
    outils_vus = []
    for lancement in liste:
        outil = lancement.get("outil") or "?"
        if outil not in outils_vus:
            outils_vus.append(outil)
        for genre, cle, niveau, texte in trouvailles(lancement, cible):
            t = vus.setdefault((genre, cle), {"genre": genre, "cle": cle, "niveau": niveau,
                                              "texte": texte, "outils": []})
            if outil not in t["outils"]:
                t["outils"].append(outil)
            if ORDRE[niveau] < ORDRE[t["niveau"]]:
                t["niveau"], t["texte"] = niveau, texte
    genres = {}
    for t in vus.values():
        genres.setdefault(t["genre"], []).append(t)
    for genre in genres:
        genres[genre].sort(key=lambda t: (ORDRE[t["niveau"]], -len(t["outils"]), t["texte"]))
    phrases = []
    if liste:
        phrases.append(f"{len(liste)} lancement{'s' if len(liste) > 1 else ''} réuni"
                       f"{'s' if len(liste) > 1 else ''}, par {len(outils_vus)} outil"
                       f"{'s' if len(outils_vus) > 1 else ''} : {', '.join(outils_vus)}.")
    graves = [t for t in genres.get("faille", []) + genres.get("porte", [])
              if t["niveau"] in (CRITIQUE, IMPORTANT)]
    if graves:
        critiques = sum(1 for t in graves if t["niveau"] == CRITIQUE)
        phrases.append(f"{len(graves)} point{'s' if len(graves) > 1 else ''} à corriger"
                       + (f", dont {critiques} grave{'s' if critiques > 1 else ''}"
                          if critiques else "") + ".")
    elif liste:
        phrases.append("Aucun point grave relevé par ces outils.")
    recoupes = sum(1 for t in vus.values() if len(t["outils"]) > 1)
    if len(outils_vus) > 1:
        phrases.append(f"{recoupes} trouvaille{'s' if recoupes > 1 else ''} vue"
                       f"{'s' if recoupes > 1 else ''} par plusieurs outils (recoupée"
                       f"{'s' if recoupes > 1 else ''}).")
    seuls = sum(1 for t in graves if len(t["outils"]) == 1)
    if seuls and len(outils_vus) > 1:
        phrases.append(f"{seuls} point{'s' if seuls > 1 else ''} à corriger vu"
                       f"{'s' if seuls > 1 else ''} par un seul outil : à confirmer à la "
                       "relecture.")
    actifs = sorted({l.get("garde") for l in liste if l.get("garde") not in ("", "passif", None)})
    return {"genres": genres, "phrases": phrases, "actifs": actifs, "outils": outils_vus}


# --- 4. Vers le rapport habituel -------------------------------------------------------

_BLOC = {"faille": "Exposition", "porte": "Réseau et postes"}


def constats(regroupe):
    """Les constats du rapport : les points à corriger, les ports, et une ligne par genre
    utile au dirigeant (sous-domaines, imitations, technologies), hors note."""
    sortie = []
    for genre in ("faille", "porte"):
        for t in regroupe["genres"].get(genre, []):
            if t["niveau"] == OK:
                continue
            cle = t["cle"] if ":" not in t["cle"] else \
                "bilan_" + hashlib.sha1(t["cle"].encode()).hexdigest()[:10]
            correction = ""
            for pluginid, (cle_zap, _, conseil) in ZAP_FR.items():
                if t["cle"] in (cle_zap, f"zap:{pluginid}") and conseil:
                    correction = conseil
                    break
            vu = ", ".join(t["outils"])
            explication = f"Vu par : {vu}." + (" Un seul outil l'a vu : à confirmer à la "
                                              "relecture." if len(t["outils"]) == 1
                                              and t["niveau"] != INFO else "")
            sortie.append(Constat(bloc=_BLOC[genre], niveau=t["niveau"], titre=t["texte"],
                                  explication=explication, correction=correction, cle=cle,
                                  sources=list(t["outils"]), hors_note=t["niveau"] == INFO))
    resumes = {
        "imitation": ("domaines_imitateurs", "domaine{s} qui imite{nt} le vôtre"),
        "sous-domaine": ("sous_domaines", "sous-domaine{s} visible{s} sur Internet"),
        "techno": ("technos_whatweb", "technologie{s} repérée{s}"),
        "compte": ("comptes_pseudo", "compte{s} trouvé{s}"),
    }
    for genre, (cle, modele) in resumes.items():
        liste = regroupe["genres"].get(genre, [])
        if not liste:
            continue
        n = len(liste)
        titre = f"{n} " + modele.format(s="s" if n > 1 else "", nt="nt" if n > 1 else "")
        exemples = ", ".join(t["texte"] for t in liste[:8]) + (" …" if n > 8 else "")
        outils = sorted({o for t in liste for o in t["outils"]})
        sortie.append(Constat(bloc="Exposition", niveau=INFO, titre=titre,
                              explication=f"{exemples}. Vu par : {', '.join(outils)}.",
                              cle=cle, sources=outils, hors_note=True))
    return sortie


def faire_rapport(regroupe, cible, sortie="rapports", societe=""):
    """Écrit le rapport (technique + dirigeant) du bilan. Renvoie le nom du dossier."""
    from . import rapport
    date = datetime.date.today().isoformat()
    autorisation = None
    if regroupe["actifs"]:
        autorisation = {"bilan": "Résultats d'outils actifs : " + " ; ".join(regroupe["actifs"]),
                        "signee": any("autorisation signée" in g for g in regroupe["actifs"])}
    brut = {"bilan": {"outils": regroupe["outils"], "phrases": regroupe["phrases"]}}
    resultat = rapport.construire(societe or cible, cible, date, constats(regroupe), brut,
                                  [], autorisation)
    nom = re.sub(r"[^a-z0-9_-]", "_", cle_cible(cible)) + f"_bilan_{date}"
    rapport.ecrire(resultat, os.path.join(sortie, nom))
    return nom
