"""Le banc de comparaison : une même question, plusieurs outils, côte à côte.

Pour chaque question (« quelles adresses annexes ? », « quels comptes sous ce pseudo ? »…),
chaque outil candidat donne une LISTE d'éléments. Vigie les rapproche élément par
élément et montre :
  - ce que tous voient (recoupé, donc fiable) ;
  - ce que chacun est SEUL à voir (ce que les autres ratent) ;
  - le temps de chacun, et ses échecs ;
  - une recommandation : garder un seul outil, garder les deux, ou en écarter un.
C'est la méthode suivie à la main le 21/11/2026 (chantier/comparaisons_2026-11-21.md),
rendue reproductible pour tous les prochains outils.

Ajouter une question : une entrée dans QUESTIONS, avec pour chaque candidat une
fonction (cible, dossier) -> ensemble d'éléments. Tout reste en lecture seule :
sources publiques, site lu comme un visiteur, ou fichiers de l'ordinateur.

    python3 -m vigie duel sous_domaines --cible exemple.fr
    python3 -m vigie duel secrets --dossier ~/mon-code
"""
import datetime
import html
import json
import os
import re
import subprocess
import tempfile
import time
import urllib.request

from . import __version__, outils, reseau
from .modeles import ControleImpossible
from .modules import adresses, chiffrement, pseudos, sousdomaines


# --- Les candidats : chacun rend un ensemble d'éléments comparables ---------------

def _sous_subfinder(cible, dossier):
    sortie = outils.executer("subfinder", ["-d", cible["domaine"], "-all", "-silent", "-oJ",
                                           "-timeout", "20", "-max-time", "3"], delai=300)
    return set(sousdomaines.lire_sortie(sortie, cible["domaine"]))


def _sous_amass(cible, dossier):
    base = os.path.join(dossier, "amass")
    outils.executer("amass", ["enum", "-passive", "-d", cible["domaine"], "-timeout", "4",
                              "-dir", base, "-nocolor", "-silent"], delai=420)
    sortie = outils.executer("amass", ["subs", "-names", "-d", cible["domaine"], "-dir", base],
                             delai=120)
    # Amass 5 laisse un « moteur » tourner après coup : on l'arrête (vu le 21/11/2026).
    subprocess.run(["pkill", "-f", "amass engine"], capture_output=True)
    return set(sousdomaines.lire_sortie(sortie, cible["domaine"]))


def _sous_theharvester(cible, dossier):
    base = os.path.join(dossier, "harvester")
    outils.executer("theHarvester", ["-d", cible["domaine"], "-l", "200", "-q", "-b",
                                     ",".join(adresses.SOURCES), "-f", base], delai=300,
                    dossier=dossier)
    try:
        with open(base + ".json", encoding="utf-8") as lu:
            hotes = json.load(lu).get("hosts") or []
    except (OSError, json.JSONDecodeError):
        raise ControleImpossible("theHarvester n'a rien produit")
    return {h.split(":")[0].lower() for h in hotes
            if h.split(":")[0].lower().endswith("." + cible["domaine"])}


def _sous_crtsh(cible, dossier):
    url = f"https://crt.sh/?q=%25.{cible['domaine']}&output=json"
    requete = urllib.request.Request(url, headers={"User-Agent": reseau.AGENT})
    try:
        with urllib.request.urlopen(requete, timeout=60) as reponse:
            fiches = json.load(reponse)
    except Exception as erreur:
        raise ControleImpossible(f"crt.sh injoignable : {erreur}")
    noms = set()
    for fiche in fiches:
        for nom in (fiche.get("name_value") or "").split("\n"):
            nom = nom.strip().lower().removeprefix("*.")
            if nom.endswith("." + cible["domaine"]):
                noms.add(nom)
    return noms


def _comptes(fonction):
    def candidat(cible, dossier):
        if not cible.get("pseudo") or not cible.get("accord"):
            raise ControleImpossible("pseudo du dirigeant ET son accord écrit requis")
        return {pseudos._site(c["site"]) for c in fonction(cible["pseudo"])}
    return candidat


def _constats(nom_module):
    """Un module de Vigie comme candidat : ses constats non « correct », par clé."""
    from .modeles import Cible
    from .modules import MODULES

    def candidat(cible, dossier):
        constats, _ = MODULES[nom_module]["fonction"](Cible(cible["domaine"]))
        return {(c.cle or c.titre) for c in constats if c.niveau != "OK"}
    return candidat


def _chiffrement_sslyze(cible, dossier):
    constats, brut = chiffrement.analyser(Cible_(cible))
    infos = brut["chiffrement"]
    return {"version " + v for v in infos["versions"]} | \
        ({"certificat reconnu"} if (infos["certificat"] or {}).get("reconnu") else set())


def _chiffrement_tlsx(cible, dossier):
    sortie = outils.executer("tlsx", ["-u", cible["domaine"], "-json", "-silent", "-ve"],
                             delai=120)
    elements = set()
    for ligne in sortie.splitlines():
        try:
            fiche = json.loads(ligne)
        except json.JSONDecodeError:
            continue
        noms = {"tls10": "TLS 1.0", "tls11": "TLS 1.1", "tls12": "TLS 1.2", "tls13": "TLS 1.3",
                "ssl30": "SSL 3"}
        elements |= {"version " + noms.get(v, v) for v in fiche.get("version_enum") or []}
        if not fiche.get("untrusted") and not fiche.get("expired"):
            elements.add("certificat reconnu")
    return elements


def Cible_(cible):
    from .modeles import Cible
    return Cible(cible["domaine"])


def _troues_grype(cible, dossier):
    sortie = outils.executer("grype", ["dir:" + cible["dossier"], "-q", "-o", "json"], delai=1800)
    try:
        data = json.loads(sortie or "{}")
    except json.JSONDecodeError:
        raise ControleImpossible("Grype n'a pas rendu de résultat lisible")
    return {f"{m['artifact']['name'].lower()} {m['artifact']['version']}"
            for m in data.get("matches") or []}


def _troues_trivy(cible, dossier):
    # Mode « rootfs » : en mode « fs », Trivy ne voit pas les paquets installés (21/11/2026).
    sortie = outils.executer("trivy", ["rootfs", "--quiet", "--scanners", "vuln", "--format",
                                       "json", cible["dossier"]], delai=1800)
    try:
        data = json.loads(sortie or "{}")
    except json.JSONDecodeError:
        raise ControleImpossible("Trivy n'a pas rendu de résultat lisible")
    return {f"{v['PkgName'].lower()} {v['InstalledVersion']}"
            for r in data.get("Results") or [] for v in r.get("Vulnerabilities") or []}


def _secrets_gitleaks(cible, dossier):
    rapport = os.path.join(dossier, "gitleaks.json")
    sous_commande = "git" if os.path.isdir(os.path.join(cible["dossier"], ".git")) else "dir"
    outils.executer("gitleaks", [sous_commande, cible["dossier"], "--no-banner",
                                 "--report-format", "json", "--report-path", rapport], delai=900)
    try:
        with open(rapport, encoding="utf-8") as lu:
            fiches = json.load(lu)
    except (OSError, json.JSONDecodeError):
        return set()
    return {f"{os.path.basename(f.get('File', ''))} : {_famille(f.get('RuleID', ''))}"
            for f in fiches or []}


def _secrets_trufflehog(cible, dossier):
    cible_th = ["git", "file://" + cible["dossier"]] if os.path.isdir(
        os.path.join(cible["dossier"], ".git")) else ["filesystem", cible["dossier"]]
    sortie = outils.executer("trufflehog", cible_th + ["--json", "--no-update",
                                                       "--results=verified,unverified"],
                             delai=900)
    elements = set()
    for ligne in (sortie or "").splitlines():
        try:
            fiche = json.loads(ligne)
        except json.JSONDecodeError:
            continue
        meta = (fiche.get("SourceMetadata") or {}).get("Data") or {}
        fichier = (meta.get("Git") or meta.get("Filesystem") or {}).get("file", "")
        if fiche.get("DetectorName"):
            elements.add(f"{os.path.basename(fichier)} : {_famille(fiche['DetectorName'])}")
    return elements


def _famille(nom):
    """« github-pat », « Github » -> « github » : les deux outils nomment différemment."""
    return re.split(r"[-_ ]", nom.lower())[0]


QUESTIONS = {
    "sous_domaines": {
        "titre": "Quelles adresses annexes de la société sont visibles publiquement ?",
        "besoin": "domaine",
        "candidats": {"Subfinder": ("subfinder", _sous_subfinder),
                      "Amass": ("amass", _sous_amass),
                      "theHarvester": ("theHarvester", _sous_theharvester),
                      "crt.sh (direct)": (None, _sous_crtsh)}},
    "comptes_pseudo": {
        "titre": "Sur quels sites un pseudo a-t-il un compte public ?",
        "besoin": "pseudo",
        "candidats": {"Sherlock": ("sherlock", _comptes(pseudos._sherlock)),
                      "Maigret": ("maigret", _comptes(pseudos._maigret)),
                      "user-scanner": ("user-scanner", _comptes(pseudos._user_scanner))}},
    "protections_site": {
        "titre": "Quelles protections manquent au site ?",
        "besoin": "domaine",
        "candidats": {"Vigie (site)": (None, _constats("site")),
                      "Lighthouse": ("lighthouse", _constats("qualite_site")),
                      "httpx": ("httpx", _constats("technos"))}},
    "mail": {
        "titre": "Que reproche-t-on aux réglages mail ?",
        "besoin": "domaine",
        "candidats": {"Vigie (mail)": (None, _constats("mail")),
                      "checkdmarc": ("checkdmarc", _constats("checkdmarc"))}},
    "chiffrement": {
        "titre": "Quelles versions du chiffrement le site accepte-t-il ?",
        "besoin": "domaine",
        "candidats": {"SSLyze": ("sslyze", _chiffrement_sslyze),
                      "tlsx": ("tlsx", _chiffrement_tlsx)}},
    "logiciels_troues": {
        "titre": "Quels logiciels d'un dossier ont des failles connues ?",
        "besoin": "dossier",
        "candidats": {"Grype": ("grype", _troues_grype), "Trivy": ("trivy", _troues_trivy)}},
    "secrets": {
        "titre": "Quels mots de passe ou jetons traînent dans un dossier de code ?",
        "besoin": "dossier",
        "candidats": {"Gitleaks": ("gitleaks", _secrets_gitleaks),
                      "TruffleHog": ("trufflehog", _secrets_trufflehog)}},
}


# --- La comparaison elle-même -------------------------------------------------------

def recommander(trouves, durees):
    """La règle de décision, en clair. `trouves` : {outil: ensemble} des outils qui ont marché."""
    if not trouves:
        return "Aucun outil n'a pu répondre : rien à comparer."
    tout = set().union(*trouves.values())
    if not tout:
        plus_rapide = min(trouves, key=lambda o: durees.get(o, 0))
        return (f"Aucun outil ne trouve rien : impossible de les départager sur ce point. "
                f"À résultat égal, le plus rapide est {plus_rapide}.")
    complets = [o for o, e in trouves.items() if e == tout]
    if complets:
        garde = min(complets, key=lambda o: durees.get(o, 0))
        autres = [o for o in trouves if o != garde]
        return (f"Garder {garde} : il voit tout ce que les autres voient"
                + (f", en {durees.get(garde, 0):.0f} s." if durees.get(garde) else ".")
                + (f" {', '.join(autres)} n'apporte{'nt' if len(autres) > 1 else ''} rien de plus "
                   "ici." if autres else ""))
    apports = {o: len(e - set().union(*(v for k, v in trouves.items() if k != o)))
               for o, e in trouves.items()}
    utiles = [o for o, n in apports.items() if n]
    inutiles = [o for o, n in apports.items() if not n]
    texte = "Garder " + " et ".join(utiles) + " : chacun voit des choses que les autres ratent."
    if inutiles:
        texte += (f" {', '.join(inutiles)} n'apporte{'nt' if len(inutiles) > 1 else ''} rien que "
                  "les autres n'aient déjà.")
    return texte


def comparer(question, cible, date=None):
    """cible : {"domaine": ..., "pseudo": ..., "accord": bool, "dossier": ...}."""
    if question not in QUESTIONS:
        raise ValueError(f"Question inconnue : {question} (connues : {', '.join(QUESTIONS)})")
    fiche = QUESTIONS[question]
    besoin = fiche["besoin"]
    if besoin == "dossier":
        cible = dict(cible, dossier=os.path.abspath(os.path.expanduser(cible.get("dossier") or "")))
        if not os.path.isdir(cible["dossier"]):
            raise ValueError("Il faut un dossier existant (--dossier).")
    elif not cible.get(besoin):
        raise ValueError(f"Il faut : {besoin}.")
    trouves, durees, echecs = {}, {}, {}
    for nom, (commande, fonction) in fiche["candidats"].items():
        if commande and not (outils.disponible(commande) if commande in outils.CATALOGUE
                            else outils.trouver(commande)):
            echecs[nom] = "pas installé"
            continue
        debut = time.time()
        with tempfile.TemporaryDirectory() as dossier:
            try:
                trouves[nom] = set(fonction(cible, dossier))
            except ControleImpossible as empechement:
                echecs[nom] = str(empechement)
            except Exception as erreur:  # un outil qui plante ne doit pas arrêter le banc
                echecs[nom] = f"plantage : {erreur}"
        durees[nom] = round(time.time() - debut, 1)
    tout = set().union(*trouves.values()) if trouves else set()
    lignes = [{"element": e, "vu_par": [o for o in trouves if e in trouves[o]]}
              for e in sorted(tout)]
    seuls = {o: sorted(e - set().union(*(v for k, v in trouves.items() if k != o)))
             for o, e in trouves.items()}
    return {"question": question, "titre": fiche["titre"],
            "cible": cible.get("domaine") or cible.get("pseudo") or cible.get("dossier"),
            "date": date or datetime.date.today().isoformat(), "version": __version__,
            "outils": {o: {"trouve": len(trouves[o]) if o in trouves else None,
                           "duree": durees.get(o), "echec": echecs.get(o, "")}
                       for o in fiche["candidats"]},
            "communs": sorted(set.intersection(*trouves.values())) if len(trouves) > 1 else [],
            "seuls": seuls, "lignes": lignes,
            "recommandation": recommander(trouves, durees)}


def en_texte(resultat):
    l = [f"BANC DE COMPARAISON — {resultat['titre']}", f"Cible : {resultat['cible']}", ""]
    for nom, o in resultat["outils"].items():
        if o["echec"]:
            l.append(f"  {nom:18} non réalisé : {o['echec']}")
        else:
            l.append(f"  {nom:18} {o['trouve']} trouvé(s) en {o['duree']} s")
    l += ["", f"Vu par tous : {len(resultat['communs'])}"]
    for nom, seuls in resultat["seuls"].items():
        l.append(f"Seulement {nom} ({len(seuls)}) : " + (", ".join(seuls[:20]) or "rien"))
    l += ["", "Recommandation : " + resultat["recommandation"]]
    return "\n".join(l)


def en_html(resultat):
    e = html.escape
    outils_ok = [o for o, v in resultat["outils"].items() if not v["echec"]]
    tete = "".join(f"<th>{e(o)}</th>" for o in outils_ok)
    corps = "".join(
        "<tr><td>" + e(str(l["element"])) + "</td>" +
        "".join(f"<td class='{'oui' if o in l['vu_par'] else 'non'}'>"
                f"{'✓' if o in l['vu_par'] else '—'}</td>" for o in outils_ok) + "</tr>"
        for l in resultat["lignes"][:500])
    lignes_outils = "".join(
        f"<li><b>{e(o)}</b> : " + (f"non réalisé ({e(v['echec'])})" if v["echec"]
                                   else f"{v['trouve']} trouvé(s) en {v['duree']} s") + "</li>"
        for o, v in resultat["outils"].items())
    return f"""<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Banc de comparaison</title>
<style>body{{font-family:system-ui,sans-serif;max-width:900px;margin:24px auto;padding:0 16px;color:#1c2533}}
table{{border-collapse:collapse;width:100%;font-size:14px}}td,th{{border-bottom:1px solid #e1e6ee;padding:6px 8px;text-align:left}}
td.oui{{color:#1e7a46;font-weight:700}}td.non{{color:#b3261e}}.reco{{background:#eef6f0;border-left:4px solid #1e7a46;padding:12px 14px;border-radius:8px}}</style>
</head><body><h1>{e(resultat['titre'])}</h1><p>Cible : <b>{e(str(resultat['cible']))}</b> — {e(resultat['date'])}</p>
<p class="reco"><b>Recommandation :</b> {e(resultat['recommandation'])}</p>
<ul>{lignes_outils}</ul><p>Vu par tous : <b>{len(resultat['communs'])}</b></p>
<table><tr><th>Élément</th>{tete}</tr>{corps}</table>
<p style="color:#5b6b82;font-size:13px">Banc de comparaison Vigie {e(resultat['version'])}.</p></body></html>"""


def ecrire(resultat, dossier="comparaisons"):
    os.makedirs(dossier, exist_ok=True)
    base = os.path.join(dossier, f"banc_{resultat['question']}_{resultat['date']}")
    with open(base + ".html", "w", encoding="utf-8") as f:
        f.write(en_html(resultat))
    with open(base + ".json", "w", encoding="utf-8") as f:
        json.dump(resultat, f, ensure_ascii=False, indent=2)
    return base + ".html"
