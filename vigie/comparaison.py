"""Mode comparaison : lancer plusieurs outils sur la même cible et montrer, en chiffres,
ce que chacun trouve — recoupé par d'autres, ou unique à lui.

C'est l'outil de mesure : il remplace « je crois que tel outil n'apporte rien »
par « voici ce qu'il a trouvé en plus ».
"""
import datetime
import html
import json
import os

from . import __version__, rapport
from .modeles import ORDRE, ControleImpossible
from .modules import MODULES

LIBELLES = rapport.LIBELLES


def comparer(cible, noms_modules, date=None):
    date = date or datetime.date.today().isoformat()
    par_module, non_realises = {}, []
    for nom in noms_modules:
        module = MODULES[nom]
        try:
            constats, _ = module["fonction"](cible)
        except ControleImpossible as empechement:
            non_realises.append({"module": module["nom"], "raison": str(empechement)})
            continue
        par_module[module["nom"]] = constats

    lignes = {}
    for nom_module, constats in par_module.items():
        for constat in constats:
            cle = constat.cle or ("titre::" + constat.titre)
            ligne = lignes.setdefault(cle, {"facette": constat.cle or constat.titre,
                                            "titre": constat.titre, "niveau": constat.niveau,
                                            "par": [], "niveaux": {}})
            if nom_module not in ligne["par"]:
                ligne["par"].append(nom_module)
            # on retient le verdict le plus grave de CE module sur cette facette
            ancien = ligne["niveaux"].get(nom_module)
            if ancien is None or ORDRE[constat.niveau] < ORDRE[ancien]:
                ligne["niveaux"][nom_module] = constat.niveau
            if ORDRE[constat.niveau] < ORDRE[ligne["niveau"]]:
                ligne["niveau"], ligne["titre"] = constat.niveau, constat.titre

    modules = list(par_module.keys())
    liste = sorted(lignes.values(), key=lambda l: (ORDRE[l["niveau"]], l["facette"]))
    for ligne in liste:
        if len(ligne["par"]) == 1:
            ligne["statut"] = "unique"            # vu par un seul outil
        elif len(set(ligne["niveaux"].values())) == 1:
            ligne["statut"] = "recoupé"           # plusieurs outils, même verdict : fiable
        else:
            ligne["statut"] = "divergent"         # plusieurs outils, verdicts différents
    uniques = {m: [l["titre"] for l in liste if l["par"] == [m]] for m in modules}
    return {
        "societe": cible.societe or cible.domaine, "cible": cible.domaine, "date": date,
        "modules": modules, "lignes": liste, "uniques": uniques,
        "non_realises": non_realises, "version": __version__,
    }


def en_texte(comp):
    out = [f"VIGIE - COMPARAISON D'OUTILS  ({comp['cible']}, {rapport.date_fr(comp['date'])})",
           "Outils comparés : " + ", ".join(comp["modules"]), ""]
    for ligne in comp["lignes"]:
        marque = "+".join("X" if m in ligne["par"] else "." for m in comp["modules"])
        tag = {"unique": "UNIQUE   ", "recoupé": "recoupé  ",
               "divergent": "DIVERGENT"}[ligne["statut"]]
        out.append(f"[{marque}] {tag} [{LIBELLES[ligne['niveau']]}] {ligne['titre']}")
    out.append("")
    for module, titres in comp["uniques"].items():
        if titres:
            out.append(f"Apporté UNIQUEMENT par {module} ({len(titres)}) :")
            out += [f"   - {t}" for t in titres]
    if comp["non_realises"]:
        out.append("")
        out.append("Non réalisés : " + "; ".join(
            f"{e['module']} ({e['raison']})" for e in comp["non_realises"]))
    return "\n".join(out)


CSS_COMP = """
.corps { padding:26px 40px 10px; }
table { border-collapse:collapse; width:100%; font-size:14.5px; margin:6px 0 18px; }
th,td { text-align:left; padding:11px 12px; border-bottom:1px solid var(--trait); }
th { font-size:12px; letter-spacing:.04em; text-transform:uppercase; color:var(--gris); }
th.outil { text-align:center; }
td.coche { text-align:center; font-weight:800; font-size:16px; }
td.coche.oui { color:#2e7d4f; } td.coche.non { color:#cdd4df; }
.facette { font-weight:700; }
.dot { display:inline-block; width:9px; height:9px; border-radius:50%; margin-right:7px;
  vertical-align:middle; }
.badge { font-size:11px; font-weight:800; padding:3px 9px; border-radius:999px; }
.badge.unique { background:#fcf0dc; color:#9a5f00; }
.badge.recoupe { background:#e6f2ec; color:#2e7d4f; }
.badge.divergent { background:#fbe9e7; color:#b3261e; }
.resume { display:flex; flex-wrap:wrap; gap:12px; margin:4px 0 22px; }
.carte { flex:1; min-width:180px; background:var(--fond); border-radius:12px; padding:16px 18px; }
.carte b { display:block; font-size:26px; color:var(--navy); }
.carte span { font-size:13.5px; color:var(--gris); }
"""


def en_html(comp):
    e = html.escape
    nb_recoupes = sum(1 for l in comp["lignes"] if l["statut"] == "recoupé")
    nb_uniques = sum(1 for l in comp["lignes"] if l["statut"] == "unique")
    nb_div = sum(1 for l in comp["lignes"] if l["statut"] == "divergent")
    carte_div = (f'<div class="carte"><b>{nb_div}</b><span>divergents (outils en désaccord)</span></div>'
                 if nb_div else "")
    cartes = (f'<div class="carte"><b>{nb_recoupes}</b><span>recoupés (verdict confirmé)</span></div>'
              f'<div class="carte"><b>{nb_uniques}</b><span>uniques à un seul outil</span></div>'
              f'{carte_div}')
    entetes = "".join(f'<th class="outil">{e(m)}</th>' for m in comp["modules"])
    lignes_html = []
    for ligne in comp["lignes"]:
        coches = "".join(
            f'<td class="coche {"oui" if m in ligne["par"] else "non"}">'
            f'{"✓" if m in ligne["par"] else "·"}</td>' for m in comp["modules"])
        badge = {"unique": ("unique", "unique à un outil"),
                 "recoupé": ("recoupe", "recoupé"),
                 "divergent": ("divergent", "divergent")}[ligne["statut"]]
        lignes_html.append(
            f'<tr><td class="facette"><span class="dot {ligne["niveau"]}"></span>'
            f'{e(ligne["titre"])}</td>{coches}'
            f'<td><span class="badge {badge[0]}">{badge[1]}</span></td></tr>')
    pastilles = ("<style>.dot.CRITIQUE{background:#b3261e}.dot.IMPORTANT{background:#c07a12}"
                 ".dot.INFO{background:#2f5fa7}.dot.OK{background:#2e7d4f}</style>")
    nonfait = ""
    if comp["non_realises"]:
        nonfait = "<h2>Non réalisés</h2><ul class='nonfait'>" + "".join(
            f"<li>{e(x['module'])} — {e(x['raison'])}</li>" for x in comp["non_realises"]) + "</ul>"
    return f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Comparaison d'outils - {e(comp['cible'])}</title>
<style>{rapport.CSS}{CSS_COMP}</style>{pastilles}</head><body><main>
<div class="couv">
<div class="enseigne">{rapport.LOGO}<div class="mot">Vigie<small>Comparaison</small></div></div>
<h1>Ce que chaque outil apporte</h1>
<div class="meta"><span>Cible&nbsp;: <b>{e(comp['cible'])}</b></span>
<span>Outils&nbsp;: <b>{e(', '.join(comp['modules']))}</b></span>
<span>Date&nbsp;: <b>{e(rapport.date_fr(comp['date']))}</b></span></div>
</div>
<div class="corps">
<div class="resume">{cartes}</div>
<table><thead><tr><th>Constat</th>{entetes}<th>Statut</th></tr></thead>
<tbody>{''.join(lignes_html)}</tbody></table>
{nonfait}
</div>
<footer>Un constat « recoupé » est confirmé par plusieurs outils (plus fiable). Un constat
« unique » n'est vu que par un seul outil : c'est ce qu'il apporte en plus.
Vigie {e(comp['version'])}.</footer>
</main></body></html>
"""


def ecrire(comp, dossier):
    os.makedirs(dossier, exist_ok=True)
    chemins = {}
    for nom, contenu in (("comparaison.txt", en_texte(comp)),
                         ("comparaison.html", en_html(comp)),
                         ("comparaison.json", json.dumps(comp, ensure_ascii=False, indent=2))):
        chemin = os.path.join(dossier, nom)
        with open(chemin, "w", encoding="utf-8") as fichier:
            fichier.write(contenu)
        chemins[nom] = chemin
    return chemins
