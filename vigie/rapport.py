"""Transforme les constats en rapport lisible par un patron : texte, données, page imprimable."""
import html
import json
import os

from . import __version__, scenarios
from .modeles import CRITIQUE, IMPORTANT, INFO, OK, fusionner, note, trier

LIBELLES = {CRITIQUE: "Critique", IMPORTANT: "Important", INFO: "À savoir", OK: "Correct"}


def date_fr(date):
    """2026-11-20 -> 20/11/2026"""
    morceaux = date.split("-")
    return "/".join(reversed(morceaux)) if len(morceaux) == 3 else date


def construire(societe, cible, date, constats, brut, non_realises, autorisation):
    constats = fusionner(constats)
    blocs = {}
    for constat in constats:
        blocs.setdefault(constat.bloc, []).append(constat)
    # La note globale est celle du domaine le plus faible : on vaut son maillon faible.
    # Ainsi elle tombe toujours sur une lettre déjà affichée, et jamais sous le pire bloc.
    notes_blocs = {nom: note(liste) for nom, liste in blocs.items()}
    return {
        "outil": "Vigie",
        "version": __version__,
        "societe": societe,
        "cible": cible,
        "date": date,
        "note_globale": min(notes_blocs.values()) if notes_blocs else None,
        "scenarios": scenarios.scenarios_pour([c.en_dict() for c in constats]),
        "blocs": {nom: {"note": notes_blocs[nom], "constats": [c.en_dict() for c in trier(liste)]}
                  for nom, liste in blocs.items()},
        "non_realises": non_realises,
        "autorisation": autorisation,
        "brut": brut,
    }


def _compte(rapport):
    compte = {}
    for bloc in rapport["blocs"].values():
        for constat in bloc["constats"]:
            compte[constat["niveau"]] = compte.get(constat["niveau"], 0) + 1
    return compte


def en_texte(rapport, public="technique"):
    """public='technique' : rapport complet (défaut). public='executif' : version patron."""
    lignes = [
        "VIGIE - DIAGNOSTIC DE SÉCURITÉ"
        + ("  (rapport exécutif)" if public == "executif" else "  (rapport technique)"),
        f"Société : {rapport['societe']}",
        f"Cible   : {rapport['cible']}",
        f"Date    : {date_fr(rapport['date'])}",
        "Note    : " + (f"{rapport['note_globale']} / 100  (classe {_lettre(rapport['note_globale'])})"
                        if rapport['note_globale'] is not None
                        else "non calculée (aucun contrôle réalisé)"),
        "",
    ]
    perimetre = _perimetre(rapport)
    if perimetre:
        lignes += [perimetre, ""]
    verdict = _verdict(rapport)
    if verdict:
        lignes += [f"Verdict : {verdict}", ""]
    compte = _compte(rapport)
    resume = ", ".join(f"{compte[n]} {LIBELLES[n].lower()}"
                       for n in (CRITIQUE, IMPORTANT, INFO, OK) if n in compte)
    lignes += [f"Résumé : {resume}", ""]
    priorites = _priorites(rapport)
    if priorites:
        lignes.append("PAR OÙ COMMENCER (du plus grave au moins grave) :")
        for numero, constat in enumerate(priorites, 1):
            lignes.append(f"  {numero}. [{LIBELLES[constat['niveau']]}] {constat['titre']}")
            if constat["correction"]:
                lignes.append(f"     {constat['correction']}")
        lignes += ["  Référentiel : guide d'hygiène informatique de l'ANSSI.", ""]
    if rapport.get("scenarios"):
        lignes.append("CE QU'UN ESCROC POURRAIT FAIRE (d'après ce qui a été trouvé) :")
        for scenario in rapport["scenarios"]:
            lignes.append(f"- {scenario['titre']}")
            lignes.append(f"  {scenario['texte']}")
        lignes.append("")
    for nom, bloc in rapport["blocs"].items():
        lignes += [f"=== {nom.upper()} : {bloc['note']} / 100  (classe {_lettre(bloc['note'])}) ===",
                   f"  {_strategie_bloc(bloc)}", ""]
        if public == "executif":
            continue
        for numero, constat in enumerate(bloc["constats"], 1):
            lignes.append(f"{numero}. [{LIBELLES[constat['niveau']]}] {constat['titre']}")
            lignes.append(f"   {constat['explication']}")
            if constat["correction"]:
                lignes.append(f"   Correction : {constat['correction']}")
            if constat.get("sources"):
                lignes.append(f"   Relevé par : {', '.join(constat['sources'])}")
            lignes.append("")
    if public == "executif":
        lignes += ["Le détail de chaque point et les contrôles non réalisés figurent dans "
                   "le rapport technique joint.", ""]
        return "\n".join(lignes)
    if rapport["non_realises"]:
        lignes.append("Contrôles non réalisés :")
        lignes += [f"- {element['module']} : {element['raison']}"
                   for element in rapport["non_realises"]]
        lignes.append("")
    return "\n".join(lignes)


# Le logo de Vigie : un œil dans un bouclier (vigilance + protection). SVG, net à toute taille.
LOGO = """<svg class="logo" viewBox="0 0 48 48" aria-hidden="true">
<path d="M24 3 42 9v13c0 11-7.6 19.5-18 23C13.6 41.5 6 33 6 22V9z" fill="#13294b"/>
<path d="M24 3 42 9v13c0 11-7.6 19.5-18 23C13.6 41.5 6 33 6 22V9z" fill="none"
 stroke="#e0a43b" stroke-width="1.5" opacity=".6"/>
<ellipse cx="24" cy="23" rx="12" ry="8" fill="none" stroke="#f3f5f9" stroke-width="2.2"/>
<circle cx="24" cy="23" r="4.1" fill="#e0a43b"/><circle cx="24" cy="23" r="1.6" fill="#13294b"/>
</svg>"""

COULEUR_NOTE = {"haute": "#2e7d4f", "moyenne": "#c07a12", "basse": "#b3261e"}

CSS = """
:root { color-scheme: light; --navy:#13294b; --or:#e0a43b; --encre:#1b2330; --gris:#5c6676;
  --trait:#e4e8ef; --fond:#eef1f6; }
* { box-sizing: border-box; }
body { margin:0; background:var(--fond); color:var(--encre);
  font:16px/1.6 "Inter",-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  -webkit-font-smoothing:antialiased; }
main { max-width:860px; margin:28px auto; background:#fff; border-radius:16px; overflow:hidden;
  box-shadow:0 8px 40px rgba(19,41,75,.10); }
.couv { background:linear-gradient(135deg,#13294b 0%,#1c3a68 100%); color:#fff;
  padding:34px 40px 30px; }
.enseigne { display:flex; align-items:center; gap:13px; }
.logo { width:44px; height:44px; flex:none; }
.mot { font-size:21px; font-weight:800; letter-spacing:.14em; text-transform:uppercase; }
.mot small { display:block; font-size:11px; font-weight:600; letter-spacing:.22em;
  color:var(--or); margin-top:2px; }
.couv h1 { font-size:27px; font-weight:800; margin:22px 0 4px; letter-spacing:-.01em; }
.meta { display:flex; flex-wrap:wrap; gap:4px 26px; font-size:14.5px; color:#c3cede; margin-top:10px; }
.meta b { color:#fff; font-weight:600; }
.synthese { display:flex; gap:30px; align-items:center; flex-wrap:wrap;
  padding:28px 40px; border-bottom:1px solid var(--trait); }
.score { display:flex; flex-direction:column; align-items:center; gap:8px; flex:none; }
.grade { width:40px; height:40px; border-radius:10px; display:flex; align-items:center;
  justify-content:center; font-weight:800; font-size:22px; color:#fff; }
.grade.note-A,.grade.note-B { background:#2e7d4f; } .grade.note-C { background:#c07a12; }
.grade.note-D { background:#c0560f; } .grade.note-E,.grade.note-F { background:#b3261e; }
.apercu { flex:1; min-width:240px; }
.verdict { font-size:17px; font-weight:600; color:var(--encre); margin:0 0 14px; }
.route { margin:0 40px; padding:22px 24px; background:#f4f7fb; border:1px solid #d6e0ee;
  border-radius:12px; }
.route h2 { margin:0 0 4px; } .route h2::after { background:#d6e0ee; }
.route .sous { font-size:13.5px; color:var(--gris); margin:0 0 14px; }
.route-liste { list-style:none; padding:0; margin:0; }
.route-liste li { display:flex; gap:14px; align-items:flex-start; padding:12px 0;
  border-top:1px solid #d6e0ee; }
.route-liste li:first-child { border-top:0; }
.rang { flex:none; width:28px; height:28px; border-radius:50%; color:#fff; font-weight:800;
  font-size:14px; display:flex; align-items:center; justify-content:center; margin-top:1px; }
.rang.CRITIQUE { background:#b3261e; } .rang.IMPORTANT { background:#c07a12; }
.route-liste b { font-size:15.5px; } .route-liste p { margin:4px 0 0; font-size:14px;
  color:#43494f; }
.route .ref { font-size:12.5px; color:var(--gris); margin:14px 0 0; }
.jauge { position:relative; width:118px; height:118px; flex:none; }
.jauge svg { transform:rotate(-90deg); }
.jauge .val { position:absolute; inset:0; display:flex; flex-direction:column;
  align-items:center; justify-content:center; font-weight:800; font-size:34px; color:var(--navy); }
.jauge .val small { font-size:13px; font-weight:600; color:var(--gris); margin-top:-2px; }
.chips { display:flex; flex-wrap:wrap; gap:10px 12px; }
.chip { display:flex; align-items:center; gap:8px; padding:8px 14px; border-radius:999px;
  background:var(--fond); font-size:14.5px; font-weight:600; }
.chip .pastille { width:10px; height:10px; border-radius:50%; }
.chip b { font-weight:800; }
.corps { padding:12px 40px 8px; }
h2 { font-size:13px; font-weight:800; letter-spacing:.12em; text-transform:uppercase;
  color:var(--gris); margin:34px 0 14px; display:flex; align-items:center; gap:12px; }
h2::after { content:""; flex:1; height:1px; background:var(--trait); }
h2 .scoreb { flex:none; font-size:12px; font-weight:800; letter-spacing:0; color:var(--navy);
  background:var(--fond); padding:3px 10px; border-radius:999px; text-transform:none; }
.constat { border:1px solid var(--trait); border-left:4px solid var(--gris); border-radius:12px;
  padding:16px 20px; margin:14px 0; break-inside:avoid; }
.etiquette { display:inline-block; font-size:11px; font-weight:800; letter-spacing:.08em;
  text-transform:uppercase; padding:3px 9px; border-radius:6px; margin-bottom:8px; }
.constat h3 { font-size:17px; font-weight:700; margin:0 0 6px; }
.constat p { margin:0 0 8px; color:#333c49; }
.correction { background:var(--fond); border-radius:8px; padding:10px 13px; font-size:14.5px;
  margin:10px 0 0 !important; }
.correction b { color:var(--navy); }
.sources { font-size:12.5px !important; color:var(--gris); margin:8px 0 0 !important; }
.CRITIQUE { border-left-color:#b3261e; } .CRITIQUE .etiquette { background:#fbe9e7; color:#b3261e; }
.IMPORTANT { border-left-color:#c07a12; } .IMPORTANT .etiquette { background:#fcf0dc; color:#9a5f00; }
.INFO { border-left-color:#2f5fa7; } .INFO .etiquette { background:#e8effa; color:#2f5fa7; }
.OK { border-left-color:#2e7d4f; } .OK .etiquette { background:#e6f2ec; color:#2e7d4f; }
.pastille.CRITIQUE{background:#b3261e;} .pastille.IMPORTANT{background:#c07a12;}
.pastille.INFO{background:#2f5fa7;} .pastille.OK{background:#2e7d4f;}
.nonfait { list-style:none; padding:0; margin:0; }
.nonfait li { font-size:14px; color:var(--gris); padding:7px 0; border-bottom:1px solid var(--trait); }
.menace { margin:0 40px; padding:22px 24px; background:#fdf6f5; border:1px solid #f0cfca;
  border-left:5px solid #b3261e; border-radius:12px; }
.menace h2 { margin:0 0 4px; color:#8a1d16; }
.menace h2::after { background:#f0cfca; }
.menace .sous { font-size:13.5px; color:#8a6a67; margin:0 0 14px; }
.menace .cas { padding:12px 0; border-top:1px solid #f0cfca; }
.menace .cas:first-of-type { border-top:0; }
.menace .cas h3 { font-size:16px; margin:0 0 5px; color:#1b2330; }
.menace .cas p { margin:0; color:#43362f; font-size:14.5px; }
footer { padding:22px 40px 30px; font-size:12.5px; color:var(--gris);
  border-top:1px solid var(--trait); background:#fbfcfe; }
.perimetre { margin-top:16px; font-size:13px; color:#c3cede; }
.perimetre b { color:#fff; font-weight:600; }
.capture { margin:0; padding:24px 40px 0; }
.capture img { width:100%; max-height:260px; object-fit:cover; object-position:top;
  border-radius:10px; border:1px solid #d6dde8; display:block; }
.capture figcaption { font-size:12px; color:#5b6b82; margin-top:6px; }
.doctype { margin-left:auto; align-self:center; font-size:11px; font-weight:700;
  letter-spacing:.1em; text-transform:uppercase; color:var(--or);
  border:1px solid rgba(224,164,59,.55); border-radius:999px; padding:5px 13px; }
.suite { margin:24px 40px 8px; padding:16px 20px; background:#f4f7fb; border:1px dashed #c3d0e2;
  border-radius:12px; font-size:14px; color:#43494f; }
.suite b { color:var(--navy); }
.domaines { padding:26px 40px 8px; }
.cartes { display:grid; grid-template-columns:repeat(auto-fit,minmax(230px,1fr)); gap:14px; }
.carte { border:1px solid var(--trait); border-radius:12px; padding:16px 18px;
  display:flex; gap:14px; align-items:flex-start; }
.carte .note-bloc { flex:none; width:38px; height:38px; border-radius:9px; color:#fff;
  font-weight:800; font-size:19px; display:flex; align-items:center; justify-content:center; }
.carte .infos { flex:1; min-width:0; }
.carte .nom { font-size:15.5px; font-weight:700; margin:0 0 2px; }
.carte .compte { font-size:12.5px; color:var(--gris); margin:0 0 7px; }
.carte .strat { font-size:13.5px; color:#43494f; margin:0; }
@media print { body{background:#fff;} main{box-shadow:none; margin:0; max-width:none; border-radius:0;} }
"""


def _jauge(note):
    """Anneau de score façon tableau de bord. Vert haut, ambre moyen, rouge bas."""
    if note is None:
        couleur, affiche = "#9aa3af", "–"
    else:
        couleur = (COULEUR_NOTE["haute"] if note >= 80
                   else COULEUR_NOTE["moyenne"] if note >= 50 else COULEUR_NOTE["basse"])
        affiche = str(note)
    r, circ = 52, 326.7
    rempli = 0 if note is None else circ * (note / 100)
    return (f'<div class="jauge"><svg width="118" height="118" viewBox="0 0 118 118">'
            f'<circle cx="59" cy="59" r="{r}" fill="none" stroke="#e8ecf2" stroke-width="11"/>'
            f'<circle cx="59" cy="59" r="{r}" fill="none" stroke="{couleur}" stroke-width="11"'
            f' stroke-linecap="round" stroke-dasharray="{rempli:.1f} {circ:.1f}"/></svg>'
            f'<div class="val">{affiche}<small>/ 100</small></div></div>')


def _lettre(note):
    """Note sur 100 -> lettre A..F, comme les plateformes de notation de sécurité."""
    if note is None:
        return "–"
    for seuil, lettre in ((90, "A"), (75, "B"), (60, "C"), (45, "D"), (25, "E")):
        if note >= seuil:
            return lettre
    return "F"


def _verdict(rapport):
    """Une phrase de décision en tête, façon « niveau de menace » d'Intruder."""
    compte = _compte(rapport)
    if rapport["note_globale"] is None:
        return ""
    if compte.get(CRITIQUE):
        return ("Des failles critiques sont ouvertes aujourd'hui : une mise en sécurité "
                "est nécessaire sans attendre.")
    if compte.get(IMPORTANT):
        return ("Pas de faille critique, mais des points importants à corriger pour "
                "réduire votre exposition.")
    return "Aucune faille majeure. Quelques réglages à surveiller, sans urgence."


def _priorites(rapport):
    """Les constats à régler en premier : critiques puis importants, dans l'ordre de gravité."""
    tous = [c for bloc in rapport["blocs"].values() for c in bloc["constats"]
            if c["niveau"] in (CRITIQUE, IMPORTANT)]
    tous.sort(key=lambda c: 0 if c["niveau"] == CRITIQUE else 1)
    return tous[:6]


def _feuille_route(rapport):
    """La feuille de route de remédiation, comme dans les rapports pros. Vide si rien à régler."""
    priorites = _priorites(rapport)
    if not priorites:
        return ""
    e = html.escape
    lignes = "".join(
        f'<li><span class="rang {c["niveau"]}">{i}</span><div>'
        f'<b>{e(c["titre"])}</b>'
        + (f'<p>{e(c["correction"])}</p>' if c["correction"] else "")
        + '</div></li>'
        for i, c in enumerate(priorites, 1))
    return (f'<section class="route"><h2>Par où commencer</h2>'
            f'<p class="sous">À régler dans cet ordre, du plus grave au moins grave.</p>'
            f'<ol class="route-liste">{lignes}</ol>'
            f'<p class="ref">Référentiel : guide d\'hygiène informatique de l\'ANSSI.</p>'
            f'</section>')


def _menace(rapport):
    """La section « ce qu'un escroc pourrait faire » — l'argument de vente. Vide si rien trouvé."""
    scenarios_ = rapport.get("scenarios") or []
    if not scenarios_:
        return ""
    e = html.escape
    cas = "".join(f'<div class="cas"><h3>{e(s["titre"])}</h3><p>{e(s["texte"])}</p></div>'
                  for s in scenarios_)
    return (f'<section class="menace"><h2>Ce qu\'un escroc pourrait faire</h2>'
            f'<p class="sous">Scénarios réels, rendus possibles par ce qui a été trouvé '
            f'ci-dessous. Rien ne dit qu\'une attaque est en cours — c\'est ce qui est '
            f'ouvert aujourd\'hui.</p>{cas}</section>')


def _capture(rapport):
    """La page d'accueil telle que la voit un visiteur (module apercu), si elle a été prise."""
    apercu = (rapport.get("brut") or {}).get("apercu", {}).get("apercu") or {}
    if not apercu.get("image_base64"):
        return ""
    type_image = "image/png" if apercu.get("type") == "image/png" else "image/jpeg"
    return (f'<figure class="capture"><img alt="Page d\'accueil du site" '
            f'src="data:{type_image};base64,{apercu["image_base64"]}">'
            f'<figcaption>Votre page d\'accueil, telle que la voit un visiteur le '
            f'{html.escape(date_fr(rapport["date"]))}.</figcaption></figure>')


def _perimetre(rapport):
    """Ce qui a été examiné et comment : le périmètre, en une phrase, pour la couverture."""
    domaines = list(rapport["blocs"].keys())
    if not domaines:
        return ""
    liste = ", ".join(domaines)
    methode = ("à partir d'informations publiques, sans action sur vos machines"
               if not rapport["autorisation"]
               else "contrôles autorisés par le dirigeant")
    return f"Périmètre : {liste} — {methode}."


def _strategie_bloc(bloc):
    """Une ligne de stratégie par domaine, déduite de ce qui a été trouvé (jamais inventée)."""
    niveaux = {c["niveau"] for c in bloc["constats"]}
    if CRITIQUE in niveaux:
        return "Des points critiques à traiter ici en priorité."
    if IMPORTANT in niveaux:
        return "Pas de critique, mais des corrections importantes à planifier."
    if INFO in niveaux:
        return "Rien de grave ; quelques réglages à surveiller."
    return "Domaine conforme, rien à faire."


def _synthese_blocs(rapport):
    """Le tableau de bord par domaine : une carte par bloc, note-lettre et stratégie."""
    if not rapport["blocs"]:
        return ""
    e = html.escape
    cartes = []
    for nom, bloc in rapport["blocs"].items():
        compte = {}
        for c in bloc["constats"]:
            compte[c["niveau"]] = compte.get(c["niveau"], 0) + 1
        detail = ", ".join(f"{compte[n]} {LIBELLES[n].lower()}"
                           for n in (CRITIQUE, IMPORTANT, INFO, OK) if n in compte) or "aucun constat"
        lettre = _lettre(bloc["note"])
        cartes.append(
            f'<div class="carte"><div class="note-bloc grade note-{lettre}">{lettre}</div>'
            f'<div class="infos"><p class="nom">{e(nom)}</p>'
            f'<p class="compte">{bloc["note"]} / 100 · {e(detail)}</p>'
            f'<p class="strat">{e(_strategie_bloc(bloc))}</p></div></div>')
    return (f'<section class="domaines"><h2>Vue par domaine</h2>'
            f'<div class="cartes">{"".join(cartes)}</div></section>')


def _corps_detaille(rapport):
    """Le détail par constat + contrôles non réalisés — le cœur du rapport technique."""
    e = html.escape
    corps = []
    for nom, bloc in rapport["blocs"].items():
        corps.append(f'<h2>{e(nom)}<span class="scoreb">{bloc["note"]} / 100</span></h2>')
        for constat in bloc["constats"]:
            correction = (f'<p class="correction"><b>À corriger :</b> {e(constat["correction"])}</p>'
                          if constat["correction"] else "")
            sources = (f'<p class="sources">Relevé par&nbsp;: {e(", ".join(constat["sources"]))}.</p>'
                       if constat.get("sources") else "")
            corps.append(
                f'<section class="constat {constat["niveau"]}">'
                f'<span class="etiquette">{e(LIBELLES[constat["niveau"]])}</span>'
                f'<h3>{e(constat["titre"])}</h3>'
                f'<p>{e(constat["explication"])}</p>{correction}{sources}</section>')
    if rapport["non_realises"]:
        corps.append('<h2>Contrôles non réalisés</h2><ul class="nonfait">')
        corps += [f'<li>{e(element["module"])} — {e(element["raison"])}</li>'
                  for element in rapport["non_realises"]]
        corps.append("</ul>")
    return f'<div class="corps">{"".join(corps)}</div>'


def en_html(rapport, public="technique"):
    """public='technique' : rapport complet (défaut). public='executif' : version patron, sans le détail."""
    e = html.escape
    compte = _compte(rapport)
    chips = "".join(
        f'<span class="chip"><span class="pastille {n}"></span><b>{compte[n]}</b> '
        f'{e(LIBELLES[n].lower())}</span>'
        for n in (CRITIQUE, IMPORTANT, INFO, OK) if n in compte)
    if public == "executif":
        corps_html = ('<section class="suite">Le détail de chaque point — explication, '
                      'correction, outil l\'ayant relevé — et les contrôles non réalisés '
                      'figurent dans le <b>rapport technique</b> joint.</section>')
        etiquette_doc = "Rapport exécutif"
    else:
        corps_html = _corps_detaille(rapport)
        etiquette_doc = "Rapport technique"
    autorisation = rapport["autorisation"]
    cadre = ("Contrôles réalisés à partir d'informations publiques, sans action sur vos machines."
             if not autorisation else
             f"Contrôles couverts par l'autorisation « {e(autorisation['fichier'])} » "
             f"(empreinte {e(autorisation['empreinte_sha256'][:16])}…).")
    note = rapport["note_globale"]
    return f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Diagnostic Vigie - {e(rapport['societe'])} — {e(etiquette_doc.lower())}</title>
<style>{CSS}</style></head>
<body><main>
<div class="couv">
<div class="enseigne">{LOGO}<div class="mot">Vigie<small>Sécurité</small></div>
<span class="doctype">{e(etiquette_doc)}</span></div>
<h1>Diagnostic de sécurité</h1>
<div class="meta"><span>Société&nbsp;: <b>{e(rapport['societe'])}</b></span>
<span>Cible&nbsp;: <b>{e(rapport['cible'])}</b></span>
<span>Date&nbsp;: <b>{e(date_fr(rapport['date']))}</b></span></div>
<p class="perimetre">{e(_perimetre(rapport))}</p>
</div>
{_capture(rapport)}
<div class="synthese">
<div class="score">{_jauge(note)}<div class="grade note-{_lettre(note)}">{_lettre(note)}</div></div>
<div class="apercu"><p class="verdict">{e(_verdict(rapport))}</p>
<div class="chips">{chips}</div></div></div>
{_synthese_blocs(rapport)}
{_menace(rapport)}
{_feuille_route(rapport)}
{corps_html}
<footer>{cadre}<br>Rapport produit par Vigie {e(rapport['version'])}.
Ce diagnostic décrit l'état constaté à sa date et ne garantit pas l'absence d'autres failles.</footer>
</main></body></html>
"""


def ecrire(rapport, dossier):
    """Écrit les deux documents : technique (rapport.*) et exécutif (rapport-executif.*)."""
    os.makedirs(dossier, exist_ok=True)
    chemins = {}
    fichiers = (
        ("rapport.txt", en_texte(rapport)),
        ("rapport.html", en_html(rapport)),
        ("rapport.json", json.dumps(rapport, ensure_ascii=False, indent=2)),
        ("rapport-executif.txt", en_texte(rapport, public="executif")),
        ("rapport-executif.html", en_html(rapport, public="executif")),
    )
    for nom, contenu in fichiers:
        chemin = os.path.join(dossier, nom)
        with open(chemin, "w", encoding="utf-8") as fichier:
            fichier.write(contenu)
        chemins[nom] = chemin
    return chemins
