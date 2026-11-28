"""L'onglet « Bilan d'une cible » : tous les résultats d'une cible réunis en un bilan.

La mécanique (ranger, traduire, regrouper, faire le rapport) est dans bilan.py. Ici :
- la liste des cibles qui ont des résultats ;
- le bilan d'une cible : les lancements (décochables), puis les trouvailles sans
  doublons, avec « vu par » ;
- l'import d'un rapport ZAP (le fichier est lu par la page, rien n'est envoyé ailleurs) ;
- le bouton qui écrit le rapport habituel (technique + dirigeant).
"""
import html
import urllib.parse

from . import bilan, rapport
from .modeles import CRITIQUE, IMPORTANT, INFO, OK

CSS = """
.cibles-liste { list-style:none; padding:0; display:grid;
  grid-template-columns:repeat(auto-fill,minmax(260px,1fr)); gap:10px; }
.cibles-liste a { display:block; padding:12px 14px; border:1px solid var(--trait);
  border-radius:10px; text-decoration:none; color:var(--navy); font-weight:700; }
.cibles-liste a:hover { background:var(--fond); }
.cibles-liste small { display:block; font-weight:400; color:#5c6676; }
.lancements { list-style:none; padding:0; margin:6px 0 12px; }
.lancements li { padding:6px 0; border-bottom:1px solid var(--trait); font-size:14px; }
.lancements label { display:flex; gap:8px; align-items:flex-start; font-weight:400; }
.lancements input { width:auto; margin-top:3px; }
.lancements small { color:#5c6676; }
.bilan-tableau { width:100%; border-collapse:collapse; margin:6px 0 14px; }
.bilan-tableau td { padding:7px 8px; border-bottom:1px solid var(--trait); vertical-align:top;
  font-size:14px; }
.bilan-tableau .qui { color:#5c6676; font-size:12.5px; white-space:nowrap; }
.niv { display:inline-block; font-size:11px; font-weight:800; padding:2px 7px; border-radius:6px;
  white-space:nowrap; }
.niv-CRITIQUE { background:#b3261e; color:#fff; }
.niv-IMPORTANT { background:#e0a43b; color:#13294b; }
.niv-INFO { background:#e4edfb; color:#1c4e8a; }
.niv-OK { background:#e6f2ec; color:#2e7d4f; }
.import-zap label { display:block; font-weight:700; margin:8px 0; }
.import-zap input { display:block; width:100%; box-sizing:border-box; margin-top:4px;
  padding:8px 10px; border:1px solid var(--trait); border-radius:8px; font:inherit; font-weight:400; }
.recoupe { font-size:11px; font-weight:800; color:#2e7d4f; }
.a-confirmer { font-size:11px; font-weight:800; color:#9a5f00; }
.boutons { display:flex; flex-wrap:wrap; gap:10px; margin:10px 0; }
.boutons button { padding:10px 16px; border-radius:9px; border:0; background:#13294b; color:#fff;
  font:inherit; font-weight:700; cursor:pointer; }
.boutons .secondaire { background:#e4edfb; color:#13294b; }
.import-zap { border:1px solid var(--trait); border-radius:12px; padding:14px 16px; margin:18px 0; }
"""

_NIVEAU = {CRITIQUE: "Grave", IMPORTANT: "À corriger", INFO: "Pour info", OK: "Correct"}
_MAX_LIGNES = 80


def _entete(titre, sous_titre):
    return f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vigie - {html.escape(titre)}</title><style>{rapport.CSS}{CSS}
.refus {{ padding:13px 16px; border-radius:10px; border-left:4px solid #b3261e;
  background:#fbeceb; color:#5a1410; margin:4px 0 14px; }}
.reussi {{ padding:13px 16px; border-radius:10px; border-left:4px solid #1e7a46;
  background:#e6f2ec; margin:4px 0 14px; }}
.reussi p {{ margin:4px 0; }}</style></head><body><main>
<div class="couv"><div class="enseigne">{rapport.LOGO}<div class="mot">Vigie<small>Sécurité</small></div></div>
<h1>{html.escape(titre)}</h1><div class="meta"><span>{html.escape(sous_titre)}</span></div></div>
<div class="corps">"""


_PIED = "</div></main></body></html>"


def _bandeau(message="", ok=""):
    if message:
        return ("<div class='refus'><b>Ça n'a pas marché :</b><br>"
                f"{html.escape(message)}</div>")
    if ok:
        return f"<div class='reussi'><p>{html.escape(ok)}</p></div>"
    return ""


def _import_zap(cible=""):
    e = html.escape
    return f"""<div class="import-zap"><h2>Ajouter un rapport ZAP</h2>
<p>Dans ZAP : menu « Rapport » → « Générer un rapport », modèle « Traditional JSON
Report » (ou XML). Puis choisis le fichier ici : Vigie le lit et l'ajoute au bilan.</p>
<form method="post" action="/bilan/zap" id="form-zap">
<label>Cible analysée par ZAP<input name="cible" value="{e(cible, quote=True)}"
 placeholder="pavillon-noir.tech"></label>
<label>Fichier du rapport ZAP<input type="file" id="fichier-zap" accept=".json,.xml"></label>
<textarea name="contenu" id="contenu-zap" hidden></textarea>
<div class="boutons"><button type="submit">Ajouter ce rapport au bilan</button></div>
</form>
<script>
document.getElementById("form-zap").addEventListener("submit", function (ev) {{
  var choix = document.getElementById("fichier-zap").files[0];
  if (!choix) {{ return; }}
  ev.preventDefault();
  var form = this, lecteur = new FileReader();
  lecteur.onload = function () {{
    document.getElementById("contenu-zap").value = lecteur.result; form.submit();
  }};
  lecteur.readAsText(choix);
}});
</script></div>"""


def page(dossier, message="", ok=""):
    """La liste des cibles qui ont des résultats."""
    liste = bilan.cibles(dossier)
    if liste:
        cartes = "".join(
            f"<li><a href='/bilan?cible={urllib.parse.quote(nom)}'>{html.escape(nom)}"
            f"<small>{n} lancement{'s' if n > 1 else ''} · dernier le "
            f"{dernier[6:8]}/{dernier[4:6]}/{dernier[:4]}</small></a></li>"
            for nom, n, dernier in liste)
        corps = f"<h2>Choisis une cible</h2><ul class='cibles-liste'>{cartes}</ul>"
    else:
        corps = ("<p>Aucun résultat gardé pour l'instant. Lance un outil (« Lancer un "
                 "outil »), un combo (« Combos ») ou un outil manuel : son résultat sera "
                 "rangé ici tout seul, dans le dossier de sa cible.</p>")
    return (_entete("Bilan d'une cible", "Tous les outils lancés sur une cible, réunis")
            + _bandeau(message, ok)
            + "<p>Vigie garde le résultat de chaque outil lancé, rangé par cible. Ici, il "
              "les <b>réunit</b> : chaque trouvaille n'apparaît qu'une fois, avec les "
              "outils qui l'ont vue, les plus graves d'abord.</p>"
            + corps + _import_zap() + _PIED)


def _choisis(dossier, cible, garder):
    tous = bilan.lancements(dossier, cible)
    if garder is None:
        return tous, tous
    return tous, [l for l in tous if l["id"] in garder]


def _ligne_lancement(l, coche):
    e = html.escape
    quand = (l.get("quand") or "").replace("T", " à ")[:19]
    etat = "" if l.get("reussi", True) else " · n'a rien donné"
    garde = "" if l.get("garde") in ("passif", "", None) else f" · {l['garde']}"
    return (f"<li><label><input type='checkbox' name='garder' value='{e(l['id'], quote=True)}'"
            f"{' checked' if coche else ''}><span><b>{e(l.get('outil', '?'))}</b> sur "
            f"{e(l.get('cible', ''))}<br><small>{e(quand)} · {e(l.get('depuis', ''))}"
            f"{e(garde)}{e(etat)}</small></span></label></li>")


def _tableau(liste):
    e = html.escape
    lignes = []
    for t in liste[:_MAX_LIGNES]:
        marque = ""
        if len(t["outils"]) > 1:
            marque = "<span class='recoupe'>recoupé</span>"
        elif t["niveau"] in (CRITIQUE, IMPORTANT):
            marque = "<span class='a-confirmer'>à confirmer</span>"
        lignes.append(
            f"<tr><td><span class='niv niv-{t['niveau']}'>{_NIVEAU[t['niveau']]}</span></td>"
            f"<td>{e(t['texte'])}</td><td class='qui'>vu par {e(', '.join(t['outils']))}"
            f"<br>{marque}</td></tr>")
    reste = len(liste) - _MAX_LIGNES
    suite = f"<p class='av-petit'>… et {reste} autres.</p>" if reste > 0 else ""
    return f"<table class='bilan-tableau'>{''.join(lignes)}</table>{suite}"


def page_cible(dossier, cible, garder=None, message="", ok=""):
    """Le bilan d'une cible. `garder` = les lancements cochés (None = tous)."""
    e = html.escape
    tous, choisis = _choisis(dossier, cible, garder)
    if not tous:
        return page(dossier, f"Aucun résultat gardé pour « {cible} ».")
    ids = {l["id"] for l in choisis}
    regroupe = bilan.regrouper(choisis, bilan.cle_cible(cible))
    morceaux = [_bandeau(message, ok)]
    morceaux.append("<h2>Bilan commun</h2><div class='reussi'>"
                    + "".join(f"<p>{e(p)}</p>" for p in regroupe["phrases"]) + "</div>")
    if regroupe["actifs"]:
        morceaux.append("<p class='av-petit'>Certains résultats viennent d'outils actifs : "
                        + e(" ; ".join(regroupe["actifs"])) + ". Ils ne vont jamais dans "
                        "un diagnostic gratuit.</p>")
    for genre in bilan.ORDRE_GENRES:
        liste = regroupe["genres"].get(genre)
        if liste:
            morceaux.append(f"<h2>{e(bilan.GENRES[genre])} ({len(liste)})</h2>"
                            + _tableau(liste))
    lancements = "".join(_ligne_lancement(l, l["id"] in ids) for l in tous)
    q = urllib.parse.quote(cible)
    morceaux.append(f"""<h2>Les lancements réunis</h2>
<p>Décoche un lancement pour le retirer du bilan (un essai raté, un vieux scan…).</p>
<form method="get" action="/bilan"><input type="hidden" name="cible" value="{e(cible, quote=True)}">
<input type="hidden" name="choix" value="1"><ul class="lancements">{lancements}</ul>
<div class="boutons"><button type="submit" class="secondaire">Refaire le bilan avec ces
lancements</button>
<button type="submit" formmethod="post" formaction="/bilan/rapport">Faire le rapport
(technique + dirigeant)</button></div></form>
<p class="av-petit">Le rapport est écrit dans le dossier « rapports », comme celui du
diagnostic. Relis-le toujours avant de l'envoyer.</p>""")
    morceaux.append(_import_zap(cible))
    morceaux.append(f"<p><a href='/bilan'>Autre cible</a> · <a href='/combos'>Combos</a> · "
                    f"<a href='/bilan?cible={q}'>Tout réafficher</a></p>")
    return (_entete(f"Bilan de {cible}", f"{len(choisis)} lancement"
                    f"{'s' if len(choisis) > 1 else ''} réuni{'s' if len(choisis) > 1 else ''}")
            + "".join(morceaux) + _PIED)


def _champs(texte):
    return urllib.parse.parse_qs(texte, keep_blank_values=True)


def lire_requete(requete):
    """(cible, garder ou None) depuis la requête GET ou le corps POST."""
    c = _champs(requete)
    cible = (c.get("cible", [""])[0] or "").strip()[:200]
    garder = set(c.get("garder", [])) if c.get("choix") else None
    return cible, garder


def importer(dossier, corps):
    """Ajoute un rapport ZAP. Renvoie (cible, phrase). Lève bilan.ImportImpossible."""
    c = _champs(corps)
    cible = (c.get("cible", [""])[0] or "").strip()[:200]
    contenu = c.get("contenu", [""])[0] or ""
    if not contenu.strip():
        raise bilan.ImportImpossible("Choisis le fichier du rapport ZAP.")
    nombre = bilan.importer_zap(dossier, cible, contenu)
    return cible, (f"Rapport ZAP ajouté : {nombre} alerte{'s' if nombre > 1 else ''} lue"
                   f"{'s' if nombre > 1 else ''}.")


def faire_rapport(dossier, corps, sortie):
    """Écrit le rapport du bilan. Renvoie le nom du rapport (pour /rapport/<nom>)."""
    cible, garder = lire_requete(corps)
    _, choisis = _choisis(dossier, cible, garder)
    if not choisis:
        raise bilan.ImportImpossible("Coche au moins un lancement pour faire le rapport.")
    regroupe = bilan.regrouper(choisis, bilan.cle_cible(cible))
    return bilan.faire_rapport(regroupe, bilan.cle_cible(cible), sortie)
