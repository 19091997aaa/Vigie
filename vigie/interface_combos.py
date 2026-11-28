"""L'onglet « Combos » : plusieurs outils enchaînés sur une cible, en un clic.

Les combos et leurs garde-fous sont dans combos.py. Ici : la page qui les présente, le
lancement en arrière-plan (un outil après l'autre) et la page de résultat, qui se met à
jour toute seule pendant que ça tourne.
"""
import html
import secrets
import threading
import urllib.parse

from . import avancement, bilan, combos, interface_outils, lancer_seul, manuel, mes_cibles, \
    presence, rapport

LANCEMENTS = {}
VERROU = threading.Lock()

CSS = """
.combos { display:grid; grid-template-columns:repeat(auto-fill,minmax(300px,1fr)); gap:14px; }
.combo { border:1px solid var(--trait); border-radius:12px; padding:16px 18px; background:#fff; }
.combo h2 { margin:6px 0 4px; font-size:18px; text-transform:none; letter-spacing:0;
  color:#13294b; display:block; }
.combo h2::after, .combo h2::before { display:none; content:none; }
.combo form label { display:block; font-weight:700; }
.combo input[name=cible] { display:block; width:100%; box-sizing:border-box; padding:9px 10px;
  margin:4px 0 8px; border:1px solid var(--trait); border-radius:8px; font:inherit; font-weight:400; }
.combo button { padding:10px 16px; border-radius:9px; border:0; background:#13294b; color:#fff;
  font:inherit; font-weight:700; cursor:pointer; }
.combo .but { font-size:14px; color:#3c4656; margin:6px 0 10px; line-height:1.45; }
.combo .note { font-size:13px; color:#5c6676; margin:8px 0; }
.combo ol { margin:4px 0 10px 20px; padding:0; font-size:14px; }
.combo label.accord { display:flex; font-weight:400; gap:8px; align-items:flex-start; font-size:13px; margin:8px 0; }
.combo .accord input { width:auto; margin-top:3px; }
.genre { display:inline-block; font-size:11px; font-weight:800; letter-spacing:.04em;
  padding:2px 8px; border-radius:6px; }
.g-passif { background:#e6f2ec; color:#2e7d4f; }
.g-personne { background:#fcf0dc; color:#9a5f00; }
.g-actif { background:#fbeceb; color:#8a1d16; }
.m-installe { font-size:11px; font-weight:800; padding:1px 6px; border-radius:6px;
  background:#2e7d4f; color:#fff; margin-left:6px; }
.m-absent { font-size:11px; font-weight:800; padding:1px 6px; border-radius:6px;
  background:#eceef1; color:#5c6676; margin-left:6px; }
.etapes { list-style:none; padding:0; margin:8px 0 16px; }
.etapes li { padding:8px 12px; border:1px solid var(--trait); border-radius:10px; margin:6px 0; }
.etapes .fait { border-color:#9fcfb3; background:#f2f9f5; }
.etapes .rate { border-color:#e6b9b5; background:#fdf4f3; }
.etapes .en_cours { border-color:#1c4e8a; background:#eef3fa; }
.etapes .saute { color:#5c6676; background:#f6f7f9; }
.etapes small { display:block; color:#3c4656; margin-top:3px; }
.trouvailles td { padding:4px 10px 4px 0; vertical-align:top; font-size:14px; }
.trouvailles .qui { color:#5c6676; font-size:12.5px; }
.outil-detail { border-top:1px solid var(--trait); padding:10px 0; }
"""

_SYMBOLE = {"attente": "○", "en_cours": "✱", "fait": "✓", "rate": "✗", "saute": "–"}


def _champs(corps):
    return urllib.parse.parse_qs(corps, keep_blank_values=True)


def _carte(combo, etats):
    e = html.escape
    outils = "".join(
        f"<li>{e(nom)}" + ("<span class='m-installe'>installé</span>" if etats.get(nom)
                          else "<span class='m-absent'>pas installé</span>") + "</li>"
        for nom, _ in combo["etapes"])
    exemple = {"domaine": "pavillon-noir.tech", "pseudo": "un pseudo",
               "email": "contact@exemple.fr"}[combo["cible"]]
    accord = ""
    if combo["genre"] == "personne":
        accord = (f"<label class='accord'><input type='checkbox' name='accord' value='oui'>"
                  f"<span>{e(combos.ACCORD)}</span></label>")
    note = f"<p class='note'>{e(combo['note'])}</p>" if combo.get("note") else ""
    manque = ""
    if combo.get("manquants"):
        manque = ("<p class='note'>Absent du catalogue : "
                  + e(", ".join(combo["manquants"])) + ".</p>")
    return f"""<div class="combo" id="combo-{combo['id']}">
<span class="genre g-{combo['genre']}">{e(combos.GENRES[combo['genre']])}</span>
<h2>{e(combo['titre'])}</h2><p class="but">{e(combo['but'])}</p>
<b>Les outils, dans l'ordre :</b><ol>{outils}</ol>{note}{manque}
<form method="post" action="/combo/lancer">
<input type="hidden" name="combo" value="{combo['id']}">
<label>Cible<input name="cible" placeholder="{e(exemple, quote=True)}"></label>{accord}
<button type="submit">Lancer ce combo</button></form></div>"""


def page(message=""):
    bandeau = ""
    if message:
        bandeau = ("<div class='refus'><b>Pourquoi ça ne part pas :</b><br>"
                   f"{html.escape(message)}</div>")
    etats = presence.etat()
    cartes = "".join(_carte(c, etats) for c in combos.resume_combos())
    return f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vigie - Combos</title><style>{rapport.CSS}{interface_outils.CSS}{CSS}</style></head><body><main>
<div class="couv"><div class="enseigne">{rapport.LOGO}<div class="mot">Vigie<small>Sécurité</small></div></div>
<h1>Combos d'outils</h1><div class="meta"><span>Plusieurs outils, une cible, un clic</span></div></div>
<div class="corps">{bandeau}
<p>Un combo lance plusieurs outils <b>l'un après l'autre</b> sur la même cible, sans
fenêtre (ça ménage la mémoire), puis <b>regroupe</b> ce qu'ils ont trouvé, sans doublons,
en disant quel outil a vu quoi. Un outil pas installé est simplement signalé.</p>
<p>Les combos <b>actifs</b> ne partent que sur <b>tes propres cibles</b> (à déclarer dans
<a href="/manuel">Outils manuels</a>). Les combos sur une <b>personne</b> demandent son
accord écrit. Aucun outil offensif n'est jamais lancé par un combo.</p>
<div class="combos">{cartes}</div>
<p><a href="/outils-un">Lancer un seul outil</a> · <a href="/">Accueil</a></p></div>
</main></body></html>"""


def lancer(corps, dossier_cibles=None, journal="journal", resultats=None):
    """Vérifie puis lance un combo en arrière-plan. Renvoie l'identifiant de suivi.
    Lève combos.Refus (raison en français) si le combo ne peut pas partir."""
    c = _champs(corps)
    ident_combo = (c.get("combo", [""])[0] or "").strip()[:40]
    cible = (c.get("cible", [""])[0] or "").strip()[:200]
    accord = (c.get("accord", [""])[0] or "") == "oui"

    def propre(nom, cible_outil):
        return interface_outils.verifier_propre_cible(nom, cible_outil, dossier_cibles)

    plan = combos.preparer(ident_combo, cible, accord=accord, propre=propre)
    combo = plan["combo"]
    if accord:
        manuel._journal(journal, {"combo": combo["titre"], "cible": plan["cible"],
                                  "accord": combos.ACCORD, "depuis": "Combos"})
    ident = secrets.token_urlsafe(9)
    etapes = [{"outil": e["outil"], "cible": e["cible"],
               "etat": "saute" if e["saute"] else "attente", "raison": e["raison"],
               "explication": [], "resultat": "", "brut": "", "reussi": False,
               "commande": "", "lance_par_vigie": False, "saute": e["saute"]}
              for e in plan["etapes"]]
    with VERROU:
        LANCEMENTS[ident] = {"etat": "en_cours", "combo": combo, "cible": plan["cible"],
                             "etapes": etapes, "suivi": None, "regroupe": None}

    def travail():
        sorties = []
        for etape, prevu in zip(etapes, plan["etapes"]):
            if prevu["saute"]:
                sorties.append({"outil": etape["outil"], "saute": True})
                continue
            nom = etape["outil"]
            suivi = avancement.Suivi(habituel=avancement.habituel(journal, nom))
            with VERROU:
                etape["etat"] = "en_cours"
                LANCEMENTS[ident]["suivi"] = suivi
            if prevu["propre"]:
                manuel._journal(journal, {
                    "outil": nom, "cible": etape["cible"], "resultat": "lancé",
                    "autorisation": "propre cible (" + mes_cibles.ATTESTATION + ")",
                    "depuis": "Combos : " + combo["titre"]})
            try:
                compte = lancer_seul.lancer(nom, etape["cible"], propre_ok=prevu["propre"],
                                            suivi=suivi)
                bon = combos.reussi(compte)
                if compte.get("lance"):
                    bilan.enregistrer(resultats, nom, etape["cible"], compte.get("sortie"),
                                      compte.get("erreurs"), "Combo : " + combo["titre"],
                                      "propre cible" if prevu["propre"] else "passif",
                                      compte.get("commande", ""), bon)
                brut = compte.get("sortie") or ""
                if compte.get("erreurs") and compte["erreurs"] not in brut:
                    brut += "\n" + compte["erreurs"]
                maj = {"etat": "fait" if bon else "rate", "reussi": bon,
                       "lance_par_vigie": True,
                       "explication": compte.get("explication", []),
                       "resultat": compte.get("traduction") if bon else "",
                       "brut": brut.strip(), "commande": compte.get("commande", "")}
                if bon and not compte.get("depasse"):
                    avancement.noter(journal, compte["outil"], compte.get("secondes"))
                sorties.append({"outil": nom, "reussi": bon, "lance_par_vigie": True,
                                "sortie": compte.get("sortie") or ""})
            except Exception as erreur:   # un outil qui plante n'arrête pas le combo
                maj = {"etat": "rate", "lance_par_vigie": True, "explication": [str(erreur)]}
                sorties.append({"outil": nom, "reussi": False, "lance_par_vigie": True,
                                "sortie": ""})
            with VERROU:
                etape.update(maj)
                LANCEMENTS[ident]["suivi"] = None
        regroupe = combos.regrouper(combo, plan["cible"], sorties)
        with VERROU:
            LANCEMENTS[ident].update(etat="fini", regroupe=regroupe)

    threading.Thread(target=travail, daemon=True).start()
    return ident


def _ligne_etape(etape, suivi):
    e = html.escape
    texte = f"{_SYMBOLE[etape['etat']]} <b>{e(etape['outil'])}</b> sur {e(etape['cible'])}"
    detail = {"attente": "En attente.", "fait": "Terminé.",
              "rate": "N'a pas donné de résultat (voir plus bas).",
              "saute": "Sauté : " + etape.get("raison", "")}.get(etape["etat"], "")
    if etape["etat"] == "en_cours" and suivi is not None:
        av = suivi.etat()
        detail = f"En cours ({av['ecoule']}). {av['phrase']} {av['activite']}"
    return f"<li class='{etape['etat']}'>{texte}<small>{e(detail)}</small></li>"


def page_resultat(ident):
    with VERROU:
        etat = LANCEMENTS.get(ident)
        if etat is None:
            return None
        etat = dict(etat, etapes=[dict(x) for x in etat["etapes"]])
    e = html.escape
    combo = etat["combo"]
    en_cours = etat["etat"] == "en_cours"
    rafraichir = "<meta http-equiv='refresh' content='3'>" if en_cours else ""
    faits = sum(1 for x in etat["etapes"] if x["etat"] in ("fait", "rate", "saute"))
    titre = (f"En cours : {faits} outil{'s' if faits > 1 else ''} sur "
             f"{len(etat['etapes'])} fini{'s' if faits > 1 else ''}" if en_cours
             else "Terminé")
    morceaux = []
    if en_cours:
        morceaux.append("<p>Les outils tournent l'un après l'autre. Cette page se met à "
                        "jour toute seule.</p>")
    morceaux.append("<ul class='etapes'>" + "".join(
        _ligne_etape(x, etat.get("suivi")) for x in etat["etapes"]) + "</ul>")
    regroupe = etat.get("regroupe")
    if regroupe:
        morceaux.append("<h2>Bilan commun</h2><div class='reussi'>"
                        + "".join(f"<p>{e(p)}</p>" for p in regroupe["bilan"]) + "</div>")
        for bloc in regroupe["blocs"]:
            lignes = "".join(
                f"<tr><td>{e(chose)}</td><td class='qui'>vu par {e(', '.join(qui))}</td></tr>"
                for chose, qui in bloc["lignes"])
            reste = (f"<p class='av-petit'>… et {bloc['reste']} autres (détail de chaque "
                     "outil plus bas).</p>" if bloc["reste"] else "")
            morceaux.append(f"<h2>{e(bloc['titre'])}</h2>"
                            f"<table class='trouvailles'>{lignes}</table>{reste}")
    if not en_cours:
        morceaux.append("<h2>Outil par outil</h2>")
        for x in etat["etapes"]:
            if x["etat"] == "saute":
                continue
            bloc = [f"<div class='outil-detail'><h3>{e(x['outil'])}</h3>"]
            if x.get("explication"):
                classe = "reussi" if x.get("reussi") else "explication"
                bloc.append(f"<div class='{classe}'>"
                            + "".join(f"<p>{e(p)}</p>" for p in x["explication"]) + "</div>")
            if x.get("resultat"):
                bloc.append(f"<pre>{e(x['resultat'])}</pre>")
            if x.get("brut") or x.get("commande"):
                detail = (f"Commande : {x['commande']}\n\n" if x.get("commande") else "") \
                    + (x.get("brut") or "")
                bloc.append("<details class='brut'><summary>Détail technique (sortie brute, "
                            f"en anglais)</summary><pre>{e(detail)}</pre></details>")
            morceaux.append("".join(bloc) + "</div>")
    return f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">{rafraichir}
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vigie - {e(combo['titre'])}</title><style>{rapport.CSS}{interface_outils.CSS}{CSS}</style></head><body><main>
<div class="couv"><div class="enseigne">{rapport.LOGO}<div class="mot">Vigie<small>Sécurité</small></div></div>
<h1>{e(combo['titre'])} sur {e(etat['cible'])}</h1><div class="meta"><span>{e(titre)}</span></div></div>
<div class="corps">{''.join(morceaux)}
<p><a href="/combos">Lancer un autre combo</a> · <a href="/">Accueil</a></p></div></main></body></html>"""
