"""L'onglet « Lancer un outil » : choisir UN outil du catalogue et le lancer seul.

On voit les 216 outils non payants rangés par famille, et ceux qui sont INSTALLÉS sur
cette machine (presence.py). Les outils PASSIFS (diag, sécurisation) se lancent ici, un
par un, sur la cible saisie. Les outils ACTIFS ou offensifs ne se lancent PAS ici : ils
renvoient vers l'onglet « Outils manuels », qui exige l'autorisation signée (règles
d'or). Tous les garde-fous sont dans lancer_seul.py.
"""
import html
import secrets
import threading

from . import __version__, fiches_outils, lancer_seul, presence, rapport, registre

LANCEMENTS = {}
VERROU = threading.Lock()

CSS = """
.familles { padding: 8px 40px 24px; }
.fam { margin: 22px 0 0; }
.fam h2 { margin: 0 0 10px; }
.liste-outils { display: grid; grid-template-columns: repeat(auto-fill,minmax(230px,1fr));
  gap: 8px 16px; list-style: none; padding: 0; margin: 0; }
.liste-outils li { font-size: 14px; padding: 6px 0; border-bottom: 1px solid var(--trait); }
.liste-outils .marque { font-size: 11px; font-weight: 800; letter-spacing: .04em;
  padding: 2px 7px; border-radius: 6px; margin-left: 6px; }
.m-auto { background: #fcf0dc; color: #9a5f00; }
.m-payant { background: #eceef1; color: #5c6676; }
.m-pret { background: #e6f2ec; color: #2e7d4f; }
.m-installe { background: #2e7d4f; color: #fff; }
.compte-installes { font-size: 15px; margin: 6px 0 0; }
.refus { padding: 13px 16px; border-radius: 10px; border-left: 4px solid #b3261e;
  background: #fbeceb; color: #5a1410; margin: 4px 0 14px; line-height: 1.5; }
.refus b { color: #8a1d16; }
.reussi { padding: 13px 16px; border-radius: 10px; border-left: 4px solid #1e7a46;
  background: #e6f2ec; margin: 4px 0 14px; line-height: 1.5; }
.explication { padding: 13px 16px; border-radius: 10px; border-left: 4px solid #9a5f00;
  background: #fcf0dc; margin: 4px 0 14px; line-height: 1.5; }
.explication p, .reussi p { margin: 4px 0; }
.aide-outil { font-size: 14px; color: #3c4656; margin: -4px 0 10px; min-height: 1.4em; }
details.brut summary { cursor: pointer; font-weight: 700; margin: 12px 0 6px; }
"""


def _champs(corps):
    import urllib.parse
    return urllib.parse.parse_qs(corps, keep_blank_values=True)


def _options_passifs(etats=None):
    """Un <select> des outils passifs non payants, groupés par famille.
    Ceux qui sont installés ici viennent en tête, marqués « ✓ »."""
    etats = etats or {}
    groupes = registre.par_famille()
    etiquettes = {"diag": "Diagnostic gratuit (OSINT passif)",
                  "secu": "Sécurisation (défensif, local)"}
    morceaux = []
    for fam in ("diag", "secu"):
        passifs = [o for o in groupes.get(fam, [])
                   if not o["payant"] and not o["autorisation_requise"]]
        if not passifs:
            continue
        options = "".join(
            _option(o, etats.get(o["nom"]))
            for o in sorted(passifs, key=lambda x: (not etats.get(x["nom"]), x["nom"].lower())))
        morceaux.append(f"<optgroup label='{etiquettes[fam]}'>{options}</optgroup>")
    return "".join(morceaux)


def aide(o):
    """Une phrase d'aide pour un outil : à quoi il sert et ce qu'il attend."""
    f = fiches_outils.fiche(o["nom"], o)
    role = f.get("role") or o.get("categorie", "")
    if f.get("mode") != "cible":
        quoi = {"service": "service à installer, ne se lance pas d'ici",
                "appli": "logiciel à ouvrir soi-même",
                "windows": "Windows seulement",
                "capture": "capture réseau, à lancer à la main",
                "ressource": "règles pour un autre outil",
                "compte": "demande un compte ou une clé",
                "agent": "compétence pour assistant IA",
                "a_la_main": "demande une préparation"}.get(f["mode"], "à la main")
        return f"Ça {role}. ({quoi})"
    attendu = fiches_outils.CIBLES.get(f.get("cible"))
    if not attendu:
        return f"Ça {role}."
    if f["cible"] == "aucune":
        return f"Ça {role}. Pas de cible à taper."
    return f"Ça {role}. Cible : {attendu[0]}, par exemple {attendu[1]}."


def _option(o, installe):
    e = html.escape
    f = fiches_outils.fiche(o["nom"], o)
    a_la_main = "" if f.get("mode") == "cible" else " (à la main)"
    return (f"<option value='{e(o['nom'])}' data-aide='{e(aide(o), quote=True)}'>"
            f"{'✓ ' if installe else ''}{e(o['nom'])}{a_la_main}"
            f" — {e((f.get('role') or o['categorie'])[:60])}</option>")


def _catalogue_html(etats=None):
    etats = etats or {}
    e = html.escape
    groupes = registre.par_famille()
    titres = registre.FAMILLES
    blocs = []
    for fam in registre.ORDRE:
        liste = sorted(groupes.get(fam, []), key=lambda x: x["nom"].lower())
        items = []
        for o in liste:
            if o["payant"]:
                marque = "<span class='marque m-payant'>payant</span>"
            elif o["autorisation_requise"]:
                marque = "<span class='marque m-auto'>autorisation</span>"
            else:
                marque = "<span class='marque m-pret'>lançable</span>"
            if etats.get(o["nom"]):
                marque += "<span class='marque m-installe'>installé</span>"
            items.append(f"<li>{e(o['nom'])}{marque}</li>")
        installes = sum(1 for o in liste if etats.get(o["nom"]))
        blocs.append(f"<div class='fam'><h2>{e(titres[fam])} ({len(liste)})"
                     f" — {installes} installé{'s' if installes > 1 else ''}</h2>"
                     f"<ul class='liste-outils'>{''.join(items)}</ul></div>")
    return "".join(blocs)


def _formulaire_brancher(etats):
    """« Je l'ai installé à la main » : on montre où est le programme, Vigie le relie."""
    e = html.escape
    manquants = sorted((o["nom"] for o in registre.charger()
                        if not o["payant"] and not etats.get(o["nom"])), key=str.lower)
    if not manquants:
        return ""
    options = "".join(f"<option>{e(nom)}</option>" for nom in manquants)
    return f"""<div class="corps" id="a-la-main"><h2>Je l'ai installé à la main</h2>
<p>Tu as posé un outil toi-même (programme téléchargé, dossier copié depuis GitHub…) ?
Montre à Vigie où il est : Vigie le relie, vérifie qu'il démarre et le marque
<span class='marque m-installe'>installé</span>. Rien n'est téléchargé.</p>
<form method="post" action="/outil/brancher">
<label>Outil<select name="nom">{options}</select></label>
<label>Où est le programme (ou son dossier)
<input name="chemin" placeholder="/home/moi/Téléchargements/chainsaw/chainsaw"></label>
<p class="aide-outil">Astuce : dans le gestionnaire de fichiers, clic droit sur le fichier
&gt; Copier, puis clique dans la case et fais Ctrl+V : le chemin s'écrit tout seul.</p>
<button type="submit">Brancher sur Vigie</button>
</form></div>"""


def brancher(corps):
    """Traite le formulaire « Je l'ai installé à la main ». Renvoie la page avec le
    résultat en français (réussite ou raison du refus)."""
    import urllib.parse
    from . import a_la_main
    champs = urllib.parse.parse_qs(corps)
    nom = champs.get("nom", [""])[0].strip()[:120]
    chemin = champs.get("chemin", [""])[0].strip()[:1000]
    try:
        return page(ok=a_la_main.brancher(nom, chemin))
    except (a_la_main.Refus, OSError) as erreur:
        return page(message=str(erreur))


def page(message="", ok=""):
    bandeau = ""
    if message:
        bandeau = ("<div class='refus'><b>Pourquoi ça ne part pas :</b><br>"
                   f"{html.escape(message)}</div>")
    elif ok:
        bandeau = f"<div class='bandeau'>{html.escape(ok)}</div>"
    etats = presence.etat()
    gratuits = [o["nom"] for o in registre.non_payants()]
    installes = sum(1 for nom in gratuits if etats.get(nom))
    return f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vigie - Lancer un outil</title><style>{rapport.CSS}{CSS}</style></head><body><main>
<div class="couv"><div class="enseigne">{rapport.LOGO}<div class="mot">Vigie<small>Sécurité</small></div></div>
<h1>Lancer un outil</h1><div class="meta"><span>Un outil, une cible, à la demande</span></div></div>
<div class="corps">{bandeau}
<p>Choisis un outil <b>passif</b> et une cible (domaine, pseudo, e-mail… selon l'outil).
Les outils <b>actifs</b> ou offensifs se lancent dans
<a href="/manuel">Outils manuels</a>, avec autorisation signée.</p>
<form method="post" action="/outil/lancer">
<label>Outil<select name="nom" id="choix-outil">{_options_passifs(etats)}</select></label>
<p class="aide-outil" id="aide-outil"></p>
<label>Cible<input name="cible" placeholder="exemple.fr ou un pseudo"></label>
<button type="submit">Lancer cet outil</button>
</form>
<script>
(function () {{
  var choix = document.getElementById("choix-outil");
  var aide = document.getElementById("aide-outil");
  function maj() {{
    var o = choix.options[choix.selectedIndex];
    aide.textContent = o ? (o.getAttribute("data-aide") || "") : "";
  }}
  choix.addEventListener("change", maj); maj();
}})();
</script></div>
<div class="familles"><h2>Tous les outils du catalogue</h2>
<p class="compte-installes"><b>{installes}</b> {'outils' if installes > 1 else 'outil'} sur
{len(gratuits)} {'sont installés' if installes > 1 else 'est installé'} sur cette machine
(marqués <span class='marque m-installe'>installé</span>).</p>
{_catalogue_html(etats)}</div>
{_formulaire_brancher(etats)}
<div class="corps"><p><a href="/">Accueil</a> · <a href="/manuel">Outils manuels</a></p></div>
</main></body></html>"""


def lancer(corps):
    """Lance un outil passif en arrière-plan. Renvoie l'identifiant de suivi.
    Lève lancer_seul.Refus (raison en clair, en français) si le lancement n'est pas
    permis ou ne peut pas marcher : outil actif, service, mauvaise cible…"""
    c = _champs(corps)
    nom = (c.get("nom", [""])[0] or "").strip()[:80]
    cible = (c.get("cible", [""])[0] or "").strip()[:200]
    lancer_seul.verifier_lancable(nom, autorisation_ok=False)   # refuse actif/payant/inconnu
    prepa = lancer_seul.preparer(nom, cible)                    # explique tout refus
    ident = secrets.token_urlsafe(9)
    with VERROU:
        LANCEMENTS[ident] = {"etat": "en_cours", "outil": nom,
                             "cible": prepa["cible"] or "cet ordinateur",
                             "resultat": "", "explication": [], "brut": "",
                             "reussi": False, "commande": ""}

    def travail():
        try:
            compte = lancer_seul.lancer(nom, cible)
            reussi = bool(compte.get("lance")) and not compte.get("code") \
                and bool((compte.get("sortie") or "").strip())
            brut = (compte.get("sortie") or "")
            if compte.get("erreurs") and compte["erreurs"] not in brut:
                brut += "\n" + compte["erreurs"]
            if compte.get("absent"):
                brut = "Raison notée à l'installation : " + (
                    lancer_seul.raison_installation(compte["outil"]) or "aucune (pas encore "
                    "d'installation sur cette machine)")
            etat = {"etat": "fini" if compte.get("lance") else "erreur",
                    "outil": compte["outil"], "reussi": reussi,
                    "explication": compte.get("explication", []),
                    "resultat": compte.get("traduction") if reussi else "",
                    "brut": brut.strip(), "commande": compte.get("commande", "")}
        except Exception as erreur:
            etat = {"etat": "erreur", "explication": [str(erreur)]}
        with VERROU:
            LANCEMENTS[ident].update(etat)
    threading.Thread(target=travail, daemon=True).start()
    return ident


def page_resultat(ident):
    with VERROU:
        etat = dict(LANCEMENTS.get(ident) or {})
    if not etat:
        return None
    e = html.escape
    en_cours = etat["etat"] == "en_cours"
    rafraichir = "<meta http-equiv='refresh' content='4'>" if en_cours else ""
    if en_cours:
        titre = "En cours…"
    elif etat.get("reussi"):
        titre = "Terminé"
    else:
        titre = "N'a pas marché" if etat["etat"] == "erreur" or etat.get("explication") \
            else "Terminé"
    morceaux = []
    if en_cours:
        morceaux.append("<p>L'outil tourne. Cette page se met à jour toute seule.</p>")
    phrases = etat.get("explication") or []
    if phrases:
        classe = "reussi" if etat.get("reussi") else "explication"
        intro = "" if etat.get("reussi") else "<p><b>Ce qui s'est passé :</b></p>"
        morceaux.append(f"<div class='{classe}'>{intro}"
                        + "".join(f"<p>{e(p)}</p>" for p in phrases) + "</div>")
    if etat.get("resultat"):
        morceaux.append(f"<h2>Résumé</h2><pre>{e(etat['resultat'])}</pre>")
    if etat.get("brut") or etat.get("commande"):
        detail = ""
        if etat.get("commande"):
            detail += f"Commande : {etat['commande']}\n\n"
        detail += etat.get("brut") or ""
        morceaux.append("<details class='brut'><summary>Détail technique (sortie brute de "
                        f"l'outil, en anglais)</summary><pre>{e(detail)}</pre></details>")
    return f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">{rafraichir}
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vigie - {e(etat['outil'])}</title><style>{rapport.CSS}{CSS}</style></head><body><main>
<div class="couv"><div class="enseigne">{rapport.LOGO}<div class="mot">Vigie<small>Sécurité</small></div></div>
<h1>{e(etat['outil'])} sur {e(etat['cible'])}</h1><div class="meta"><span>{titre}</span></div></div>
<div class="corps">{''.join(morceaux)}
<p><a href="/outils-un">Lancer un autre outil</a> · <a href="/">Accueil</a></p></div></main></body></html>"""
