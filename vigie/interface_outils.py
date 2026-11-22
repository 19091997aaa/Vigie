"""L'onglet « Lancer un outil » : choisir UN outil du catalogue et le lancer seul.

On voit les 216 outils non payants rangés par famille. Les outils PASSIFS (diag,
sécurisation) se lancent ici, un par un, sur la cible saisie. Les outils ACTIFS ou
offensifs ne se lancent PAS ici : ils renvoient vers l'onglet « Outils manuels », qui
exige l'autorisation signée (règles d'or). Tous les garde-fous sont dans lancer_seul.py.
"""
import html
import secrets
import threading

from . import __version__, lancer_seul, rapport, registre

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
"""


def _champs(corps):
    import urllib.parse
    return urllib.parse.parse_qs(corps, keep_blank_values=True)


def _options_passifs():
    """Un <select> des outils passifs non payants, groupés par famille."""
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
            f"<option value='{html.escape(o['nom'])}'>{html.escape(o['nom'])}"
            f" — {html.escape(o['categorie'][:48])}</option>"
            for o in sorted(passifs, key=lambda x: x["nom"].lower()))
        morceaux.append(f"<optgroup label='{etiquettes[fam]}'>{options}</optgroup>")
    return "".join(morceaux)


def _catalogue_html():
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
            items.append(f"<li>{e(o['nom'])}{marque}</li>")
        blocs.append(f"<div class='fam'><h2>{e(titres[fam])} ({len(liste)})</h2>"
                     f"<ul class='liste-outils'>{''.join(items)}</ul></div>")
    return "".join(blocs)


def page(message="", ok=""):
    bandeau = ""
    if message:
        bandeau = f"<div class='erreur'>{html.escape(message)}</div>"
    elif ok:
        bandeau = f"<div class='bandeau'>{html.escape(ok)}</div>"
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
<label>Outil<select name="nom">{_options_passifs()}</select></label>
<label>Cible<input name="cible" placeholder="exemple.fr ou un pseudo" required></label>
<button type="submit">Lancer cet outil</button>
</form></div>
<div class="familles"><h2>Tous les outils du catalogue</h2>{_catalogue_html()}</div>
<div class="corps"><p><a href="/">Accueil</a> · <a href="/manuel">Outils manuels</a></p></div>
</main></body></html>"""


def lancer(corps):
    """Lance un outil passif en arrière-plan. Renvoie l'identifiant de suivi.
    Lève lancer_seul.Refus (raison en clair) si le lancement n'est pas permis."""
    c = _champs(corps)
    nom = (c.get("nom", [""])[0] or "").strip()[:80]
    cible = (c.get("cible", [""])[0] or "").strip()[:200]
    lancer_seul.verifier_lancable(nom, autorisation_ok=False)   # refuse actif/payant/inconnu
    if not cible:
        raise lancer_seul.Refus("Indique une cible.")
    ident = secrets.token_urlsafe(9)
    with VERROU:
        LANCEMENTS[ident] = {"etat": "en_cours", "outil": nom, "cible": cible, "resultat": ""}

    def travail():
        try:
            compte = lancer_seul.lancer(nom, cible)
            if not compte.get("lance"):
                etat = {"etat": "erreur", "resultat": compte.get("raison", "non lancé")}
            else:
                note = "" if compte["verifiee"] else \
                    "(ligne de lancement devinée du catalogue, à confirmer)\n\n"
                etat = {"etat": "fini", "outil": compte["outil"],
                        "resultat": note + (compte.get("traduction") or "Rien à afficher.")}
        except Exception as erreur:
            etat = {"etat": "erreur", "resultat": str(erreur)}
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
    rafraichir = "<meta http-equiv='refresh' content='4'>" if etat["etat"] == "en_cours" else ""
    titre = {"en_cours": "En cours…", "fini": "Terminé", "erreur": "Arrêté"}[etat["etat"]]
    return f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">{rafraichir}
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vigie - {e(etat['outil'])}</title><style>{rapport.CSS}{CSS}</style></head><body><main>
<div class="couv"><div class="enseigne">{rapport.LOGO}<div class="mot">Vigie<small>Sécurité</small></div></div>
<h1>{e(etat['outil'])} sur {e(etat['cible'])}</h1><div class="meta"><span>{titre}</span></div></div>
<div class="corps"><pre>{e(etat['resultat'] or 'Cette page se met à jour toute seule.')}</pre>
<p><a href="/outils-un">Lancer un autre outil</a> · <a href="/">Accueil</a></p></div></main></body></html>"""
