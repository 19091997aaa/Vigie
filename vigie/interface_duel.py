"""La page « Comparer » de l'interface : le banc de comparaison (duel.py) en un clic.

On choisit une question, on donne la cible (domaine, pseudo avec accord, ou dossier),
et Vigie lance les outils candidats côte à côte. La page de résultat montre le tableau
élément par élément et la recommandation.
"""
import html
import secrets
import threading
import urllib.parse

from . import __version__, duel, rapport
from .cli import nettoyer_domaine

EN_COURS = {}
VERROU = threading.Lock()


def page(message=""):
    e = html.escape
    choix = "".join(f"<option value='{e(cle)}'>{e(q['titre'])}</option>"
                    for cle, q in duel.QUESTIONS.items())
    erreur = f"<p class='erreur'>{e(message)}</p>" if message else ""
    return f"""<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Vigie - comparer</title>
<style>{rapport.CSS}
.corps {{ padding:30px 40px 10px; }} form {{ display:grid; gap:14px; }}
label {{ display:grid; gap:6px; font-weight:700; font-size:14px; }}
input, select {{ font:inherit; padding:11px 13px; border:1.5px solid #cfd6e1; border-radius:10px; }}
button {{ font:inherit; font-weight:800; padding:14px; border:0; border-radius:10px;
  background:var(--navy); color:#fff; cursor:pointer; }}
.aide {{ font-size:13.5px; color:var(--gris); font-weight:400; }}
.erreur {{ padding:13px 16px; border-radius:10px; background:#fbeceb; color:#8a1d16; }}
</style></head><body><main>
<div class="couv"><div class="enseigne">{rapport.LOGO}<div class="mot">Vigie<small>Sécurité</small></div></div>
<h1>Comparer des outils</h1><div class="meta"><span>Une question, plusieurs outils, côte à côte</span></div></div>
<div class="corps">{erreur}
<p class="aide">Vigie lance chaque outil sur la même cible et montre ce que chacun voit, ce que
les autres ratent, le temps, et lequel garder. Tout se fait en lecture seule.</p>
<form method="post" action="/comparer">
<label>Question <select name="question">{choix}</select></label>
<label>Nom de domaine <span class="aide">Pour les questions sur un site ou une société.</span>
<input name="domaine" autocapitalize="none" autocomplete="off"></label>
<label>Pseudo <span class="aide">Pour les comptes : le pseudo de la personne, donné par elle.</span>
<input name="pseudo" autocapitalize="none" autocomplete="off"></label>
<label class="aide"><span><input type="checkbox" name="accord" value="oui"> La personne a donné son accord écrit</span></label>
<label>Dossier de l'ordinateur <span class="aide">Pour les logiciels troués et les secrets dans du code.</span>
<input name="dossier" autocomplete="off"></label>
<button type="submit">Comparer</button></form>
<p><a href="/">Retour à l'accueil</a></p></div>
<footer>Vigie {__version__}.</footer></main></body></html>"""


def lancer(corps):
    """Vérifie la saisie, lance le banc en arrière-plan, renvoie son code. ValueError sinon."""
    c = urllib.parse.parse_qs(corps)
    un = lambda nom: (c.get(nom, [""])[0] or "").strip()[:300]  # noqa: E731
    question = un("question")
    if question not in duel.QUESTIONS:
        raise ValueError("Choisis une question dans la liste.")
    cible = {"domaine": nettoyer_domaine(un("domaine")) if un("domaine") else "",
             "pseudo": un("pseudo"), "accord": un("accord") == "oui", "dossier": un("dossier")}
    besoin = duel.QUESTIONS[question]["besoin"]
    if besoin != "dossier" and not cible.get(besoin):
        raise ValueError({"domaine": "Il faut le nom de domaine.",
                          "pseudo": "Il faut le pseudo."}.get(besoin, "Champ manquant."))
    ident = secrets.token_urlsafe(9)
    with VERROU:
        EN_COURS[ident] = None

    def travail():
        try:
            contenu = duel.en_html(duel.comparer(question, cible))
        except Exception as erreur:
            contenu = f"<p>Comparaison arrêtée : {html.escape(str(erreur))}</p><p><a href='/comparer'>Retour</a></p>"
        with VERROU:
            EN_COURS[ident] = contenu
    threading.Thread(target=travail, daemon=True).start()
    return ident


def page_resultat(ident):
    with VERROU:
        if ident not in EN_COURS:
            return None
        contenu = EN_COURS[ident]
    if contenu is None:
        return ("<!DOCTYPE html><html lang='fr'><head><meta charset='utf-8'>"
                "<meta http-equiv='refresh' content='5'><title>Comparaison en cours</title></head>"
                "<body style='font-family:system-ui;padding:30px'><h1>Comparaison en cours…</h1>"
                "<p>Les outils tournent l'un après l'autre. Cette page se met à jour toute seule.</p>"
                "</body></html>")
    return contenu
