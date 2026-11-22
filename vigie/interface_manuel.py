"""L'onglet « Outils manuels » de l'interface : autorisations et lancements un par un.

Deux formulaires :
  1. préparer l'autorisation à faire signer (mandat.py) : Vigie l'écrit dans le dossier
     « autorisations », on l'ouvre, on l'imprime, le client la signe ;
  2. lancer un outil manuel (manuel.py) : on choisit l'outil, la cible, la fiche
     d'autorisation et le fichier signé (déposé par Anass dans le même dossier),
     et on retape la cible pour confirmer. Tous les garde-fous de manuel.py s'appliquent.
La sortie de Nmap est traduite en français (ports.py).
"""
import html
import os
import re
import secrets
import threading
import urllib.parse

from . import __version__, audit_actif, manuel, mandat, ports, rapport

NUMERO = re.compile(r"[0-9]{8}-[0-9a-f]{6}")
FICHIER = re.compile(r"[A-Za-z0-9 ._-]{1,120}")
LANCEMENTS = {}
VERROU = threading.Lock()


def _fichiers(dossier):
    if not os.path.isdir(dossier):
        return [], []
    noms = sorted(os.listdir(dossier), reverse=True)
    fiches = [n for n in noms if n.startswith("autorisation_") and n.endswith(".json")]
    signees = [n for n in noms if FICHIER.fullmatch(n) and not n.endswith((".json", ".html"))
               and not n.startswith(".")]
    return fiches, signees


def _options(noms):
    return "".join(f"<option>{html.escape(n)}</option>" for n in noms) or \
        "<option value=''>(aucun fichier)</option>"


def page(dossier, message="", ok=""):
    e = html.escape
    fiches, signees = _fichiers(dossier)
    outils_html = "".join(f"<option value='{e(nom)}'>{e(nom)} : {e(o['role'])}</option>"
                          for nom, o in manuel.OUTILS.items())
    tests = "".join(f"<label class='aide'><input type='checkbox' name='tests' value='{e(t)}'"
                    f"{' checked' if t != 'manuels' else ''}> {e(libelle)}</label>"
                    for t, libelle in mandat.TESTS.items())
    bandeau = (f"<p class='erreur'>{e(message)}</p>" if message else "") + \
              (f"<p class='bandeau fini'>{ok}</p>" if ok else "")
    return f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vigie - outils manuels</title>
<style>{rapport.CSS}{CSS}</style></head><body><main>
<div class="couv">
<div class="enseigne">{rapport.LOGO}<div class="mot">Vigie<small>Sécurité</small></div></div>
<h1>Outils manuels</h1>
<div class="meta"><span>Contrôles actifs, un par un, uniquement sur autorisation signée</span></div>
</div>
<div class="corps">
{bandeau}
<p class="aide">Ces outils touchent les machines de la cible. Sans autorisation écrite et signée,
c'est un délit (article 323-1 du Code pénal). Vigie refuse tout lancement hors du périmètre,
des dates ou des tests signés, et note chaque lancement dans le journal.</p>

<h2>1. Préparer l'autorisation à faire signer</h2>
<form method="post" action="/manuel/autorisation">
<label>Société <input name="societe" required autocomplete="off"></label>
<label>Personne qui signe pour la société <input name="representant" required autocomplete="off"></label>
<label>Cibles <span class="aide">Noms de domaine ou adresses IP, séparés par des virgules.</span>
<input name="cibles" required autocapitalize="none" autocomplete="off"></label>
<label>Du <input name="debut" type="date" required></label>
<label>Au <input name="fin" type="date" required></label>
<div>{tests}</div>
<label>Contact du client en cas d'incident <input name="contact" autocomplete="off"></label>
<button type="submit">Préparer l'autorisation</button>
</form>

<h2>2. Lancer un outil</h2>
<p class="aide">Dépose d'abord l'autorisation signée (scan ou PDF) dans le dossier
« autorisations » de Vigie, puis recharge cette page.</p>
<form method="post" action="/manuel/lancer">
<label>Outil <select name="outil">{outils_html}</select></label>
<label>Cible <input name="cible" required autocapitalize="none" autocomplete="off"></label>
<label>Fiche d'autorisation <select name="fiche">{_options(fiches)}</select></label>
<label>Autorisation signée <select name="signee">{_options(signees)}</select></label>
<label>Confirmation <span class="aide">Retape la cible exactement.</span>
<input name="confirmation" required autocapitalize="none" autocomplete="off"></label>
<button type="submit">Lancer, après vérification</button>
</form>
<p><a href="/">Retour à l'accueil</a></p>
</div>
<footer>Vigie {__version__}. Chaque lancement et chaque refus est inscrit au journal.</footer>
</main></body></html>"""


CSS = """
.corps { padding:30px 40px 10px; } form { display:grid; gap:14px; margin:4px 0 18px; }
label { display:grid; gap:6px; font-weight:700; font-size:14px; }
input, select { font:inherit; padding:11px 13px; border:1.5px solid #cfd6e1; border-radius:10px; }
label.aide { display:flex; gap:8px; align-items:center; font-weight:400; }
button { font:inherit; font-weight:800; padding:14px; border:0; border-radius:10px;
  background:var(--navy); color:#fff; cursor:pointer; }
.aide { font-size:13.5px; color:var(--gris); }
.erreur { padding:13px 16px; border-radius:10px; border-left:4px solid #b3261e;
  background:#fbeceb; color:#8a1d16; }
.bandeau { padding:13px 16px; border-radius:10px; border-left:4px solid #1e7a46;
  background:var(--fond); }
pre { white-space:pre-wrap; font-size:13px; background:var(--fond); padding:12px;
  border-radius:10px; }
"""


def _champs(corps):
    return {cle: valeurs for cle, valeurs in urllib.parse.parse_qs(corps).items()}


def creer_autorisation(corps, dossier):
    """Écrit l'autorisation demandée. Renvoie son numéro. ValueError si la saisie est fausse."""
    c = _champs(corps)
    un = lambda nom: (c.get(nom, [""])[0] or "").strip()[:200]  # noqa: E731
    fiche = mandat.creer(un("societe"), un("representant"),
                         [x for x in re.split(r"[,\s]+", un("cibles")) if x],
                         un("debut"), un("fin"), c.get("tests") or ["ports"],
                         contact_urgence=un("contact"))
    mandat.ecrire(fiche, dossier)
    return fiche["numero"]


def page_autorisation(dossier, numero):
    """Le document à imprimer, ou None."""
    if not NUMERO.fullmatch(numero or ""):
        return None
    chemin = os.path.join(dossier, f"autorisation_{numero}.html")
    if not os.path.isfile(chemin):
        return None
    with open(chemin, encoding="utf-8") as fichier:
        return fichier.read()


def lancer(corps, dossier, journal):
    """Vérifie tout, puis lance l'outil en arrière-plan. Renvoie le code du lancement.
    Lève manuel.Refus (raison en clair) si quelque chose n'est pas en règle."""
    c = _champs(corps)
    un = lambda nom: (c.get(nom, [""])[0] or "").strip()[:200]  # noqa: E731
    fiche, signee = un("fiche"), un("signee")
    if not FICHIER.fullmatch(fiche or "-") or not FICHIER.fullmatch(signee or "-") \
            or "/" in fiche + signee or ".." in fiche + signee:
        raise manuel.Refus("Choisis la fiche et le fichier signé dans les listes.")
    ident = secrets.token_urlsafe(9)
    args = (un("outil"), un("cible"), os.path.join(dossier, fiche),
            os.path.join(dossier, signee), un("confirmation"), journal)
    # Les vérifications sont refaites par manuel.lancer : ici, on en fait une à blanc
    # tout de suite pour pouvoir répondre « refusé » sans attendre l'outil.
    _verifier(*args)
    with VERROU:
        LANCEMENTS[ident] = {"etat": "en_cours", "outil": args[0], "cible": args[1],
                             "resultat": ""}

    def travail():
        try:
            chemin = manuel.lancer(*args)
            with open(chemin, encoding="utf-8") as fichier:
                brut = fichier.read()
            texte = _traduire(args[0], chemin) or brut[:20000]
            etat = {"etat": "fini", "resultat": texte}
        except Exception as erreur:  # refus tardif ou outil en échec : on le montre
            etat = {"etat": "erreur", "resultat": str(erreur)}
        with VERROU:
            LANCEMENTS[ident].update(etat)
    threading.Thread(target=travail, daemon=True).start()
    return ident


def _verifier(nom, cible, fiche, signee, confirmation, journal):
    """Mêmes contrôles que manuel.lancer, sans lancer ni écrire au journal."""
    if nom not in manuel.OUTILS:
        raise manuel.Refus(f"Outil inconnu : {nom}")
    cible = cible.strip().lower()
    if not manuel.CIBLE.fullmatch(cible):
        raise manuel.Refus(f"Cible invalide : {cible!r}")
    raison = mandat.couvre(mandat.lire(fiche), cible, manuel.OUTILS[nom]["test"])
    if raison:
        raise manuel.Refus(raison)
    if not os.path.isfile(signee):
        raise manuel.Refus("Le fichier signé est introuvable.")
    if confirmation.strip().lower() != cible:
        raise manuel.Refus("Confirmation manquante : retape exactement la cible.")


def _traduire(nom, chemin):
    try:
        if nom == "nmap":
            lignes = ports.traduire(ports.lire_nmap(chemin))
        elif nom in audit_actif.TRADUCTEURS:
            lignes = audit_actif.TRADUCTEURS[nom](chemin)
        else:
            return ""
    except Exception:
        return ""
    return "\n".join(f"[{niveau}] {texte}" for niveau, texte in lignes) or \
        "Aucun service ouvert parmi les ports vérifiés."


def page_resultat(ident):
    with VERROU:
        etat = dict(LANCEMENTS.get(ident) or {})
    if not etat:
        return None
    e = html.escape
    rafraichir = "<meta http-equiv='refresh' content='5'>" if etat["etat"] == "en_cours" else ""
    titre = {"en_cours": "En cours…", "fini": "Terminé", "erreur": "Arrêté"}[etat["etat"]]
    return f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">{rafraichir}
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vigie - {e(etat['outil'])}</title><style>{rapport.CSS}{CSS}</style></head><body><main>
<div class="couv"><div class="enseigne">{rapport.LOGO}<div class="mot">Vigie<small>Sécurité</small></div></div>
<h1>{e(etat['outil'])} sur {e(etat['cible'])}</h1><div class="meta"><span>{titre}</span></div></div>
<div class="corps"><pre>{e(etat['resultat'] or 'Cette page se met à jour toute seule.')}</pre>
<p><a href="/manuel">Retour aux outils manuels</a></p></div></main></body></html>"""
