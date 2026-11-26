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

from . import __version__, audit_actif, manuel, mandat, mes_cibles, ports, rapport

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


def _options(noms, propre=False):
    choix = "".join(f"<option>{html.escape(n)}</option>" for n in noms)
    if propre:   # en tête : pas d'autorisation, la cible doit être une des miennes
        return ("<option value=''>Aucune : c'est une de mes propres cibles</option>"
                + choix)
    return choix or "<option value=''>(aucun fichier)</option>"


def _section_mes_cibles(dossier):
    """« Mes propres cibles » : domaines et VM de labo attestés par Anass."""
    e = html.escape
    donnees = mes_cibles.lire(dossier)
    lignes = []
    for domaine in sorted(donnees["domaines"]):
        lignes.append(f"<li><b>{e(domaine)}</b> : <b class='ok'>à toi</b> "
                      f"{_bouton('retirer', domaine, 'Retirer', discret=True)}</li>")
    for reseau_ip in donnees["reseaux"]:
        lignes.append(f"<li><b>{e(reseau_ip)}</b> : machine ou réseau de labo "
                      f"{_bouton('retirer', reseau_ip, 'Retirer', discret=True)}</li>")
    liste = (f"<ul class='mes-cibles'>{''.join(lignes)}</ul>" if lignes else
             "<p class='aide'>Aucune pour l'instant.</p>")
    return f"""<h2>Mes propres cibles (sans autorisation)</h2>
<p class="aide">Ton site et tes machines de labo : pas besoin de t'autoriser toi-même.
Tu coches une fois « je suis propriétaire » et c'est bon. Un sous-domaine qui pointe vers
une autre machine ou un autre service (une boutique en ligne…) reste bloqué. Les machines
de labo : adresses privées seulement. Tout est noté au journal. Pour toute autre cible,
l'autorisation signée reste obligatoire.</p>
{liste}
<form method="post" action="/manuel/cibles" class="ligne">
<input type="hidden" name="action" value="domaine">
<label>Mon domaine <input name="valeur" placeholder="pavillon-noir.tech" required
 autocapitalize="none" autocomplete="off"></label>
<label class="aide"><input type="checkbox" name="atteste" value="oui" required>
Je suis propriétaire de ce domaine.</label>
<button type="submit">Ajouter le domaine</button></form>
<form method="post" action="/manuel/cibles" class="ligne">
<input type="hidden" name="action" value="reseau">
<label>Ma machine ou mon réseau de labo <input name="valeur" placeholder="192.168.56.0/24"
 required autocapitalize="none" autocomplete="off"></label>
<label class="aide"><input type="checkbox" name="atteste" value="oui" required>
Ces machines sont à moi (mon labo).</label>
<button type="submit">Ajouter la machine</button></form>"""


def _bouton(action, valeur, texte, discret=False):
    e = html.escape
    return (f"<form method='post' action='/manuel/cibles' class='enligne'>"
            f"<input type='hidden' name='action' value='{action}'>"
            f"<input type='hidden' name='valeur' value='{e(valeur)}'>"
            f"<button type='submit' class='{'discret' if discret else 'petit'}'>{e(texte)}"
            f"</button></form>")


def gerer_cibles(corps, dossier, journal):
    """Traite les formulaires de « Mes propres cibles ». Renvoie le message à afficher.
    Lève mes_cibles.Refus (en français) si la demande n'est pas acceptée."""
    c = _champs(corps)
    un = lambda nom: (c.get(nom, [""])[0] or "").strip()[:200]  # noqa: E731
    action, valeur = un("action"), un("valeur")
    if action in ("domaine", "reseau") and un("atteste") != "oui":
        raise mes_cibles.Refus("Coche la case : tu attestes que cette cible est à toi.")
    if action == "domaine":
        domaine, _ = mes_cibles.ajouter_domaine(dossier, journal, valeur)
        return (f"{domaine} est ajouté à tes cibles : les outils peuvent le viser sans "
                "autorisation.")
    if action == "reseau":
        return f"{mes_cibles.ajouter_reseau(dossier, journal, valeur)} est ajouté à ton labo."
    if action == "retirer":
        mes_cibles.retirer(dossier, journal, valeur)
        return f"{valeur} est retiré de tes cibles."
    raise mes_cibles.Refus("Demande inconnue.")


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
<div class="meta"><span>Contrôles actifs, un par un : sur autorisation signée, ou sur tes propres cibles déclarées</span></div>
</div>
<div class="corps">
{bandeau}
<p class="aide">Ces outils touchent les machines de la cible. Sans autorisation écrite et signée,
c'est un délit (article 323-1 du Code pénal). Vigie refuse tout lancement hors du périmètre,
des dates ou des tests signés, et note chaque lancement dans le journal.</p>

{_section_mes_cibles(dossier)}

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
<label>Fiche d'autorisation <select name="fiche">{_options(fiches, propre=True)}</select></label>
<label>Autorisation signée <select name="signee">{_options(signees, propre=True)}</select></label>
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
form.ligne { grid-template-columns:1fr; border:1px solid var(--trait); border-radius:10px;
  padding:12px 14px; }
form.enligne { display:inline; margin:0 0 0 8px; }
button.petit, button.discret { padding:5px 10px; font-size:13px; }
button.discret { background:#eceef1; color:#5c6676; }
.mes-cibles li { margin:8px 0; line-height:1.6; }
b.ok { color:#1e7a46; } b.attente { color:#9a5f00; }
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
    # Fiche vide = « une de mes propres cibles » : vérifiée par mes_cibles.py.
    args = (un("outil"), un("cible"), os.path.join(dossier, fiche) if fiche else None,
            os.path.join(dossier, signee) if fiche and signee else None,
            un("confirmation"), journal)
    # Les vérifications sont refaites par manuel.lancer : ici, on en fait une à blanc
    # tout de suite pour pouvoir répondre « refusé » sans attendre l'outil.
    _verifier(*args, dossier_cibles=dossier)
    with VERROU:
        LANCEMENTS[ident] = {"etat": "en_cours", "outil": args[0], "cible": args[1],
                             "resultat": ""}

    def travail():
        try:
            chemin = manuel.lancer(*args, dossier_cibles=dossier)
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


def _verifier(nom, cible, fiche, signee, confirmation, journal, dossier_cibles=None):
    """Mêmes contrôles que manuel.lancer, sans lancer ni écrire au journal."""
    if nom not in manuel.OUTILS:
        raise manuel.Refus(f"Outil inconnu : {nom}")
    cible = cible.strip().lower()
    if not manuel.CIBLE.fullmatch(cible):
        raise manuel.Refus(f"Cible invalide : {cible!r}")
    if not fiche:
        raison = mes_cibles.raison_refus(dossier_cibles, cible) if dossier_cibles else \
            "Il faut la fiche de l'autorisation."
        if raison:
            raise manuel.Refus(raison)
    else:
        raison = mandat.couvre(mandat.lire(fiche), cible, manuel.OUTILS[nom]["test"])
        if raison:
            raise manuel.Refus(raison)
        if not signee or not os.path.isfile(signee):
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
