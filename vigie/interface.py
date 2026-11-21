"""Vigie dans le navigateur : la même mécanique que la commande, avec un formulaire.

Le moteur tourne sur l'ordinateur. L'écran s'ouvre dans un navigateur, sur
l'ordinateur lui-même ou sur un téléphone du même Wi-Fi (option --reseau-local,
protégée par un code).

Seuls les contrôles sans action sur les machines sont proposés ici.
"""
import html
import json
import os
import re
import secrets
import socket
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__, rapport
from .cli import dossier_rapport, lancer, nettoyer_domaine
from .modeles import Cible
from .modules import MODULES, PAR_DEFAUT

NOM_RAPPORT = re.compile(r"[a-z0-9_-]{3,120}")

CSS_FORM = """
.corps { padding:30px 40px 10px; }
form { display:grid; gap:18px; margin:4px 0 8px; }
label { display:grid; gap:7px; font-weight:700; font-size:14px; color:var(--encre); }
input { font:inherit; padding:13px 15px; border:1.5px solid #cfd6e1; border-radius:10px; }
input:focus { outline:none; border-color:var(--navy); }
button { font:inherit; font-size:16px; font-weight:800; padding:15px 18px; border:0;
  border-radius:10px; background:var(--navy); color:#fff; cursor:pointer; }
button:hover { background:#1c3a68; }
.aide { font-size:13.5px; color:var(--gris); font-weight:400; }
.erreur { padding:13px 16px; border-radius:10px; border-left:4px solid #b3261e;
  background:#fbeceb; color:#8a1d16; margin-bottom:6px; }
.rapports { list-style:none; padding:0; margin:0; }
.rapports a { display:flex; align-items:center; gap:10px; padding:13px 16px; margin:8px 0;
  border:1px solid var(--trait); border-radius:10px; text-decoration:none; color:var(--navy);
  font-weight:600; }
.rapports a:hover { border-color:var(--navy); background:var(--fond); }
.rapports a::before { content:"\\1F4C4"; }
.etapes { list-style:none; padding:0; margin:6px 0 18px; }
.etape { display:flex; align-items:center; gap:14px; padding:14px 16px; margin:8px 0;
  border:1px solid var(--trait); border-radius:10px; }
.etape .pastille { flex:none; width:28px; height:28px; border-radius:50%; display:grid;
  place-items:center; font-weight:800; font-size:15px; color:#fff; background:#cfd6e1; }
.etape .texte { flex:1; display:grid; gap:3px; }
.etape .nom { font-weight:700; }
.etape .detail { font-size:13.5px; color:var(--gris); }
.etape .temps { font-size:13px; color:var(--gris); font-variant-numeric:tabular-nums; }
.etape.en_cours { border-color:var(--navy); background:var(--fond); }
.etape.en_cours .pastille { background:transparent; border:3px solid #cfd6e1;
  border-top-color:var(--navy); animation:tourne 0.9s linear infinite; }
.etape.fini .pastille { background:#1e7a46; }
.etape.non_realise .pastille { background:#b7791f; }
.etape.echec .pastille { background:#b3261e; }
@keyframes tourne { to { transform:rotate(360deg); } }
.bandeau { padding:14px 16px; border-radius:10px; font-weight:700; margin:4px 0 10px;
  background:var(--fond); border-left:4px solid var(--navy); }
.bandeau.fini { border-left-color:#1e7a46; }
.bandeau.erreur { border-left-color:#b3261e; background:#fbeceb; color:#8a1d16; }
.bouton { display:inline-block; font-weight:800; padding:13px 18px; border-radius:10px;
  background:var(--navy); color:#fff; text-decoration:none; }
"""

PAGE = """<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vigie</title>
<style>{css}{cssform}</style></head><body><main>
<div class="couv">
<div class="enseigne">{logo}<div class="mot">Vigie<small>Sécurité</small></div></div>
<h1>Nouveau diagnostic</h1>
<div class="meta"><span>Audit d'exposition pour petites entreprises</span></div>
</div>
<div class="corps">
{message}
<form method="post" action="/diagnostic">
<label>Nom de domaine de la société
<input name="domaine" placeholder="exemple.fr" required autocapitalize="none" autocomplete="off">
</label>
<label>Nom de la société <span class="aide">Affiché en tête du rapport.</span>
<input name="societe" autocomplete="off"></label>
<button type="submit">Lancer le diagnostic</button>
<p class="aide">Contrôles lancés&nbsp;: {controles}. Ils lisent des informations publiques et
prennent environ une minute. Vous suivez chaque contrôle en direct.</p>
</form>
<h2>Rapports déjà produits</h2>
{rapports}
</div>
<footer>Vigie {version}. Diagnostic réservé à la société du client, avec son accord.</footer>
</main></body></html>"""


PAGE_SUIVI = """<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vigie</title>
<style>{css}{cssform}</style></head><body><main>
<div class="couv">
<div class="enseigne">{logo}<div class="mot">Vigie<small>Sécurité</small></div></div>
<h1>Diagnostic en cours</h1>
<div class="meta"><span>{titre}</span></div>
</div>
<div class="corps">
<div id="bandeau" class="bandeau">Préparation…</div>
<ul id="etapes" class="etapes">{etapes}</ul>
<p id="suite"></p>
<noscript><p class="aide">Rechargez la page pour voir l'avancement.</p></noscript>
<p><a href="/">Retour à l'accueil</a></p>
</div>
<footer>Vigie {version}. Cette page se met à jour toute seule.</footer>
</main>
<script>
const ICONES = {{en_attente:"", en_cours:"", fini:"✓", non_realise:"!", echec:"✕"}};
const MOTS = {{en_attente:"En attente", en_cours:"En cours", fini:"Terminé",
  non_realise:"Pas réalisé", echec:"Échec"}};
function texte(x) {{ const d = document.createElement("div"); d.textContent = x; return d.innerHTML; }}
function duree(s) {{ return s < 60 ? s + " s" : Math.floor(s / 60) + " min " + (s % 60) + " s"; }}
async function rafraichir() {{
  let etat;
  try {{ etat = await (await fetch("/suivi/{ident}/etat", {{cache:"no-store"}})).json(); }}
  catch (e) {{ setTimeout(rafraichir, 2000); return; }}
  document.getElementById("etapes").innerHTML = etat.etapes.map(e =>
    `<li class="etape ${{e.etat}}"><span class="pastille">${{ICONES[e.etat]}}</span>` +
    `<span class="texte"><span class="nom">${{texte(e.libelle)}}</span>` +
    `<span class="detail">${{MOTS[e.etat]}}${{e.detail ? " : " + texte(e.detail) : ""}}</span></span>` +
    `<span class="temps">${{e.duree !== null ? duree(e.duree) : ""}}</span></li>`).join("");
  const b = document.getElementById("bandeau");
  const finis = etat.etapes.filter(e => e.etat !== "en_attente" && e.etat !== "en_cours").length;
  if (etat.etat === "fini") {{
    b.className = "bandeau fini";
    b.textContent = "Diagnostic terminé. Ouverture du rapport…";
    document.getElementById("suite").innerHTML =
      `<a class="bouton" href="/rapport/${{etat.rapport}}">Voir le rapport</a>`;
    setTimeout(() => {{ location.href = "/rapport/" + etat.rapport; }}, 2500);
    return;
  }}
  if (etat.etat === "erreur") {{
    b.className = "bandeau erreur";
    b.textContent = "Le diagnostic s'est arrêté : " + etat.erreur;
    return;
  }}
  const courant = etat.etapes.find(e => e.etat === "en_cours");
  b.className = "bandeau";
  b.textContent = (courant ? "En ce moment : " + courant.libelle : "Préparation…") +
    "  (" + finis + " sur " + etat.etapes.length + " terminés)";
  setTimeout(rafraichir, 1000);
}}
rafraichir();
</script></body></html>"""

# Les diagnostics lancés depuis l'interface, avec leur avancement (gardés en mémoire).
SUIVIS = {}
VERROU = threading.Lock()


def _libelle(nom):
    """Nom lisible d'un contrôle. Marche pour tout module ajouté plus tard."""
    return MODULES.get(nom, {}).get("nom") or nom


def nouveau_suivi(cible, noms_modules):
    ident = secrets.token_urlsafe(9)
    with VERROU:
        SUIVIS[ident] = {
            "titre": cible.societe or cible.domaine, "etat": "en_cours", "rapport": "",
            "erreur": "",
            "etapes": [{"nom": nom, "libelle": _libelle(nom), "etat": "en_attente",
                        "detail": "", "debut": None, "fin": None} for nom in noms_modules],
        }
    return ident


def noter(ident, nom, etat, detail=""):
    """Met à jour l'avancement d'un contrôle (appelé par le moteur pendant le diagnostic)."""
    with VERROU:
        for etape in SUIVIS[ident]["etapes"]:
            if etape["nom"] == nom:
                etape["etat"], etape["detail"] = etat, detail
                if etat == "en_cours":
                    etape["debut"] = time.monotonic()
                else:
                    etape["fin"] = time.monotonic()
                return


def etat_suivi(ident):
    """Photo de l'avancement, prête à envoyer au navigateur. None si inconnu."""
    with VERROU:
        suivi = SUIVIS.get(ident)
        if suivi is None:
            return None
        maintenant = time.monotonic()
        etapes = []
        for etape in suivi["etapes"]:
            duree = None
            if etape["debut"] is not None:
                duree = int((etape["fin"] or maintenant) - etape["debut"])
            etapes.append({"nom": etape["nom"], "libelle": etape["libelle"],
                           "etat": etape["etat"], "detail": etape["detail"], "duree": duree})
        return {"titre": suivi["titre"], "etat": suivi["etat"], "rapport": suivi["rapport"],
                "erreur": suivi["erreur"], "etapes": etapes}


def executer_suivi(ident, cible, noms_modules, sortie):
    """Lance le diagnostic en arrière-plan et note chaque étape au fil de l'eau."""
    try:
        resultat = lancer(cible, noms_modules,
                          suivi=lambda nom, etat, detail: noter(ident, nom, etat, detail))
        dossier = dossier_rapport(sortie, resultat)
        rapport.ecrire(resultat, dossier)
        with VERROU:
            SUIVIS[ident]["etat"], SUIVIS[ident]["rapport"] = "fini", os.path.basename(dossier)
    except Exception as erreur:  # le navigateur doit le savoir, pas rester bloqué
        with VERROU:
            SUIVIS[ident]["etat"] = "erreur"
            SUIVIS[ident]["erreur"] = str(erreur) or erreur.__class__.__name__


def page_suivi(ident):
    suivi = etat_suivi(ident)
    etapes = "".join(
        f"<li class='etape {e['etat']}'><span class='pastille'></span><span class='texte'>"
        f"<span class='nom'>{html.escape(e['libelle'])}</span></span></li>"
        for e in suivi["etapes"])
    return PAGE_SUIVI.format(css=rapport.CSS, cssform=CSS_FORM, logo=rapport.LOGO,
                             titre=html.escape(suivi["titre"]), etapes=etapes, ident=ident,
                             version=__version__)


def _liste_rapports(sortie):
    if not os.path.isdir(sortie):
        return "<p class='aide'>Aucun rapport pour l'instant.</p>"
    noms = sorted((nom for nom in os.listdir(sortie)
                   if NOM_RAPPORT.fullmatch(nom)
                   and os.path.isfile(os.path.join(sortie, nom, "rapport.html"))), reverse=True)
    if not noms:
        return "<p class='aide'>Aucun rapport pour l'instant.</p>"
    return "<ul class='rapports'>" + "".join(
        f"<li><a href='/rapport/{nom}'>{html.escape(nom)}</a></li>" for nom in noms) + "</ul>"


def page_accueil(sortie, erreur=""):
    message = f"<p class='erreur'>{html.escape(erreur)}</p>" if erreur else ""
    controles = ", ".join(MODULES[nom]["nom"].lower() for nom in PAR_DEFAUT)
    return PAGE.format(css=rapport.CSS, cssform=CSS_FORM, logo=rapport.LOGO, message=message,
                       controles=html.escape(controles),
                       rapports=_liste_rapports(sortie), version=__version__)


def traiter_formulaire(corps, sortie):
    """Démarre le diagnostic demandé en arrière-plan. Renvoie le code de son suivi.

    Le domaine est vérifié tout de suite : une saisie invalide lève ValueError.
    """
    champs = urllib.parse.parse_qs(corps)
    domaine = nettoyer_domaine(champs.get("domaine", [""])[0])
    societe = champs.get("societe", [""])[0].strip()[:120]
    cible = Cible(domaine, societe)
    ident = nouveau_suivi(cible, PAR_DEFAUT)
    threading.Thread(target=executer_suivi, args=(ident, cible, PAR_DEFAUT, sortie),
                     daemon=True).start()
    return ident


def fabrique(sortie, code):
    class Requete(BaseHTTPRequestHandler):
        server_version = "Vigie"

        def log_message(self, *arguments):  # pas de journal bavard dans le terminal
            pass

        def _envoyer(self, statut, contenu, entetes=(), type_="text/html"):
            donnees = contenu.encode("utf-8")
            self.send_response(statut)
            self.send_header("Content-Type", f"{type_}; charset=utf-8")
            self.send_header("Content-Length", str(len(donnees)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            for nom, valeur in entetes:
                self.send_header(nom, valeur)
            self.end_headers()
            self.wfile.write(donnees)

        def _autorise(self):
            """En mode réseau local, il faut le code affiché dans le terminal."""
            if not code:
                return True
            return f"vigie={code}" in self.headers.get("Cookie", "")

        def do_GET(self):
            adresse = urllib.parse.urlsplit(self.path)
            if code and urllib.parse.parse_qs(adresse.query).get("code", [""])[0] == code:
                self._envoyer(303, "", [("Location", "/"), (
                    "Set-Cookie", f"vigie={code}; HttpOnly; SameSite=Strict; Path=/")])
                return
            if not self._autorise():
                self._envoyer(403, "<p>Accès refusé. Ouvrez l'adresse affichée dans le terminal.</p>")
                return
            if adresse.path == "/":
                self._envoyer(200, page_accueil(sortie))
                return
            suivi = re.fullmatch(r"/suivi/([A-Za-z0-9_-]{8,40})(/etat)?", adresse.path)
            if suivi and etat_suivi(suivi.group(1)) is not None:
                if suivi.group(2):
                    self._envoyer(200, json.dumps(etat_suivi(suivi.group(1)), ensure_ascii=False),
                                  [("Cache-Control", "no-store")], type_="application/json")
                else:
                    self._envoyer(200, page_suivi(suivi.group(1)))
                return
            trouve = re.fullmatch(r"/rapport/([a-z0-9_-]{3,120})", adresse.path)
            if trouve:
                chemin = os.path.join(sortie, trouve.group(1), "rapport.html")
                if os.path.isfile(chemin):
                    with open(chemin, encoding="utf-8") as fichier:
                        self._envoyer(200, fichier.read())
                    return
            self._envoyer(404, "<p>Page introuvable.</p>")

        def do_POST(self):
            if not self._autorise():
                self._envoyer(403, "<p>Accès refusé.</p>")
                return
            if self.path != "/diagnostic":
                self._envoyer(404, "<p>Page introuvable.</p>")
                return
            taille = min(int(self.headers.get("Content-Length", "0") or 0), 4096)
            corps = self.rfile.read(taille).decode("utf-8", "replace")
            try:
                ident = traiter_formulaire(corps, sortie)
            except ValueError as erreur:
                self._envoyer(400, page_accueil(sortie, str(erreur)))
                return
            self._envoyer(303, "", [("Location", f"/suivi/{ident}")])

    return Requete


def _adresse_locale():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sonde:
            sonde.connect(("192.0.2.1", 9))  # aucune donnée envoyée : sert à lire l'adresse locale
            return sonde.getsockname()[0]
    except OSError:
        return "adresse-de-cet-ordinateur"


def servir(port=8765, reseau_local=False, sortie="rapports"):
    code = secrets.token_urlsafe(9) if reseau_local else ""
    hote = "0.0.0.0" if reseau_local else "127.0.0.1"
    serveur = ThreadingHTTPServer((hote, port), fabrique(sortie, code))
    print(f"Vigie {__version__} est ouvert.")
    print(f"  Sur cet ordinateur : http://localhost:{port}/" + (f"?code={code}" if code else ""))
    if reseau_local:
        print(f"  Sur le téléphone (même Wi-Fi) : http://{_adresse_locale()}:{port}/?code={code}")
        print("  Le code dans l'adresse protège l'accès. Ne partagez pas cette adresse.")
    print("Pour arrêter : Ctrl + C")
    try:
        serveur.serve_forever()
    except KeyboardInterrupt:
        print("\nVigie est arrêté.")
    finally:
        serveur.server_close()
